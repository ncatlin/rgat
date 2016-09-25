/*
Copyright 2016 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Header for the thread that reads trace information from drgat and buffers it
*/
#include "stdafx.h"
#include "thread_trace_reader.h"
#include "thread_graph_data.h"

thread_trace_reader::thread_trace_reader()
{
}


thread_trace_reader::~thread_trace_reader()
{
}

void __stdcall thread_trace_reader::ThreadEntry(void* pUserData) {
	return ((thread_trace_reader*)pUserData)->reader_thread();
}

//thread handler to build graph for a thread
void thread_trace_reader::reader_thread()
{
	wstring pipename(L"\\\\.\\pipe\\rioThread");
	pipename.append(std::to_wstring(TID));
	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE,
		255, //max instances
		64, //outbuffer
		1024 * 1024, //inbuffer
		1, //timeout?
		NULL);

	if ((int)hPipe == -1)
	{
		printf("Error: Could not create pipe in thread handler %d. error:%d\n",TID, GetLastError());
		return;
	}

	ConnectNamedPipe(hPipe, NULL);
	char *tagReadBuf = (char*)malloc(TAGCACHESIZE);
	if (!tagReadBuf) {
		cerr << "[rgat]Failed to allocate tag buffer for thread " << TID << endl;
		return;
	}

	int PIDcount = 0;
	char *messageBuffer;

	DWORD bytesRead = 0;
	while (true)
	{
		if (die) break;
		if (!ReadFile(hPipe, tagReadBuf, TAGCACHESIZE, &bytesRead, NULL))
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				cerr << "[rgat]Error: thread " << TID << " pipe read ERROR: " << err << ". [Closing handler]" << endl;
			pipeClosed = true;
			break;
		}

		if (bytesRead == TAGCACHESIZE) {
			cerr << "\t\t[rgat](Easily fixable) Error: Excessive data sent to cache!" << endl;
			pipeClosed = true;
			break;
		}
		tagReadBuf[bytesRead] = 0;

		messageBuffer = (char*)malloc(bytesRead+1);
		memcpy(messageBuffer, tagReadBuf, bytesRead+1);
		add_message(messageBuffer, bytesRead+1);

	}
	if (!die)
		cout << "Trace reader lost connection to thread " << TID << " exiting after buffer processing"<<endl;
	//keep the thread open until killed or buffers emptied
	while (!firstQueue.empty() && !secondQueue.empty())
	{
		if (die) break;
		Sleep(10);
	}
	cout << "Trace reader exiting" << endl;
}

vector<pair<char *, int>> * thread_trace_reader::get_read_queue()
{
	if (readingFirstQueue)
		return &secondQueue;
	else
		return &firstQueue;
}

void thread_trace_reader::add_message(char *buffer, int size)
{
	pair<char*, int> bufPair = make_pair(buffer, size);
	WaitForSingleObject(flagMutex, INFINITE);
	vector<pair<char *, int>> *targetQueue = get_read_queue();

	if (targetQueue->size() >= traceBufMax)
	{
		cout << "[rgat]Warning: Trace queue full with " << traceBufMax << " items! Waiting for renderer to catch up..." << endl;
		ReleaseMutex(flagMutex);
		do {
			Sleep(500);

			WaitForSingleObject(flagMutex, INFINITE);

			targetQueue = get_read_queue();
			if (targetQueue->size() < traceBufMax/2) break;
			if (targetQueue->size() <  traceBufMax/10)
				cout << "[rgat]Trace queue now "<< targetQueue->size() << "items" << endl;
			ReleaseMutex(flagMutex);
		} while (true);
		cout << "[rgat]Trace queue now "<< targetQueue->size() << "items, resuming." << endl;
	}
	targetQueue->push_back(bufPair);
	pendingData += size;
	ReleaseMutex(flagMutex);
}

int thread_trace_reader::get_message(char **buffer, unsigned long *bufSize)
{
	
	if (readingQueue->empty() || readIndex >= readingQueue->size())
	{
		WaitForSingleObject(flagMutex, INFINITE);
		if (!readingQueue->empty())
		{
			vector<pair<char *, int>>::iterator queueIt = readingQueue->begin();
			for (; queueIt != readingQueue->end(); ++queueIt)
				free(queueIt->first);
			readingQueue->clear();
		}
		readIndex = 0;

		if (readingFirstQueue)
		{
			readingQueue = &secondQueue;
			readingFirstQueue = false;
		}
		else
		{
			readingQueue = &firstQueue;
			readingFirstQueue = true;
		}

		if (processedData)
		{
			pendingData -= processedData;
			processedData = 0;
		}
		ReleaseMutex(flagMutex);
	}

	if (readingQueue->empty())
	{
		if (pipeClosed && firstQueue.empty() && secondQueue.empty()) *bufSize = -1;
		else *bufSize = 0;
		return pendingData;
	}

	pair<char *, int> buf_size = readingQueue->at(readIndex++);
	*buffer = buf_size.first;
	*bufSize = buf_size.second;
	processedData += buf_size.second;
	return pendingData;
}

bool thread_trace_reader::getBufsState(pair <unsigned long, unsigned long> *bufSizes)
{
	unsigned long q1Size = firstQueue.size();
	unsigned long q2Size = secondQueue.size();

	if (readingFirstQueue)
		q1Size -= readIndex;
	else
		q2Size -= readIndex;

	*bufSizes = make_pair(q1Size, q2Size);
	return readingFirstQueue; 
}