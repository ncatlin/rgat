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
		thisgraph->setBacklogIn(0);
		do {
			
			Sleep(500);

			WaitForSingleObject(flagMutex, INFINITE);

			targetQueue = get_read_queue();
			if (targetQueue->size() < traceBufMax/2) 
				break;
			if (targetQueue->size() <  traceBufMax/10)
				cout << "[rgat]Trace queue now "<< targetQueue->size() << "items" << endl;
			ReleaseMutex(flagMutex);

		} while (!die);
		cout << "[rgat]Trace queue now "<< targetQueue->size() << " items, resuming." << endl;
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

//thread handler to build graph for a thread
void thread_trace_reader::main_loop()
{
	alive = true;
	wstring pipename(L"\\\\.\\pipe\\rioThread");
	pipename.append(std::to_wstring(TID));
	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE,
		1, //max instances
		1, //outbuffer
		1024 * 1024, //inbuffermax
		1, //timeout?
		NULL);

	if ((int)hPipe == -1)
	{
		cerr << "[rgat]Error: Could not create pipe in thread handler "<<TID<<". error:" << GetLastError() << endl;
		return;
	}

	ConnectNamedPipe(hPipe, NULL);
	char *tagReadBuf = (char*)malloc(TAGCACHESIZE);
	if (!tagReadBuf) {
		cerr << "[rgat]Failed to allocate tag buffer for thread " << TID << endl;
		return;
	}

	ALLEGRO_TIMER *secondtimer = al_create_timer(1);
	al_register_event_source(bench_timer_queue, al_get_timer_event_source(secondtimer));
	al_start_timer(secondtimer);
	unsigned long itemsRead = 0;

	int PIDcount = 0;
	char *messageBuffer;
	DWORD bytesRead = 0;
	while (!die)
	{
		if (!al_is_event_queue_empty(bench_timer_queue))
		{
			al_flush_event_queue(bench_timer_queue);
			thisgraph->setBacklogIn(itemsRead);
			itemsRead = 0;
		}

		DWORD available;
		if(!PeekNamedPipe(hPipe, NULL, NULL, NULL, &available, NULL) || !available)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE) break;
			Sleep(5);
			continue;
		}

		if (!ReadFile(hPipe, tagReadBuf, TAGCACHESIZE, &bytesRead, NULL))
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				cerr << "[rgat]Error: thread " << TID << " pipe read ERROR: " << err << ". [Closing handler]" << endl;
			break;
		}

		if (bytesRead >= TAGCACHESIZE) {
			cerr << "\t\t[rgat](Easily fixable) Error: Excessive data sent to cache!" << endl;
			break;
		}

		tagReadBuf[bytesRead] = 0;
		//cout << "[rgat] "<<TID<<"reader read [" << tagReadBuf << "]" << endl;
		if (tagReadBuf[bytesRead - 1] != '@')
		{
			cerr << "[rgat]ERROR: [tid"<<TID<<"] Improperly terminated trace message recieved ["<<tagReadBuf<<"]. ("<<bytesRead<<" bytes) Terminating." << endl;
			assert(0);
		}
		
		messageBuffer = (char*)malloc(bytesRead + 1);
		memcpy(messageBuffer, tagReadBuf, bytesRead + 1);

		add_message(messageBuffer, bytesRead + 1);

		++itemsRead;
	}
	pipeClosed = true;
	//wait until buffers emptied
	while (!firstQueue.empty() && !secondQueue.empty() && !die)
		Sleep(10);

	alive = false;
}