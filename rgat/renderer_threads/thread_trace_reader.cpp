/*
Copyright 2016-2017 Nia Catlin

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


bool thread_trace_reader::connectPipe()
{
	wstring pipename(L"\\\\.\\pipe\\rioThread");
	pipename.append(std::to_wstring(threadID));

	const wchar_t* szName = pipename.c_str();
	threadpipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE,
		1, //max instances
		1, //outbuffer
		1024 * 1024, //inbuffermax
		1, //timeout?
		NULL);

	if (threadpipe == (HANDLE)-1)
	{
		cerr << "[rgat]Error: Could not create pipe in thread handler " << threadID << ". error:" << GetLastError() << endl;
		alive = false;
		return false;
	}

	ConnectNamedPipe(threadpipe, NULL);
	return true;
}

vector<string *> * thread_trace_reader::get_read_queue()
{
	if (readingFirstQueue)
		return &secondQueue;
	else
		return &firstQueue;
}

void thread_trace_reader::add_message(string *newMsg)
{
	queueSwitchFlagLock.lock();
	vector<string *> *targetQueue = get_read_queue();

	if (targetQueue->size() >= traceBufMax)
	{
		cout << "[rgat]Warning: Trace queue full with " << traceBufMax << " items! Waiting for processor to catch up..." << endl;
		queueSwitchFlagLock.unlock();
		if (thisgraph)
			thisgraph->setBacklogIn(0);
		do {
			
			std::this_thread::sleep_for(500ms);
			queueSwitchFlagLock.lock();

			targetQueue = get_read_queue();
			if (targetQueue->size() < traceBufMax/2) 
				break;
			if (targetQueue->size() <  traceBufMax/10)
				cout << "[rgat]Trace queue now "<< targetQueue->size() << "items" << endl;
			queueSwitchFlagLock.unlock();

		} while (!die);
		cout << "[rgat]Trace queue now "<< targetQueue->size() << " items, resuming." << endl;
	}

	targetQueue->push_back(newMsg);
	pendingData += newMsg->size();

	if(!die)
		queueSwitchFlagLock.unlock();
}

string *thread_trace_reader::get_message()
{
	
	if (readingQueue->empty() || readIndex >= readingQueue->size())
	{
		queueSwitchFlagLock.lock();
		if (!readingQueue->empty())
		{
			vector<string *>::iterator queueIt = readingQueue->begin();
			for (; queueIt != readingQueue->end(); ++queueIt)
				delete *queueIt;
			readingQueue->clear();
		}
		readIndex = 0;

		//swap to the other queue
		readingQueue = readingFirstQueue ? &secondQueue : &firstQueue;
		readingFirstQueue = !readingFirstQueue;

		if (processedData)
		{
			pendingData -= processedData;
			processedData = 0;
		}
		queueSwitchFlagLock.unlock();
	}

	if (readingQueue->empty())
	{
		if (pipeClosed && firstQueue.empty() && secondQueue.empty()) return (string *)-1;
		return NULL;
	}

	string * nextMessage = readingQueue->at(readIndex++);
	processedData += nextMessage->size();
	return nextMessage;
}

bool thread_trace_reader::getBufsState(pair <size_t, size_t> &bufSizes)
{
	size_t q1Size = firstQueue.size();
	size_t q2Size = secondQueue.size();

	if (readingFirstQueue)
		q1Size -= readIndex;
	else
		q2Size -= readIndex;

	bufSizes = make_pair(q1Size, q2Size);
	return readingFirstQueue; 
}

bool thread_trace_reader::data_available(bool &error)
{
	DWORD available;
	if (!PeekNamedPipe(threadpipe, NULL, NULL, NULL, &available, NULL) || !available)
	{
		int GLE = GetLastError();
		if (GLE == ERROR_BROKEN_PIPE) error = true;
		return false;
	}
	else
		return true;
}

bool thread_trace_reader::read_data(vector <char> &tagReadBuf, DWORD &bytesRead)
{
	if (!ReadFile(threadpipe, &tagReadBuf.at(0), (DWORD)tagReadBuf.size(), &bytesRead, NULL))
	{
		int err = GetLastError();
		if (err != ERROR_BROKEN_PIPE)
			cerr << "[rgat]Error: thread " << threadID << " pipe read ERROR: " << err << ". [Closing handler]" << endl;
		return false;
	}
	return true;
}

//thread handler to build graph for a thread
void thread_trace_reader::main_loop()
{
	alive = true;
	if (!threadpipe && !connectPipe())
	{
		return;
	}

	vector <char> tagReadBuf(TAGCACHESIZE, 0);

	clock_t endwait = clock() + 1;
	unsigned long itemsRead = 0;

	DWORD bytesRead = 0;
	while (!die)
	{
		//should maybe have this as a timer but the QT one is more of a pain to set up
		clock_t secondsnow = clock();
		if (secondsnow > endwait)
		{
			endwait = secondsnow + 1;
			if(thisgraph)
				thisgraph->setBacklogIn(itemsRead);
			itemsRead = 0;
		}

		bool error = false;
		if (!data_available(error))
		{
			if (!error) 
				continue; 
			else 
				break;
		}


		if (!read_data(tagReadBuf, bytesRead))
			break;
		if (bytesRead >= TAGCACHESIZE) {
			cerr << "\t\t[rgat](Easily fixable) Error: Excessive data sent to cache!" << endl;
			break;
		}

		tagReadBuf[bytesRead] = 0;
		if ((bytesRead == 0) || tagReadBuf[bytesRead - 1] != '@')
		{
			die = true;
			if (!bytesRead) break;
			if (tagReadBuf.at(0) != 'X')
			{
				std::string bufstring(tagReadBuf.begin(), tagReadBuf.begin() + bytesRead);
				cerr << "[rgat]ERROR: [threadid" << threadID << "] Improperly terminated trace message recieved [" 
					<< bufstring << "]. (" << bytesRead << " bytes) Terminating." << endl;
			}
			
			break;
		}
		
		//we can improve this if it's a bottleneck
		string *msgbuf = new string(tagReadBuf.begin(), tagReadBuf.begin() + bytesRead);

		add_message(msgbuf);
		++itemsRead;
	}

	pipeClosed = true;
	//wait until buffers emptied
	while (!firstQueue.empty() && !secondQueue.empty() && !die)
		std::this_thread::sleep_for(10ms);

	alive = false;
}
