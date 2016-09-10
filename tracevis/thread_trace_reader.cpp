#include "stdafx.h"
#include "thread_trace_reader.h"


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
	wcout << "Opening thread reader pipe '" << pipename << "'" << endl;
	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, //max instances
		64, //outbuffer
		1024 * 1024, //inbuffer
		300, //timeout
		NULL);

	if ((int)hPipe == -1)
	{
		//thisgraph->active = false;
		printf("Error: Could not create pipe in thread handler. error:%d\n", GetLastError());
		return;
	}

	ConnectNamedPipe(hPipe, NULL);
	char *tagReadBuf = (char*)malloc(TAGCACHESIZE);
	int PIDcount = 0;
	char *messageBuffer;

	bool threadRunning = true;
	while (threadRunning)
	{
		DWORD bytesRead = 0;
		ReadFile(hPipe, tagReadBuf, TAGCACHESIZE, &bytesRead, NULL);
		if (bytesRead == TAGCACHESIZE) {
			printf("\t\tERROR: THREAD READ CACHE EXCEEDED! [%s]\n", tagReadBuf);
			pipeClosed = true;
			return;
		}

		tagReadBuf[bytesRead] = 0;
		tagReadBuf[TAGCACHESIZE - 1] = 0;
		//printf("\n\nread buf: [%s]\n\n", buf);
		if (!bytesRead)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				printf("thread %d pipe read ERROR: %d. [Closing handler]\n", TID, err);

			pipeClosed = true;
			return;
		}

		messageBuffer = (char*)malloc(bytesRead+1);
		//printf("allocated %lx -- ", messageBuffer);
		memcpy(messageBuffer, tagReadBuf, bytesRead+1);
		add_message(messageBuffer, bytesRead+1);

	}
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

	if (targetQueue->size() > 400000)
	{
		printf("Queue exceeds 400000 items! Waiting for renderer to catch up\n");
		ReleaseMutex(flagMutex);
		do {
			Sleep(500);

			WaitForSingleObject(flagMutex, INFINITE);

			targetQueue = get_read_queue();
			if (targetQueue->size() < 200000) break;

			ReleaseMutex(flagMutex);
		} while (true);
	}
	targetQueue->push_back(bufPair);
	pendingData += size;
	ReleaseMutex(flagMutex);
}

int thread_trace_reader::get_message(char **buffer, unsigned long *bufSize)
{
	
	if (readingQueue->empty() || readingQueue->size()-1 <= readIndex)
	{
		WaitForSingleObject(flagMutex, INFINITE);
		if (!readingQueue->empty())
		{
			vector<pair<char *, int>>::iterator queueIt = readingQueue->begin();
			for (; queueIt != readingQueue->end(); ++queueIt)
			{
				//printf(" freeing %lx -- ", queueIt->first);
				free(queueIt->first);
			}
			readingQueue->clear();
		}
		readIndex = 0;

		
		if (readingFirstQueue)
		{
			//printf("First queue emptied! ");
			readingQueue = &secondQueue;
			readingFirstQueue = false;
		}
		else
		{
			//printf("secondQueue emptied! ");
			readingQueue = &firstQueue;
			readingFirstQueue = true;
		}

		if (processedData)
		{
			pendingData -= processedData;
			//printf("Processed %d bytes of data in queue, %d remaining (queue size %d)\n", processedData, pendingData, readingQueue->size());
			processedData = 0;
		}
		ReleaseMutex(flagMutex);
		
	}

	if (readingQueue->empty())
	{
		if (pipeClosed) *bufSize = -1;
		else *bufSize = 0;
		return pendingData;
	}

	pair<char *, int> buf_size = readingQueue->at(readIndex++);
	if (!(readIndex % 500)) printf("processing index %d of %d\n", readIndex, readingQueue->size());
	*buffer = buf_size.first;
	//printf(" using %lx -- ", buffer);
	*bufSize = buf_size.second;
	processedData += buf_size.second;
	return pendingData;
}