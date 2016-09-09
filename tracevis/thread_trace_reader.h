#pragma once
#include "stdafx.h"
#include "thread_graph_data.h"


class thread_trace_reader
{
public:
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	int TID;
	int get_message(char **buffer);
	void reader_thread();
	thread_trace_reader();
	~thread_trace_reader();
	unsigned int pendingData = 0;

private:
	//stackoverflow.com/questions/4029448/thread-safety-for-stl-queue/4029534#4029534
	queue<pair<char *, int>> firstQueue;
	queue<pair<char *, int>> secondQueue;
	queue<pair<char *, int>> *readingQueue = &firstQueue;
	bool readingFirstQueue = true;
	HANDLE flagMutex = CreateMutex(NULL, FALSE, NULL);
	void add_message(char *buffer, int size);
	bool pipeClosed = false;
	unsigned int processedData = 0;
};

