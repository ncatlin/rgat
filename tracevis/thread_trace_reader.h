#pragma once
#include "stdafx.h"
#include "thread_graph_data.h"


class thread_trace_reader
{
public:
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	int TID;
	bool die = false;
	int get_message(char **buffer, unsigned long *bufSize);
	void reader_thread();
	thread_trace_reader();
	~thread_trace_reader();
	unsigned long pendingData = 0;

private:
	//stackoverflow.com/questions/4029448/thread-safety-for-stl-queue/4029534#4029534
	vector<pair<char *, int>> firstQueue;
	unsigned long readIndex = 0;
	vector<pair<char *, int>> secondQueue;
	vector<pair<char *, int>> *readingQueue = &firstQueue;
	bool readingFirstQueue = true;
	HANDLE flagMutex = CreateMutex(NULL, FALSE, NULL);
	void add_message(char *buffer, int size);
	vector<pair<char *, int>> * get_read_queue();
	bool pipeClosed = false;
	unsigned int processedData = 0;
};

