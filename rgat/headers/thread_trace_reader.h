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
#pragma once
#include "stdafx.h"
#include "base_thread.h"
#include "proto_graph.h"
#include "binaryTarget.h"

class thread_trace_reader : public base_thread
{
public:

	thread_trace_reader(proto_graph *graph, HANDLE pipe)
		: base_thread()
	{
		thisgraph = graph;
		threadID = graph->get_TID();
		InitializeCriticalSection(&flagCritsec);
		threadpipe = pipe;
	}

	thread_trace_reader(PID_TID tid)
		: base_thread()
	{
		thisgraph = NULL;
		threadID = tid;
		InitializeCriticalSection(&flagCritsec);
	}
	thread_trace_reader(){ DeleteCriticalSection(&flagCritsec); }


	size_t traceBufMax = 0;
	string *get_message();

	size_t pendingData = 0;
	bool getBufsState(pair <size_t, size_t> *bufSizes);

private:
	void main_loop();

	CRITICAL_SECTION flagCritsec;
	
	//stackoverflow.com/questions/4029448/thread-safety-for-stl-queue/4029534#4029534
	unsigned long readIndex = 0;
	vector<string *> firstQueue;
	vector<string *> secondQueue;
	vector<string *> *readingQueue = &firstQueue;
	bool readingFirstQueue = true;
	
	void add_message(string *);
	vector<string *> *get_read_queue();
	bool pipeClosed = false;
	unsigned int processedData = 0;
	proto_graph *thisgraph;
	HANDLE threadpipe = NULL;

	PID_TID threadID;
};

