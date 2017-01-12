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

class thread_trace_reader : public base_thread
{
public:
	thread_trace_reader(proto_graph *graph, unsigned int thisPID, unsigned int thisTID)
		: base_thread(thisPID, thisTID)
	{
		thisgraph = graph;
	}
	
	unsigned long traceBufMax = 0;
	int get_message(char **buffer, unsigned long *bufSize);
	
	unsigned long pendingData = 0;
	bool getBufsState(pair <unsigned long, unsigned long> *bufSizes);

private:
	void main_loop();
	//stackoverflow.com/questions/4029448/thread-safety-for-stl-queue/4029534#4029534
	unsigned long readIndex = 0;
	vector<pair<char *, int>> firstQueue;
	vector<pair<char *, int>> secondQueue;
	vector<pair<char *, int>> *readingQueue = &firstQueue;
	bool readingFirstQueue = true;
	HANDLE flagMutex = CreateMutex(NULL, FALSE, NULL);
	void add_message(char *buffer, int size);
	vector<pair<char *, int>> * get_read_queue();
	bool pipeClosed = false;
	unsigned int processedData = 0;
	proto_graph *thisgraph;

	ALLEGRO_EVENT_QUEUE *bench_timer_queue = al_create_event_queue();
};

