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
Header for the thread that manages each instrumented process
*/
#pragma once

#include "stdafx.h"
#include "base_thread.h"
#include "traceStructs.h"
#include "thread_trace_reader.h"

class module_handler : public base_thread
{
public:
	module_handler(binaryTarget *binaryptr, traceRecord* runRecordptr, wstring pipeid)
		: base_thread() {
		binary = binaryptr;  runRecord = runRecordptr;

		pipename = wstring(L"\\\\.\\pipe\\");
		pipename += pipeid;
	};

	wstring pipename;

private:
	binaryTarget *binary;
	traceRecord* runRecord;

	vector < base_thread *> threadList;	
	vector < thread_trace_reader *> readerThreadList; 
	PROCESS_DATA *piddata = NULL;

	void main_loop();
	void start_thread_rendering(PID_TID TID);
};