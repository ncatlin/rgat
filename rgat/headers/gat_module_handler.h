/*
Copyright 2017 Nia Catlin

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

class gat_module_handler : public base_thread
{
public:
	gat_module_handler(binaryTarget *binaryptr, traceRecord* runRecordptr, wstring pipeid, HANDLE modpipeHandle, HANDLE controlpipeHandle)
		: base_thread() {
		binary = binaryptr;  runRecord = runRecordptr;

		if (modpipeHandle && controlpipeHandle)
		{
			inputPipe = modpipeHandle;
			controlPipe = controlpipeHandle;
		}
		else
		{
			inputpipename = wstring(L"\\\\.\\pipe\\");
			inputpipename += pipeid;
		}
	};

	wstring inputpipename;
	HANDLE controlPipe;

private:
	HANDLE inputPipe;
	binaryTarget *binary;
	traceRecord* runRecord;

	vector < base_thread *> threadList;	
	vector < thread_trace_reader *> readerThreadList; 
	PROCESS_DATA *piddata = NULL;

	void main_loop();
	void start_thread_rendering(PID_TID TID, HANDLE threadpipe); 
	void sendIncludeLists();
	void end_threads();
	
	void handleNewThread(char *buf, OVERLAPPED &ov2);
	void handleNewVisualiserThread(PID_TID TID, OVERLAPPED &ov2);
	void handleSymbol(char *buf);
	void handleModule(char *buf, DWORD bytesRead);
	void handlePipeError();
	DWORD getData(char *buf, OVERLAPPED ov2, bool &pendingControlCommand);
	bool gat_module_handler::establishPipe();
};