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
Header for the thread that reads tracing feedback (coverage, exceptions, etc)
*/

#pragma once

#include "thread_trace_reader.h"
#include "base_thread.h"
#include "binaryTarget.h"

class fuzz_feedback_processor : public base_thread
{
public:
	fuzz_feedback_processor(traceRecord* runRecordptr, thread_trace_reader *readerThread)
		:base_thread()
	{
		runRecord = runRecordptr;
		binary = (binaryTarget *)runRecord->get_binaryPtr();
		piddata = binary->get_piddata();
		reader = readerThread;
	}

	PROCESS_DATA *piddata;

private:
	void main_loop();

	thread_trace_reader *reader;

	void process_coverage_result(char * entry);
	void process_exception_notification(char *entry);

	binaryTarget *binary;
	traceRecord* runRecord;
};