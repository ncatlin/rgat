#include "fuzz_feedback_processor.h"

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
The thread that builds a graph for each trace from the drgat trace stream (which is delivered by the trace_reader thread).
*/

#include "stdafx.h"
#include "fuzz_feedback_processor.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "shrike_structs.h"
#include "b64.h"
#include "OSspecific.h"
#include "boost\tokenizer.hpp"

//#define VERBOSE
void fuzz_feedback_processor::process_exception_notification(char *entry)
{

}


void fuzz_feedback_processor::process_coverage_result(char *entry)
{
	
}

//build graph for a thread as the trace data arrives from the reader thread
void fuzz_feedback_processor::main_loop()
{
	alive = true;

	unsigned long itemsDone = 0;

	string *message;
	clock_t backlogUpdateTimer = clock() + 1;
	while (!die)
	{
		clock_t timenow = clock();
		if (timenow > backlogUpdateTimer)
		{
			backlogUpdateTimer = timenow + 1;
			itemsDone = 0;
		}

		message = reader->get_message();
		if (!message)
		{
			Sleep(5);
			continue;
		}


		if ((int)message == -1) //thread pipe closed
		{
			break;
		}

		++itemsDone;

		boost::char_separator<char> sep("@");
		boost::tokenizer< boost::char_separator<char> > tok(*message, sep);
		for (boost::tokenizer< boost::char_separator<char> >::iterator beg = tok.begin(); beg != tok.end(); ++beg)
		{
			string entry = *beg;
			if (entry.empty()) break;

			//cout << "TID"<<TID<<" Processing entry: ["<<entry<<"]"<<endl;
			char entrytag = entry[0];
			switch (entrytag)
			{
			case feedbackTags::eCoverageResult:
				process_coverage_result((char *)entry.c_str());
				continue;

			case feedbackTags::eExceptionNotification:
				process_exception_notification((char *)entry.c_str());
				continue;

			default:
				cerr << "[rgat]ERROR: Fuzz feedback unhandled line " <<
					entry << " (" << entry.size() << " bytes)" << endl;
				assert(0);
			}
		}
	}

	alive = false;
}

