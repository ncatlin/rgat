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
This is the base thread for each instrumented process.
It reads module and symbol data for the process
It also launches trace reader and handler threads when the process spawns a thread
*/

#include "stdafx.h"
#include "module_handler.h"
#include "traceMisc.h"
#include "trace_graph_builder.h"
#include "thread_trace_reader.h"
#include "b64.h"
#include "fuzzRun.h"
#include "graphplots/plotted_graph.h"

#include <boost/filesystem.hpp>

//listen to module data for given process
void module_handler::main_loop()
{
	alive = true;



	inputpipename.append(runRecord->getModpathID());
	HANDLE hPipe = CreateNamedPipe(inputpipename.c_str(),
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 64, 56 * 1024, 0, NULL);

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	if (ConnectNamedPipe(hPipe, &ov) || !ov.hEvent)
	{
		wcerr << "[rgat]ERROR: Failed to ConnectNamedPipe to " << inputpipename << " for PID "<< runRecord->getPID() << ". Error: " << GetLastError();
		alive = false;
		return;
	}

	while (!die)
	{
		if (WaitForSingleObject(ov.hEvent, 1000) != WAIT_TIMEOUT) break;
		wcerr << "[rgat]WARNING: Long wait for module handler pipe " << inputpipename << endl;
	}

	wstring controlpipename = wstring(L"\\\\.\\pipe\\");
	controlpipename.append(L"rioControl");
	controlpipename.append(runRecord->getModpathID());
	controlPipe = CreateNamedPipe(controlpipename.c_str(),
		PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 64, 56 * 1024, 0, NULL);


	piddata = runRecord->get_piddata();
	piddata->set_running(true);
	clientState->newProcessSeen();
	/*
	if (runRecord->getTraceType() == eTracePurpose::eFuzzer)
	{
		fuzzRun *fuzzinstance = (fuzzRun *)runRecord->fuzzRunPtr;
		fuzzinstance->notify_new_process(TID);
	}*/

	char buf[400] = { 0 };

	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!ov2.hEvent)
	{
		wcerr << "[rgat]ERROR - Failed to create overlapped event in module handler" << endl;
		assert(false);
	}



	while (!die && !piddata->should_die())
	{
		DWORD bread = 0;
		ReadFile(hPipe, buf, 399, &bread, &ov2);
		while (true)
		{
			int res = WaitForSingleObject(ov2.hEvent, 300);
			if (res != WAIT_TIMEOUT) break;
			int gle = GetLastError();
			if (gle == ERROR_BROKEN_PIPE)
			{
				die = true;
				piddata->set_running(false);
			}
			if (die || piddata->should_die() || clientState->rgatIsExiting()) {
				die = true;
				break;
			}
		}
		
		int res2 = GetOverlappedResult(hPipe, &ov2, &bread, false);
		buf[bread] = 0;
	
		if (!bread)
		{
			//not sure this ever gets called, read probably fails?
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE && !die)
				wcerr << "[rgat]ERROR: threadpipe ReadFile error: " << err << endl;
			alive = false;
			break;
		}
		else
		{	
			//thread created
			if (buf[0] == 'T' && buf[1] == 'I')
			{
				PID_TID TID = 0;
				if (!extract_tid(buf, string("TI"), &TID))
				{
					wcerr << "[rgat] Fail to extract thread ID from TI tag:" << buf << endl;
					continue;
				}

				if (runRecord->getTraceType() == eTracePurpose::eVisualiser)
				{
					start_thread_rendering(TID);
					continue;
				}

				if (runRecord->getTraceType() == eTracePurpose::eFuzzer)
				{
					fuzzRun *fuzzinstance = (fuzzRun *)runRecord->fuzzRunPtr;
					fuzzinstance->notify_new_thread(TID);
					continue;
				}

				continue;
			}

			//symbol
			if (buf[0] == 's' && buf[1] == '!' && bread > 8)
			{
				char *next_token = NULL;
				unsigned int modnum = atoi(strtok_s(buf + 2, "@", &next_token));
				if (modnum > piddata->modpaths.size()) {
					wcerr << "[rgat]Bad mod number " << modnum << "in sym processing. " <<
						piddata->modpaths.size() << " exist." << endl;
					continue;
				}

				char *offset_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS address;
				sscanf_s(offset_s, "%llx", &address);

				if(!piddata->modBounds.count(modnum)) 
					wcerr << "[rgat]Warning: sym before module. handle me"<<endl; //fail if sym came before module
				else
					address += piddata->modBounds[modnum].first;

				string symname = string(next_token);
				piddata->getDisassemblyWriteLock();
				piddata->modsymsPlain[modnum][address] = symname;
				piddata->dropDisassemblyWriteLock();
				continue;
			}

			//module/dll
			if (buf[0] == 'm' && buf[1] == 'n' && bread > 8)
			{
				char *next_token = NULL;
				string b64path;
				//null path
				if (buf[2] == '@' && buf[3] == '@')
				{
					next_token = buf + 4; //skip past 'mn@@'
				}
				else 
					b64path = string(strtok_s(buf + 2, "@", &next_token));

				char *modnum_s = strtok_s(next_token, "@", &next_token);
				long modnum = -1;
				sscanf_s(modnum_s, "%d", &modnum);

				piddata->getDisassemblyReadLock();
				if (piddata->modpaths.count(modnum) > 0) 
				{
					wcerr<< "[rgat]ERROR: PID:"<<piddata->PID<<" Bad(prexisting) module number "<<modnum<<" in mn ["<<
						buf<<"]. current is:" << piddata->modpaths.at(modnum) << endl;
					assert(0);
				}
				piddata->dropDisassemblyReadLock();

				//todo: safe stol? if this is safe whytf have i implented safe stol
				char *startaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS startaddr = 0;
				sscanf_s(startaddr_s, "%llx", &startaddr);

				char *endaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS endaddr = 0;
				sscanf_s(endaddr_s, "%llx", &endaddr);


				char *skipped_s = strtok_s(next_token, "@", &next_token);
				piddata->getDisassemblyWriteLock();

				if (*skipped_s == '1')
					piddata->activeMods[modnum] = UNINSTRUMENTED_MODULE;
				else
					piddata->activeMods[modnum] = INSTRUMENTED_MODULE;

				piddata->dropDisassemblyWriteLock();

				if (!startaddr | !endaddr | (next_token - buf != bread)) {
					wcerr << "ERROR! Processing module line: "<< buf << endl;
					assert(0);
				}
				
				boost::filesystem::path path_plain;
				if (!b64path.empty())
					path_plain = boost::filesystem::path((base64_decode(b64path)));
				else
					path_plain = "";

				piddata->getDisassemblyWriteLock();
				piddata->modpaths[modnum] = path_plain;
				
				if (!piddata->modBounds.count(modnum) && piddata->modsymsPlain.count(modnum))
					{
						wcerr << "[rgat]ERROR: module after sym - add address to all relevant syms" << endl;
						assert(0);
					}

				piddata->modBounds[modnum] = make_pair(startaddr, endaddr);

				piddata->dropDisassemblyWriteLock();

				continue;
			}
		}
	}

	char termbuf[] = "KT";
	WriteFile(controlPipe, termbuf, 2, 0, 0);

	//exited loop, first tell readers to terminate
	vector <thread_trace_reader *>::iterator readerThreadIt = readerThreadList.begin();
	for (; readerThreadIt != readerThreadList.end(); ++readerThreadIt)
		((thread_trace_reader *)(*readerThreadIt))->kill();

	vector <base_thread *>::iterator threadIt = threadList.begin();
	for (; threadIt != threadList.end(); ++threadIt)
		((base_thread *)(*threadIt))->kill();

	//wait for trace readers and trace processors to terminate
	vector <base_thread *>::iterator athreadIt = threadList.begin();
	for (athreadIt = threadList.begin(); athreadIt != threadList.end(); ++athreadIt)
	{
		while ((base_thread *)(*athreadIt)->is_alive())
			Sleep(5);
	}

	runRecord->notify_pid_end(piddata->PID, piddata->randID);
	piddata->set_running(false); //the process is done
	clientState->processEnded();
	alive = false; //this thread is done
}

void  module_handler::start_thread_rendering(PID_TID TID)
{
	proto_graph *newProtoGraph = new proto_graph(piddata, TID);
	plotted_graph* newPlottedGraph = (plotted_graph *)clientState->createNewPlottedGraph(newProtoGraph);

	newPlottedGraph->initialiseDefaultDimensions();
	newPlottedGraph->set_animation_update_rate(clientState->config.animationUpdateRate);

	thread_trace_reader *TID_reader = new thread_trace_reader(runRecord, newProtoGraph);
	TID_reader->traceBufMax = clientState->config.traceBufMax;
	newProtoGraph->setReader(TID_reader);

	threadList.push_back(TID_reader);
	readerThreadList.push_back(TID_reader);
	std::thread tracereader(&thread_trace_reader::ThreadEntry, TID_reader);
	tracereader.detach();

	trace_graph_builder *graph_builder = new trace_graph_builder(runRecord, newProtoGraph, TID_reader);

	if (!runRecord->insert_new_thread(TID, newPlottedGraph, newProtoGraph))
	{
		wcerr << "[rgat]ERROR: Trace tendering thread creation failed" << endl;
		return;
	}

	threadList.push_back(graph_builder);
	std::thread graph_builder_thread(&trace_graph_builder::ThreadEntry, graph_builder);
	graph_builder_thread.detach();
}