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
#include "gat_module_handler.h"
#include "traceMisc.h"
#include "trace_graph_builder.h"
#include "thread_trace_reader.h"
#include "b64.h"
#include "fuzzRun.h"
#include "graphplots/plotted_graph.h"

#include <boost/filesystem.hpp>

//listen to module data for given process
void gat_module_handler::main_loop()
{
	alive = true;

	if (!inputPipe)
	{
		inputpipename.append(runRecord->getModpathID());
		inputPipe = CreateNamedPipe(inputpipename.c_str(),
			PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_WAIT,
			255, 64, 1024 * 1024, 0, NULL);
		if (inputPipe == INVALID_HANDLE_VALUE)
		{
			wcerr << "[rgat]ERROR: module handler could not create named pipe " << inputpipename << " err: "<< GetLastError() << endl;
			return;
		}

		OVERLAPPED ov = { 0 };
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

		if (ConnectNamedPipe(inputPipe, &ov) || !ov.hEvent)
		{
			wcerr << "[rgat]ERROR: Failed to ConnectNamedPipe to " << inputpipename << " for PID " << runRecord->getPID() << ". Error: " << GetLastError();
			alive = false;
			return;
		}

		while (!die)
		{
			if (WaitForSingleObject(ov.hEvent, 1000) != WAIT_TIMEOUT)
				break;
			wcerr << "[rgat]WARNING: Long wait for module handler pipe " << inputpipename << endl;
		}
		if (die) { alive = false;  return; }


		wstring controlpipename = wstring(L"\\\\.\\pipe\\");
		controlpipename.append(L"rioControl");
		controlpipename.append(runRecord->getModpathID());
		controlPipe = CreateNamedPipe(controlpipename.c_str(), PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
			255, 64, 56 * 1024, 0, NULL);

		if (!WaitNamedPipe(controlpipename.c_str(), 20000))
		{
			wcerr << "[rgat]ERROR: Failed to ConnectNamedPipe to " << controlpipename << " for PID " << runRecord->getPID() << ". Error: " << GetLastError();
			alive = false;
			return;
		}
	}


	piddata = runRecord->get_piddata();
	runRecord->set_running(true);
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


	sendIncludeLists();


	bool pendingControlCommand = false;

	while (true)
	{
		DWORD bytesRead = 0;
		ReadFile(inputPipe, buf, 399, &bytesRead, &ov2);
		while (true)
		{
			int res = WaitForSingleObject(ov2.hEvent, 300);
			if (res != WAIT_TIMEOUT) break;
			int gle = GetLastError();
			if (gle == ERROR_BROKEN_PIPE)
			{
				die = true; 
				runRecord->set_running(false);
			}
			if (die || runRecord->should_die() || clientState->rgatIsExiting()) {
				die = true;
				pendingControlCommand = true;
				break;
			}
		}
		
		BOOL GOResult = GetOverlappedResult(inputPipe, &ov2, &bytesRead, false);
		if (!GOResult)
		{
			//cout << "Get overlapped failed" << endl;
		}
		buf[bytesRead] = 0;
	
		if (!bytesRead)
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

					wstring pipename(L"\\\\.\\pipe\\rioThread");
					pipename.append(std::to_wstring(TID));

					HANDLE threadpipeThisEnd, threadpipeTheirEnd;
					if (!createInputPipe(runRecord->getPID(), pipename, threadpipeThisEnd, threadpipeTheirEnd, 1024 * 1024))
					{
						cerr << "[rgat] Failed to create pipe for thread " << TID << ". Failing. " << endl;
						alive = false;
						return;
					}


					uint8_t handlesize = (binary->getBitWidth() == 32) ? 4 : 8;
					const int returnbufsize = handlesize + 2;
					char returnBuf[10];
					returnBuf[0] = '@';
					memcpy(returnBuf + 1, &threadpipeTheirEnd, handlesize);
					if (handlesize == 4)
						returnBuf[1 + 4] = '@';
					else
						returnBuf[1 + 8] = '@';

					DWORD byteswritten = 0;
					WriteFile(inputPipe, returnBuf, returnbufsize, &byteswritten, &ov2);

					if (byteswritten == returnbufsize)
						start_thread_rendering(TID, threadpipeThisEnd);
					else
						cerr << "[rgat] Error: Failed to send remote handle to thread function" << endl;

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
			if (buf[0] == 's' && buf[1] == '!' && bytesRead > 8)
			{
				char *next_token = NULL;
				unsigned int modnum = atoi(strtok_s(buf + 2, "@", &next_token));
				if (modnum > piddata->modpaths.size()) {
					wcerr << "[rgat]Bad mod number " << modnum << "in sym processing. " <<
						piddata->modpaths.size() << " exist." << endl;
					continue;
				}

				char *offset_s = strtok_s(next_token, "@", &next_token);
				ADDRESS_OFFSET offset;
				sscanf_s(offset_s, "%llx", &offset);

				string symname = string(next_token);
				piddata->getDisassemblyWriteLock();
				piddata->modsymsPlain[runRecord->modIDTranslationVec.at(modnum)][offset] = symname;
				piddata->dropDisassemblyWriteLock();
				continue;
			}

			//module/dll
			if (buf[0] == 'm' && buf[1] == 'n' && bytesRead > 8)
			{
				char *next_token = NULL;
				boost::filesystem::path path_plain;
				//string b64path;
				//null path
				if (buf[2] == '@' && buf[3] == '@')
				{
					next_token = buf + 4; //skip past 'mn@@'
				}
				else 
					path_plain = string(strtok_s(buf + 2, "@", &next_token));

				//if (!b64path.empty())
				//	path_plain = boost::filesystem::path((base64_decode(b64path)));
				//else
				//	path_plain = "";


				//todo: problem. module numbers can differ between runs. need to translate them on a per trace basis.
				char *localmodnum_s = strtok_s(next_token, "@", &next_token);
				long localmodID = -1;
				sscanf_s(localmodnum_s, "%d", &localmodID);


				piddata->getDisassemblyWriteLock();

				if (runRecord->modIDTranslationVec.at(localmodID) != -1)
				{
					wcerr << "[rgat]ERROR: PID:" << runRecord->PID << " Bad(prexisting) module number " << localmodID << " in mn [" <<
						buf << "]. current is:" << piddata->modpaths.at(localmodID) << endl;
					assert(0);
				}

				long globalModID;
				//auto modIDIt = piddata->globalModuleIDs.find(path_plain); //first time we have seen this module in any run of target
				//if (modIDIt == piddata->globalModuleIDs.end())
				//{
					globalModID = (long)piddata->modpaths.size();
					piddata->modpaths.push_back(path_plain);
					piddata->globalModuleIDs[path_plain] = globalModID;
					runRecord->modIDTranslationVec[localmodID] = globalModID;
				//}
				//else
				//{
				//	globalModID = modIDIt->second;
				//	runRecord->modIDTranslationVec[localmodID] = globalModID;
				//}

				piddata->dropDisassemblyWriteLock();


				//todo: safe stol? if this is safe whytf have i implented safe stol
				char *startaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS startaddr = 0;
				sscanf_s(startaddr_s, "%llx", &startaddr);

				char *endaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS endaddr = 0;
				sscanf_s(endaddr_s, "%llx", &endaddr);


				char *is_instrumented_s = strtok_s(next_token, "@", &next_token);
				piddata->getDisassemblyWriteLock();
				runRecord->activeMods[globalModID] = (*is_instrumented_s == INSTRUMENTED_CODE);
				piddata->dropDisassemblyWriteLock();

				if (!startaddr | !endaddr | (next_token - buf != bytesRead)) {
					wcerr << "ERROR! Processing module line: "<< buf << endl;
					assert(0);
				}

				//cout << "load module " << std::hex << path_plain << " addr  0x" << startaddr << "-" << endaddr << " locmodid " << localmodID << " globmodid " << globalModID << endl;

				assert(runRecord->get_piddata()->modBounds.at(globalModID) == NULL);
				runRecord->get_piddata()->modBounds[globalModID] = new pair<MEM_ADDRESS, MEM_ADDRESS>(startaddr, endaddr);
				runRecord->loadedModuleCount++;

				continue;
			}

			//request for commands
			//dynamorio has fairly crappy support for sending data to the client
			//doesnt like blocking either so client polls for commands
			if (buf[0] == 'C')
			{
				DWORD sent; //crashes on win7 without this
				if (!pendingControlCommand) //no command, send a heartbeat
				{
					char heartbeatbuf[] = "HB";
					WriteFile(controlPipe, heartbeatbuf, 2, &sent, 0);
					continue;
				}

				if (die)
				{
					char heartbeatbuf[] = "KT";
					WriteFile(controlPipe, heartbeatbuf, 2, &sent, 0);
					break;
				}
			}

			if (buf[0] == '!')
			{
				cout <<"[Msg from instrumentation]:"<< buf << endl;
				continue;
			}



			cerr << "[rgat]ERROR: Bad module handler input from instrumentation: " << buf << endl;
			break;

		}
	}

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

	runRecord->notify_pid_end(runRecord->PID, runRecord->randID);
	runRecord->set_running(false); //the process is done
	clientState->processEnded();

	CloseHandle(inputPipe);
	alive = false; //this thread is done
}

void gat_module_handler::start_thread_rendering(PID_TID TID, HANDLE threadpipe)
{
	proto_graph *newProtoGraph = new proto_graph(runRecord, TID);
	plotted_graph* newPlottedGraph = (plotted_graph *)clientState->createNewPlottedGraph(newProtoGraph);

	newPlottedGraph->initialiseDefaultDimensions();
	newPlottedGraph->set_animation_update_rate(clientState->config.animationUpdateRate);

	thread_trace_reader *TID_reader = new thread_trace_reader(newProtoGraph, threadpipe);
	TID_reader->traceBufMax = clientState->config.traceBufMax;
	newProtoGraph->setReader(TID_reader);

	threadList.push_back(TID_reader);
	readerThreadList.push_back(TID_reader);
	std::thread tracereader(&thread_trace_reader::ThreadEntry, TID_reader);
	tracereader.detach();

	trace_graph_builder *graph_builder = new trace_graph_builder(runRecord, newProtoGraph, TID_reader);

	if (!runRecord->insert_new_thread(TID, newPlottedGraph, newProtoGraph))
	{
		wcerr << "[rgat]ERROR: Trace rendering thread creation failed" << endl;
		return;
	}

	threadList.push_back(graph_builder);
	std::thread graph_builder_thread(&trace_graph_builder::ThreadEntry, graph_builder);
	graph_builder_thread.detach();
}

void gat_module_handler::sendIncludeLists()
{

	string buf;	
	DWORD bytesRead;
	BWPATHLISTS includelists = binary->getBWListPaths();

	if (includelists.inWhitelistMode)
	{
		if (includelists.WLDirs.empty() && includelists.WLFiles.empty())
			std::cerr << "Warning: Exclude mode with nothing included. Nothing will be instrumented." << std::endl;

		buf = "@W";
		for each (boost::filesystem::path path in includelists.WLDirs)
		{
			buf.append("@D@");
			buf.append(path.string());
		}
		for each (boost::filesystem::path path in includelists.WLFiles)
		{
			buf.append("@F@");
			buf.append(path.string());
		}
	}
	else
	{

		buf = "@B";
		for each (boost::filesystem::path path in includelists.BLDirs)
		{
			buf.append("@D@");
			buf.append(path.string());
		}
		for each (boost::filesystem::path path in includelists.BLFiles)
		{
			buf.append("@F@");
			buf.append(path.string());
		}
	}

	buf.append("@X");

	cout << "Sending includelist data: " << buf << endl;
	WriteFile(inputPipe, &buf.at(0), (DWORD)buf.size(), &bytesRead, 0);
}