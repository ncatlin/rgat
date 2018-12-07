
/*
Copyright 2016-2017 Nia Catlin
/*
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
#include "shrike_module_handler.h"
#include "traceMisc.h"
#include "fuzz_feedback_processor.h"
#include "thread_trace_reader.h"
#include "b64.h"
#include "fuzzRun.h"

#include <boost/filesystem.hpp>

//listen to module data for given process
void shrike_module_handler::main_loop()
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


	bool pendingControlCommand = false;

	while (true)
	{
		DWORD bytesRead = 0;
		ReadFile(hPipe, buf, 399, &bytesRead, &ov2);
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

		int res2 = GetOverlappedResult(hPipe, &ov2, &bytesRead, false);
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
				WriteLock disassemblyWriteLock(piddata->disassemblyRWLock);
				piddata->modsymsPlain[runRecord->modIDTranslationVec.at(modnum)][offset] = symname;
				disassemblyWriteLock.unlock();
				continue;
			}

			//module/dll
			if (buf[0] == 'm' && buf[1] == 'n' && bytesRead > 8)
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

				boost::filesystem::path path_plain;
				if (!b64path.empty())
					path_plain = boost::filesystem::path((base64_decode(b64path)));
				else
					path_plain = "";


				//todo: problem. module numbers can differ between runs. need to translate them on a per trace basis.
				char *localmodnum_s = strtok_s(next_token, "@", &next_token);
				long localmodID = -1;
				sscanf_s(localmodnum_s, "%d", &localmodID);


				WriteLock disassemblyWriteLock(piddata->disassemblyRWLock);

				if (runRecord->modIDTranslationVec.at(localmodID) != -1)
				{
					wcerr << "[rgat]ERROR: PID:" << runRecord->PID << " Bad(prexisting) module number " << localmodID << " in mn [" <<
						buf << "]. current is:" << piddata->modpaths.at(localmodID) << endl;
					assert(0);
				}

				long globalModID;
				auto modIDIt = piddata->globalModuleIDs.find(path_plain); //first time we have seen this module in any run of target
				if (modIDIt == piddata->globalModuleIDs.end())
				{
					globalModID = (long)piddata->modpaths.size();
					piddata->modpaths.push_back(path_plain);
					piddata->globalModuleIDs[path_plain] = globalModID;
					runRecord->modIDTranslationVec[localmodID] = globalModID;
				}
				else
				{
					globalModID = modIDIt->second;
					runRecord->modIDTranslationVec[localmodID] = globalModID;
				}

				disassemblyWriteLock.unlock();


				//todo: safe stol? if this is safe whytf have i implented safe stol
				char *startaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS startaddr = 0;
				sscanf_s(startaddr_s, "%llx", &startaddr);

				char *endaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS endaddr = 0;
				sscanf_s(endaddr_s, "%llx", &endaddr);


				char *is_instrumented_s = strtok_s(next_token, "@", &next_token);
				disassemblyWriteLock.lock();
				runRecord->activeMods[globalModID] = (*is_instrumented_s == INSTRUMENTED_CODE);
				disassemblyWriteLock.unlock();

				if (!startaddr | !endaddr | (next_token - buf != bytesRead)) {
					wcerr << "ERROR! Processing module line: " << buf << endl;
					assert(0);
				}

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
				if (!pendingControlCommand) //no command, send a heartbeat
				{
					char heartbeatbuf[] = "HB";
					DWORD sent; //crashes on win7 without this here
					WriteFile(controlPipe, heartbeatbuf, 2, &sent, 0);
					continue;
				}

				if (die)
				{
					char heartbeatbuf[] = "KT";
					WriteFile(controlPipe, heartbeatbuf, 2, 0, 0);
					break;
				}
			}
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
	alive = false; //this thread is done
}

void  shrike_module_handler::start_thread_rendering(PID_TID TID)
{

	thread_trace_reader *TID_reader = new thread_trace_reader();
	TID_reader->traceBufMax = clientState->config.traceBufMax;

	threadList.push_back(TID_reader);
	readerThreadList.push_back(TID_reader);
	std::thread tracereader(&thread_trace_reader::ThreadEntry, TID_reader);
	tracereader.detach();



	fuzz_feedback_processor *feedback_processor = new fuzz_feedback_processor(runRecord, TID_reader);
	threadList.push_back(feedback_processor);
	std::thread feedback_reader_thread(&fuzz_feedback_processor::ThreadEntry, feedback_processor);
	feedback_reader_thread.detach();
}