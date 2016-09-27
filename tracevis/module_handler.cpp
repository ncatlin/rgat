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
This is the base thread for each instrumented process.
It reads module and symbol data for the process
It also launches trace reader and handler threads when the process spawns a thread
*/

#include "stdafx.h"
#include "module_handler.h"
#include "traceMisc.h"
#include "trace_handler.h"
#include "thread_trace_reader.h"
#include "thread_graph_data.h"
#include "GUIManagement.h"
#include "b64.h"

void __stdcall module_handler::ThreadEntry(void* pUserData) {
	module_handler *newThread = (module_handler*)pUserData;
	return newThread->PID_thread();
}

//listen to mod data for given PID
void module_handler::PID_thread()
{
	pipename = wstring(L"\\\\.\\pipe\\rioThreadMod");
	pipename.append(std::to_wstring(PID));

	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 64, 56 * 1024, 0, NULL);

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	if (ConnectNamedPipe(hPipe, &ov))
	{
		wcerr << "[rgat]ERROR: Failed to ConnectNamedPipe to " << pipename << " for PID "<<PID<< ". Error: " << GetLastError();
		return;
	}

	while (true)
	{
		int result = WaitForSingleObject(ov.hEvent, 3000);
		if (result != WAIT_TIMEOUT) break;
		cerr << "[rgat]WARNING: Long wait for module handler pipe" << endl;
	}

	//if not launch by command line - do GUI stuff
	if (clientState->commandlineLaunchPath.empty())
	{
		TraceVisGUI* widgets = (TraceVisGUI *)clientState->widgets;
		widgets->addPID(PID);
	}

	char buf[400] = { 0 };
	int PIDcount = 0;

	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	vector < pair <thread_trace_reader*, thread_trace_handler *>> threadList;
	DWORD res= 0;
	while (!die)
	{
		DWORD bread = 0;
		ReadFile(hPipe, buf, 399, &bread, &ov2);
		while (true)
		{
			if (WaitForSingleObject(ov2.hEvent, 300) != WAIT_TIMEOUT) break;
			if (die || clientState->die) {
				die = true;
				break;
			}
		}
		if (clientState->die || die) break;

		if (GetLastError() != ERROR_IO_PENDING) continue;
		int res2 = GetOverlappedResult(hPipe, &ov2, &bread, false);
		buf[bread] = 0;
	
		if (!bread)
		{
			//not sure this ever gets called, read probably fails?
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				cerr << "[rgat]ERROR. threadpipe ReadFile error: " << err << endl;
			piddata->active = false;
			cerr << "Mod pipe exit" << endl;
			return;
		}
		else
		{	
			if (buf[0] == 'T' && buf[1] == 'I')
			{
				int TID = 0;
				if (!extract_integer(buf, string("TI"), &TID))
				{
					cerr << "[rgat] Fail to extract thread ID from TI tag:" << buf << endl;
					continue;
				}
				
				thread_graph_data *graph = new thread_graph_data(piddata, TID);
				thread_trace_reader *TID_reader = new thread_trace_reader(graph, PID, TID);
				TID_reader->traceBufMax = clientState->config->traceBufMax;
				graph->setReader(TID_reader);

				DWORD threadID = 0;
				HANDLE hOutThread = CreateThread(
					NULL, 0, (LPTHREAD_START_ROUTINE)TID_reader->ThreadEntry,
					(LPVOID)TID_reader, 0, &threadID);

				thread_trace_handler *TID_thread = new thread_trace_handler(graph, PID, TID);

				TID_thread->piddata = piddata;
				TID_thread->reader = TID_reader;
				TID_thread->timelinebuilder = clientState->timelineBuilder;
				if (clientState->launchopts.basic)
					TID_thread->basicMode = true;

				threadList.push_back(make_pair(TID_reader, TID_thread));

				if (clientState->launchopts.basic)
					graph->basic = true;

				if (!obtainMutex(piddata->graphsListMutex, 1010)) return;
				if (piddata->graphs.count(TID) > 0)
					cerr << "[rgat]ERROR: Duplicate thread ID! Tell the dev to stop being awful" << endl;
				piddata->graphs.insert(make_pair(TID, (void*)graph));
				dropMutex(piddata->graphsListMutex);

				clientState->timelineBuilder->notify_new_tid(PID, TID);
				hOutThread = CreateThread(
					NULL, 0, (LPTHREAD_START_ROUTINE)TID_thread->ThreadEntry,
					(LPVOID)TID_thread, 0, &threadID);

				continue;
			}

			if (buf[0] == 's' && buf[1] == '!' && bread > 8)
			{
				char *next_token = NULL;
				unsigned int modnum = atoi(strtok_s(buf + 2, "@", &next_token));
				string symname = string(strtok_s(next_token, "@", &next_token));
				char *offset_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS address;
				sscanf_s(offset_s, "%x", &address);
				assert(piddata->modBounds.count(modnum)); //fail if sym came before module
				address += piddata->modBounds.at(modnum).first;
				if (!address | (next_token - buf != bread)) continue;
				if (modnum > piddata->modpaths.size()) {
					cerr << "[rgat]Bad mod number "<<modnum<< "in sym processing. " <<
						piddata->modpaths.size() << " exist." << endl;
					continue;
				}

				piddata->modsyms[modnum][address] = base64_decode(symname);
				continue;
			}

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

				if (piddata->modpaths.count(modnum) > 0) {
					printf("\n\nERROR: PID:%d, Bad(prexisting) module number %d in mn [%s]. current is:%s\n\n", 
						PID,modnum,buf, piddata->modpaths.at(modnum).c_str());
					assert(0);
				}

				//todo: safe stol? if this is safe whytf have i implented safe stol
				char *startaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS startaddr = 0;
				sscanf_s(startaddr_s, "%lx", &startaddr);

				char *endaddr_s = strtok_s(next_token, "@", &next_token);
				MEM_ADDRESS endaddr = 0;
				sscanf_s(endaddr_s, "%lx", &endaddr);

				char *skipped_s = strtok_s(next_token, "@", &next_token);
				if (*skipped_s == '1')
					piddata->activeMods.insert(piddata->activeMods.begin() + modnum, MOD_UNINSTRUMENTED);
				else
					piddata->activeMods.insert(piddata->activeMods.begin() + modnum, MOD_ACTIVE);

				if (!startaddr | !endaddr | (next_token - buf != bread)) {
					printf("ERROR! Processing module line: %s\n", buf);
					assert(0);
				}

				if (!b64path.empty())
					piddata->modpaths[modnum] = base64_decode(b64path);
				else
					piddata->modpaths[modnum] = string("NULL");
				
				piddata->modBounds[modnum] = make_pair(startaddr, endaddr);
				printf("mod: %d = %s\n", modnum, piddata->modpaths[modnum].c_str());
				continue;
			}
		}
	}

	vector < pair <thread_trace_reader*, thread_trace_handler *>>::iterator threadIt;
	for (threadIt = threadList.begin(); threadIt != threadList.end(); ++threadIt)
	{
		threadIt->first->die = true;
		threadIt->second->die = true;
	}
	clientState->timelineBuilder->notify_pid_end(PID);
}