#include "stdafx.h"
#include "module_handler.h"
#include "traceMisc.h"
#include "trace_handler.h"
#include "thread_trace_reader.h"
#include "thread_graph_data.h"
#include "GUIManagement.h"

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
	std::wcout << "[vis mod handler] creating mod thread " << szName << endl;
	wprintf(L"creating mod thread %s\n", szName);

	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 64, 56 * 1024, 300, NULL);

	int conresult = ConnectNamedPipe(hPipe, NULL);
	printf("[vis mod handler]connect result: %d, GLE:%d. Waiting for input...\n", conresult,GetLastError());
	
	if (clientState->commandlineLaunchPath.empty())
	{
		TraceVisGUI* widgets = (TraceVisGUI *)clientState->widgets;
		widgets->addPID(PID);
	}

	char buf[400] = { 0 };
	int PIDcount = 0;

	vector < pair <thread_trace_reader*, thread_trace_handler *>> threadList;

	while (true)
	{
		if (die)break; 
		DWORD bread = 0;
		if (!ReadFile(hPipe, buf, 399, &bread, NULL)) {
			printf("Failed to read metadata pipe for PID:%d\n", PID);
			break;
		}
		buf[bread] = 0;

		if (!bread)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				printf("threadpipe PIPE ERROR: %d\n", err);
			printf("\t!----------pid mod pipe %d broken------------\n", PID);
			piddata->active = false;
			return;
		}
		else
		{	
			if (buf[0] == 'T' && buf[1] == 'I')
			{
				printf("[MODTHREAD PID %d] got TI %s\n",PID, buf);
				int TID = 0;
				if (!extract_integer(buf, string("TI"), &TID))
				{
					printf("\tMODHANDLER TI: ERROR GOT TI BUT NO EX XTRACT!\n");
					continue;
				}
				DWORD threadID = 0;

				thread_trace_reader *TID_reader = new thread_trace_reader;
				TID_reader->PID = PID;
				TID_reader->TID = TID;
				HANDLE hOutThread = CreateThread(
					NULL, 0, (LPTHREAD_START_ROUTINE)TID_reader->ThreadEntry,
					(LPVOID)TID_reader, 0, &threadID);

				thread_trace_handler *TID_thread = new thread_trace_handler;
				TID_thread->PID = PID;
				TID_thread->TID = TID;
				TID_thread->piddata = piddata;
				TID_thread->reader = TID_reader;
				TID_thread->timelinebuilder = clientState->timelineBuilder;
				if (clientState->launchopts.basic)
					TID_thread->basicMode = true;

				threadList.push_back(make_pair(TID_reader, TID_thread));

				thread_graph_data *tgraph =  new thread_graph_data(&piddata->disassembly, piddata->disassemblyMutex);
				if (clientState->launchopts.basic)
					tgraph->basic = true;
				tgraph->setReader(TID_reader);

				tgraph->tid = TID; //todo: dont need this
				if (!obtainMutex(piddata->graphsListMutex, "Module Handler")) return;
				if (piddata->graphs.count(TID) > 0)
					printf("\n\n\t\tDUPICATE THREAD ID! TODO:MOVE TO INACTIVE\n\n");
				piddata->graphs.insert(make_pair(TID, (void*)tgraph));
				dropMutex(piddata->graphsListMutex, "Module Handler");

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
				char *symname = strtok_s(next_token, "@", &next_token);
				char *offset_s = strtok_s(next_token, "@", &next_token);
				unsigned long address;
				sscanf_s(offset_s, "%x", &address);
				address += piddata->modBounds.at(modnum).first;
				if (!address | !symname | (next_token - buf != bread)) continue;
				if (modnum > piddata->modpaths.size()) {
					printf("Bad mod number in s!\n");
					continue;
				}
				piddata->modsyms[modnum][address] = symname;
				continue;
			}

			if (buf[0] == 'm' && buf[1] == 'n' && bread > 8)
			{
				char *next_token = NULL;

				char *path = NULL;
				if (buf[2] == '@' && buf[3] == '@')
				{
					path = (char*)malloc(5); //mem leak
					snprintf(path, 5, "NULL");
					next_token = buf + 4;
				}
				else 
					path = strtok_s(buf + 2, "@", &next_token);

				char *modnum_s = strtok_s(next_token, "@", &next_token);
				long modnum = -1;
				sscanf_s(modnum_s, "%d", &modnum);

				if (piddata->modpaths.count(modnum) > 0) {
					printf("Bad modnum! in mn %s", buf);
					continue;
				}

				//todo: safe stol? if this is safe whytf have i implented safe stol
				char *startaddr_s = strtok_s(next_token, "@", &next_token);
				unsigned long startaddr = 0;
				sscanf_s(startaddr_s, "%lx", &startaddr);

				char *endaddr_s = strtok_s(next_token, "@", &next_token);
				unsigned long endaddr = 0;
				sscanf_s(endaddr_s, "%lx", &endaddr);

				char *skipped_s = strtok_s(next_token, "@", &next_token);
				if (*skipped_s == '1')
					piddata->activeMods.insert(piddata->activeMods.begin() + modnum, MOD_UNINSTRUMENTED);
				else
					piddata->activeMods.insert(piddata->activeMods.begin() + modnum, MOD_ACTIVE);

				if (!startaddr | !endaddr | (next_token - buf != bread)) {
					printf("ERROR! Processing mn line: %s\n", buf);
					continue;
				}

				piddata->modpaths[modnum] = string(path);
				piddata->modBounds[modnum] = make_pair(startaddr, endaddr);
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