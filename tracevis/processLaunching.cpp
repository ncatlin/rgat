#pragma once 
#include <stdafx.h>
#include "processLaunching.h"

//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
//+ module data and disassembly
THREAD_POINTERS *launch_new_process_threads(PID_TID PID, std::map<PID_TID, PROCESS_DATA *> *glob_piddata_map, HANDLE pidmutex, VISSTATE *clientState, cs_mode bitWidth)
{
	THREAD_POINTERS *processThreads = new THREAD_POINTERS;
	PROCESS_DATA *piddata = new PROCESS_DATA(bitWidth);
	piddata->PID = PID;
	if (clientState->switchProcess)
		clientState->spawnedProcess = piddata;

	if (!obtainMutex(pidmutex, 1038)) return 0;
	glob_piddata_map->insert_or_assign(PID, piddata);
	dropMutex(pidmutex);

	//spawns trace threads + handles module data for process
	module_handler *tPIDThread = new module_handler(PID, 0);
	tPIDThread->clientState = clientState;
	tPIDThread->piddata = piddata;

	rgat_create_thread((LPTHREAD_START_ROUTINE)tPIDThread->ThreadEntry, tPIDThread);
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	basicblock_handler *tBBHandler = new basicblock_handler(PID, 0, bitWidth);
	tBBHandler->clientState = clientState;
	tBBHandler->piddata = piddata;

	rgat_create_thread((LPTHREAD_START_ROUTINE)tBBHandler->ThreadEntry, tBBHandler);
	processThreads->BBthread = tBBHandler;
	processThreads->threads.push_back(tBBHandler);

	//non-graphical
	if (!clientState->commandlineLaunchPath.empty()) return processThreads;

	//graphics rendering threads for each process here	
	preview_renderer *tPrevThread = new preview_renderer(PID, 0);
	tPrevThread->clientState = clientState;
	tPrevThread->piddata = piddata;

	rgat_create_thread((LPTHREAD_START_ROUTINE)tPrevThread->ThreadEntry, tPrevThread);

	heatmap_renderer *tHeatThread = new heatmap_renderer(PID, 0);
	tHeatThread->clientState = clientState;
	tHeatThread->piddata = piddata;
	tHeatThread->setUpdateDelay(clientState->config->heatmap.delay);

	rgat_create_thread((LPTHREAD_START_ROUTINE)tHeatThread->ThreadEntry, tHeatThread);

	processThreads->heatmapThread = tHeatThread;
	processThreads->threads.push_back(tHeatThread);


	conditional_renderer *tCondThread = new conditional_renderer(PID, 0);
	tCondThread->clientState = clientState;
	tCondThread->piddata = piddata;
	tCondThread->setUpdateDelay(clientState->config->conditional.delay);
	Sleep(200);
	rgat_create_thread((LPTHREAD_START_ROUTINE)tCondThread->ThreadEntry, tCondThread);
	processThreads->conditionalThread = tCondThread;
	processThreads->threads.push_back(tCondThread);

	return processThreads;
}

#ifdef WIN32
void process_coordinator_listener(VISSTATE *clientState, vector<THREAD_POINTERS *> *threadsList)
{
	//todo: posibly worry about pre-existing if pidthreads dont work

	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\BootstrapPipe",
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
		255, 65536, 65536, 0, NULL);

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		cout << "[rgat]CreateNamedPipe failed with error " << GetLastError();
		return;
	}

	DWORD res = 0, bread = 0;
	char buf[40];
	while (!clientState->die)
	{
		bool conFail = ConnectNamedPipe(hPipe, &ov);
		if (conFail)
		{
			cerr << "[rgat]Warning! Bootstrap connection error" << endl;
			Sleep(1000);
			continue;
		}

		int err = GetLastError();
		if (err == ERROR_IO_PENDING || err == ERROR_PIPE_LISTENING) {
			res = WaitForSingleObject(ov.hEvent, 3000);
			if (res == WAIT_TIMEOUT) {
				Sleep(100);
				continue;
			}
		}

		ReadFile(hPipe, buf, 30, &bread, NULL);
		DisconnectNamedPipe(hPipe);

		if (!bread) {
			cout << "[rgat]ERROR: Read 0 when waiting for PID. Try again" << endl;
			Sleep(1000);
			continue;
		}
		buf[bread] = 0;

		PID_TID PID = 0;
		cs_mode bitWidth = extract_pid_bitwidth(buf, string("PID"), &PID);
		if (bitWidth)
		{
			clientState->timelineBuilder->notify_new_pid(PID);
			THREAD_POINTERS *threadPointers = launch_new_process_threads(PID, &clientState->glob_piddata_map, clientState->pidMapMutex, clientState, bitWidth);
			threadsList->push_back(threadPointers);
			continue;
		}

	}
}
#endif // WIN32

//listens for new and dying processes, spawns and kills threads to handle them
void process_coordinator_thread(VISSTATE *clientState)
{

	vector<THREAD_POINTERS *> threadsList;
	process_coordinator_listener(clientState, &threadsList);
	if (threadsList.empty()) return;

	//we get here when rgat is exiting
	//this tells all the child threads to die
	vector<THREAD_POINTERS *>::iterator processIt;
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		THREAD_POINTERS *p = ((THREAD_POINTERS *)*processIt);
		vector<base_thread *>::iterator threadIt = p->threads.begin();
		for (; threadIt != p->threads.end(); ++threadIt)
		{
			//killing BB thread frees the disassembly data, causing race
			if (*threadIt == p->BBthread) continue;
			((base_thread *)*threadIt)->kill();
		}
	}

	//wait for all children to terminate
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		THREAD_POINTERS *p = ((THREAD_POINTERS *)*processIt);
		vector<base_thread *>::iterator threadIt = p->threads.begin();

		for (; threadIt != p->threads.end(); ++threadIt)
		{
			int waitLimit = 100;
			while (true)
			{
				if (!waitLimit--) ExitProcess(-1);
				if (((base_thread *)*threadIt)->is_alive()) {
					Sleep(2);
					continue;
				}
				break;
			}
		}
	}

	//now safe to kill the disassembler threads
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
		((THREAD_POINTERS *)*processIt)->BBthread->kill();

	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
		while (((THREAD_POINTERS *)*processIt)->BBthread->is_alive())
			Sleep(1);

	clientState->glob_piddata_map.clear();
}

//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
void launch_saved_process_threads(PID_TID PID, PROCESS_DATA *piddata, VISSTATE *clientState)
{
	preview_renderer *previews_thread = new preview_renderer(PID, 0);
	previews_thread->clientState = clientState;
	previews_thread->piddata = piddata;
	rgat_create_thread((LPTHREAD_START_ROUTINE)previews_thread->ThreadEntry, previews_thread);

	heatmap_renderer *heatmap_thread = new heatmap_renderer(PID, 0);
	heatmap_thread->clientState = clientState;
	heatmap_thread->piddata = piddata;
	rgat_create_thread((LPTHREAD_START_ROUTINE)heatmap_thread->ThreadEntry, heatmap_thread);

	conditional_renderer *conditional_thread = new conditional_renderer(PID, 0);
	conditional_thread->clientState = clientState;
	conditional_thread->piddata = piddata;
	Sleep(200);
	rgat_create_thread((LPTHREAD_START_ROUTINE)conditional_thread->ThreadEntry, conditional_thread);

	clientState->spawnedProcess = clientState->glob_piddata_map[PID];
}