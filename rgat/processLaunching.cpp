#pragma once 
#include <stdafx.h>
#include "processLaunching.h"
#include "serialise.h"
#include "ui_rgat.h"

#define PIDSTRING_BUFSIZE MAX_PATH + 100

//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
//+ module data and disassembly

void launch_new_process_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState)
{
	
	PROCESS_DATA *piddata = new PROCESS_DATA(target->getBitWidth());

	//spawns trace threads + handles module data for process
	module_handler *tPIDThread = new module_handler(target, runRecord);

	THREAD_POINTERS *processThreads = (THREAD_POINTERS *)runRecord->processThreads;
	rgat_create_thread((LPTHREAD_START_ROUTINE)tPIDThread->ThreadEntry, tPIDThread);
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	basicblock_handler *tBBHandler = new basicblock_handler(target, runRecord);

	rgat_create_thread((LPTHREAD_START_ROUTINE)tBBHandler->ThreadEntry, tBBHandler);
	processThreads->BBthread = tBBHandler;
	processThreads->threads.push_back(tBBHandler);

	//non-graphical
	if (!clientState->openGLWorking()) return;

	//graphics rendering threads for each process here	
	preview_renderer *tPrevThread = new preview_renderer(runRecord);
	processThreads->previewThread = tPrevThread;
	rgat_create_thread((LPTHREAD_START_ROUTINE)tPrevThread->ThreadEntry, tPrevThread);

	heatmap_renderer *tHeatThread = new heatmap_renderer(runRecord);
	

	rgat_create_thread((LPTHREAD_START_ROUTINE)tHeatThread->ThreadEntry, tHeatThread);

	processThreads->heatmapThread = tHeatThread;
	processThreads->threads.push_back(tHeatThread);

	conditional_renderer *tCondThread = new conditional_renderer(runRecord);

	Sleep(200);
	rgat_create_thread((LPTHREAD_START_ROUTINE)tCondThread->ThreadEntry, tCondThread);
	processThreads->conditionalThread = tCondThread;
	processThreads->threads.push_back(tCondThread);
}



#ifdef WIN32

//respond to a new trace notification by creating a target (if not already existing) and a new trace for it 
//along with threads to process that trace
void process_new_PID_notification(rgatState *clientState, vector<THREAD_POINTERS *> *threadsList, vector <char> *buf)
{
	PID_TID PID = 0;
	boost::filesystem::path binarypath;
	int PID_ID;
	cs_mode bitWidth = extract_pid_bitwidth_path(buf, string("PID"), &PID, &PID_ID, &binarypath);
	if (bitWidth)
	{
		PID_TID parentPID = getParentPID(PID);

		binaryTarget *target;

		clientState->targets.getTargetByPath(binarypath, &target);
		target->applyBitWidthHint(bitWidth);

		traceRecord *trace = target->createNewTrace(PID, PID_ID, TIMENOW_IN_MS);
		trace->setBinaryPtr(target);
		trace->notify_new_pid(PID, PID_ID, parentPID);

		clientState->targets.registerChild(parentPID, trace);

		launch_new_process_threads(target, trace, clientState);
		threadsList->push_back((THREAD_POINTERS *)trace->processThreads);

		if (clientState->waitingForNewTrace)
		{
			clientState->updateActivityStatus("New process started with PID: " + QString::number(trace->get_piddata()->PID), 5000);
			clientState->switchTrace = trace;
			clientState->waitingForNewTrace = false;
		}

	}
	else
	{
		cerr << "[rgat]Bad bitwidth " << bitWidth << " or path " << binarypath << endl;
	}
}

//read notifications of new traces from drgat clients over the bootstrap pipe
bool read_new_PID_notification_sleepy(vector <char> *buf, HANDLE hPipe, OVERLAPPED *ov)
{

	bool conFail = ConnectNamedPipe(hPipe, ov);
	if (conFail)
	{
		cerr << "[rgat]Warning! Bootstrap connection error" << endl;
		Sleep(1000);
		return false;
	}

	int err = GetLastError();
	if (err == ERROR_IO_PENDING || err == ERROR_PIPE_LISTENING) 
	{
		if (WaitForSingleObject(ov->hEvent, 3000) == WAIT_TIMEOUT)
		{
			Sleep(100);
			return false;
		}
	}

	buf->clear();
	buf->resize(PIDSTRING_BUFSIZE-1, 0);
	DWORD bread = 0;
	bool success = ReadFile(hPipe, &buf->at(0), buf->size(), &bread, NULL);
	DisconnectNamedPipe(hPipe);
	buf->resize(bread, 0);

	if (!success || !bread)
	{
		cerr << "[rgat]ERROR: Failed to read process notification. Try again" << endl;
		Sleep(1000);
		return false;
	}

	return true;
}

//listens for traces on the bootstrap pipe
void process_coordinator_listener(rgatState *clientState, vector<THREAD_POINTERS *> *threadsList)
{
	//todo: posibly worry about pre-existing if pidthreads dont work

	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\BootstrapPipe",
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
		255, 65536, 65536, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat]CreateNamedPipe failed with error " << GetLastError() << endl;
		return;
	}

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	DWORD res = 0, bread = 0;
	vector <char> buf;
	buf.resize(PIDSTRING_BUFSIZE, 0);
	while (!clientState->rgatIsExiting())
	{
		if (read_new_PID_notification_sleepy(&buf, hPipe, &ov))
		{
			process_new_PID_notification(clientState, threadsList, &buf);
		}
	}
}
#endif // WIN32

//spawns the trace handler then cleans up after it on exit
void process_coordinator_thread(rgatState *clientState)
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
				if (!waitLimit--) ExitProcess(-1); //why troubleshoot bad thread coding when you can smash with hammer?
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
}

//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
void launch_saved_process_threads(traceRecord *runRecord, rgatState *clientState)
{
	preview_renderer *previews_thread = new preview_renderer(runRecord);
	rgat_create_thread((LPTHREAD_START_ROUTINE)previews_thread->ThreadEntry, previews_thread);

	heatmap_renderer *heatmap_thread = new heatmap_renderer(runRecord);
	rgat_create_thread((LPTHREAD_START_ROUTINE)heatmap_thread->ThreadEntry, heatmap_thread);

	conditional_renderer *conditional_thread = new conditional_renderer(runRecord);
	Sleep(200);
	rgat_create_thread((LPTHREAD_START_ROUTINE)conditional_thread->ThreadEntry, conditional_thread);
}