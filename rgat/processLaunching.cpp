#pragma once 
#include <stdafx.h>
#include "processLaunching.h"
#include "serialise.h"
#include "ui_rgat.h"
#include "osSpecific.h"
#include <thread>


#define PIDSTRING_BUFSIZE MAX_PATH + 100

//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
//+ module data and disassembly

void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState)
{
	//spawns trace threads + handles module data for process
	drgat_module_handler *tPIDThread = new drgat_module_handler(target, runRecord, L"rioThreadMod");

	RGAT_THREADS_STRUCT *processThreads = new RGAT_THREADS_STRUCT;
	runRecord->processThreads = processThreads;
	std::thread modthread(&drgat_module_handler::ThreadEntry, tPIDThread);
	modthread.detach();
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	drgat_basicblock_handler *tBBHandler = new drgat_basicblock_handler(target, runRecord, L"rioThreadBB");

	std::thread bbthread(&drgat_basicblock_handler::ThreadEntry, tBBHandler);
	bbthread.detach();
	processThreads->BBthread = tBBHandler;
	processThreads->threads.push_back(tBBHandler);

	//non-graphical
	if (!clientState->openGLWorking()) return;

	//graphics rendering threads for each process here	
	preview_renderer *tPrevThread = new preview_renderer(runRecord);
	processThreads->previewThread = tPrevThread;
	std::thread previewthread(&preview_renderer::ThreadEntry, tPrevThread);
	previewthread.detach();

	heatmap_renderer *tHeatThread = new heatmap_renderer(runRecord);
	std::thread heatthread(&heatmap_renderer::ThreadEntry, tHeatThread);
	heatthread.detach();
	processThreads->heatmapThread = tHeatThread;
	processThreads->threads.push_back(tHeatThread);

	conditional_renderer *tCondThread = new conditional_renderer(runRecord);
	Sleep(200);
	std::thread condthread(&conditional_renderer::ThreadEntry, tCondThread);
	condthread.detach();
	processThreads->conditionalThread = tCondThread;
	processThreads->threads.push_back(tCondThread);
}



#ifdef WIN32

//respond to a new trace notification by creating a target (if not already existing) and a new trace for it 
//along with threads to process that trace
void process_new_drgat_connection(rgatState *clientState, vector<RGAT_THREADS_STRUCT *> *threadsList, vector <char> *buf)
{
	PID_TID PID = 0;
	boost::filesystem::path binarypath;
	int PID_ID;
	cs_mode bitWidth = extract_pid_bitwidth_path(buf, string("PID"), &PID, &PID_ID, &binarypath);
	if (bitWidth)
	{
		PID_TID parentPID = getParentPID(PID);

		binaryTarget *target;
		binaryTargets *container;

		if (clientState->testsRunning && clientState->testTargets.exists(binarypath))
			container = &clientState->testTargets;
		else
			container = &clientState->targets;

		container->getTargetByPath(binarypath, &target);

		target->applyBitWidthHint(bitWidth);

		traceRecord *trace = target->createNewTrace(PID, PID_ID, TIMENOW_IN_MS);
		trace->setTraceType(eTracePurpose::eVisualiser);
		trace->notify_new_pid(PID, PID_ID, parentPID);

		container->registerChild(parentPID, trace);

		launch_new_visualiser_threads(target, trace, clientState);

		threadsList->push_back((RGAT_THREADS_STRUCT *)trace->processThreads);

		if (clientState->waitingForNewTrace)
		{
			clientState->updateActivityStatus("New process started with PID: " + QString::number(trace->PID), 5000);
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
bool read_drgat_newPID_sleepy(vector <char> *buf, HANDLE hPipe, OVERLAPPED *ov)
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
void process_coordinator_listener(rgatState *clientState, vector<RGAT_THREADS_STRUCT *> *threadsList)
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

	vector <char> buf;
	buf.resize(PIDSTRING_BUFSIZE, 0);
	while (!clientState->rgatIsExiting())
	{
		if (read_drgat_newPID_sleepy(&buf, hPipe, &ov))
		{
			process_new_drgat_connection(clientState, threadsList, &buf);
		}
	}
}
#endif // WIN32

//spawns the trace handler then cleans up after it on exit
void process_coordinator_thread(rgatState *clientState)
{

	vector<RGAT_THREADS_STRUCT *> threadsList;
	process_coordinator_listener(clientState, &threadsList);
	if (threadsList.empty()) return;

	//we get here when rgat is exiting
	//this tells all the child threads to die
	vector<RGAT_THREADS_STRUCT *>::iterator processIt;
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		RGAT_THREADS_STRUCT *p = ((RGAT_THREADS_STRUCT *)*processIt);
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
		RGAT_THREADS_STRUCT *p = ((RGAT_THREADS_STRUCT *)*processIt);
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
		((RGAT_THREADS_STRUCT *)*processIt)->BBthread->kill();

	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
		while (((RGAT_THREADS_STRUCT *)*processIt)->BBthread->is_alive())
			Sleep(1);
}

//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
void launch_saved_process_threads(traceRecord *runRecord, rgatState *clientState)
{
	preview_renderer *previews_thread = new preview_renderer(runRecord);
	std::thread previewsthread(&preview_renderer::ThreadEntry, previews_thread);
	previewsthread.detach();

	heatmap_renderer *heatmap_thread = new heatmap_renderer(runRecord);
	std::thread heatthread(&heatmap_renderer::ThreadEntry, heatmap_thread);
	heatthread.detach();

	conditional_renderer *conditional_thread = new conditional_renderer(runRecord);
	Sleep(200);
	std::thread condthread(&conditional_renderer::ThreadEntry, conditional_thread);
	condthread.detach();
}

string get_options(LAUNCHOPTIONS *launchopts)
{
	stringstream optstring;

	//rgat client options
	if (launchopts->removeSleeps)
		optstring << " -caffine";

	if (launchopts->pause)
		optstring << " -sleep";

	//if (launchopts->debugMode)
	//	optstring << " -blkdebug";
	return optstring.str();
}

//take the target binary path, feed it into dynamorio with all the required options
void execute_tracer(void *binaryTargetPtr, clientConfig *config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS *launchopts = &target->launchopts;
	string runpath;
	if (!get_dr_drgat_commandline(config, launchopts, &runpath, (target->getBitWidth() == 64)))
		return;

	runpath.append(get_options(launchopts));
	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts->args;

	cout << "[rgat]Starting execution using command line [" << runpath << "]" << endl;

	boost::process::spawn(runpath);
}

void execute_dynamorio_test(void *binaryTargetPtr, clientConfig *config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS *launchopts = &target->launchopts;
	string runpath;
	if (!get_bbcount_path(config, launchopts, &runpath, (target->getBitWidth() == 64), "bbcount"))
		return;

	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts->args;

	cout << "[rgat]Starting test using command line [" << runpath << "]" << endl;
	boost::process::spawn(runpath);
}