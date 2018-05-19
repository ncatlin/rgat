#pragma once 
#include <stdafx.h>
#include "processLaunching.h"
#include "serialise.h"
#include "ui_rgat.h"
#include "osSpecific.h"
#include <thread>
//#include <QtNetwork\qnetworkdatagram.h>
#include <QtNetwork\qtcpsocket.h>
#include <QtNetwork\qtcpserver.h>

#define PIDSTRING_BUFSIZE MAX_PATH + 100

//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
//+ module data and disassembly

void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState)
{
	PIN_PIPES localhandles = { NULL, NULL, NULL };
	launch_new_visualiser_threads(target, runRecord, clientState, localhandles);
}

void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState, PIN_PIPES localhandles)
{
	//spawns trace threads + handles module data for process
	gat_module_handler *tPIDThread = new gat_module_handler(target, runRecord, L"rgatThreadMod", localhandles.modpipe, localhandles.controlpipe);

	RGAT_THREADS_STRUCT *processThreads = new RGAT_THREADS_STRUCT;
	runRecord->processThreads = processThreads;
	std::thread modthread(&gat_module_handler::ThreadEntry, tPIDThread);
	modthread.detach();
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	gat_basicblock_handler *tBBHandler = new gat_basicblock_handler(target, runRecord, L"rgatThreadBB", localhandles.bbpipe);

	std::thread bbthread(&gat_basicblock_handler::ThreadEntry, tBBHandler);
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
void process_new_drgat_connection(rgatState *clientState, vector<RGAT_THREADS_STRUCT *> *threadsList, string buf)
{
	PID_TID PID = 0;
	boost::filesystem::path binarypath;
	int PID_ID;
	cs_mode bitWidth = extract_pid_bitwidth_path(buf, string("PID"), &PID, &PID_ID, &binarypath);
	if (!bitWidth)
	{
		cerr << "[rgat]Bad bitwidth " << bitWidth << " or path " << binarypath << endl;
		return;
	}

	PID_TID parentPID = getParentPID(PID);

	binaryTarget *target;
	binaryTargets *container;

	if (clientState->testsRunning && clientState->testTargets.exists(binarypath))
		container = &clientState->testTargets;
	else
		container = &clientState->targets;

	container->getTargetByPath(binarypath, &target);

	target->applyBitWidthHint(bitWidth);

	traceRecord *trace = target->createNewTrace(PID, PID_ID, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
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






//read notifications of new traces from drgat clients over the bootstrap pipe
bool readpipe_drgat_newPID(string &resultstring, HANDLE hPipe, OVERLAPPED *ov)
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
		if (WaitForSingleObject(ov->hEvent, 500) == WAIT_TIMEOUT)
		{
			return false;
		}
	}

	vector <char> inbuf;
	inbuf.resize(PIDSTRING_BUFSIZE-1, 0);
	DWORD bread = 0;
	bool success = ReadFile(hPipe, &inbuf.at(0), (DWORD)inbuf.size(), &bread, NULL);
	DisconnectNamedPipe(hPipe);
	inbuf.resize(bread, 0);

	if (!success || !bread)
	{
		cerr << "[rgat]ERROR: Failed to read process notification. Try again" << endl;
		Sleep(1000);
		return false;
	}

	resultstring = string(inbuf.begin(), inbuf.end());
	return true;
}

#define SHAREDMEM_READY_FOR_USE 4
void create_pipes_for_pin(PID_TID PID, int PID_ID, void *sharedMem, PIN_PIPES &localHandles, cs_mode bitWidth)
{
	HANDLE remoteModpipeHandle, remoteBBpipeHandle, remoteCtrlPipeHandle;
	wstring pipepath;

	boost::filesystem::path pipeNameBase("\\\\.\\pipe\\");
	pipeNameBase += boost::filesystem::unique_path();
	pipeNameBase += "\\";

	pipeNameBase += to_wstring(PID_ID);
	pipepath = pipeNameBase.wstring() + L"mod";
	if (!createInputOutputPipe(PID, pipepath, localHandles.modpipe, remoteModpipeHandle))
		return;

	pipepath = pipeNameBase.wstring() + L"bb";
	if (!createInputPipe(PID, pipepath, localHandles.bbpipe, remoteBBpipeHandle))
		return;

	pipepath = pipeNameBase.wstring() + L"ctrl";
	if (!createOutputPipe(PID, pipepath, localHandles.controlpipe, remoteCtrlPipeHandle))
		return;

	size_t handleSize = (bitWidth == CS_MODE_32) ? 4 : 8;

	//copy the remote handles to mapped file for pin to use
	size_t memoffset = 1;
	memcpy((void *)((char *)sharedMem + memoffset), &remoteModpipeHandle, handleSize);
	memoffset += handleSize;
	memcpy((void *)((char *)sharedMem + memoffset), &remoteBBpipeHandle, handleSize);
	memoffset += handleSize;
	memcpy((void *)((char *)sharedMem + memoffset), &remoteCtrlPipeHandle, handleSize);

	//tell pin we are done writing the handles
	(*((char *)sharedMem + 0)) = SHAREDMEM_READY_FOR_USE;
}


void process_new_pin_connection(rgatState *clientState, vector<RGAT_THREADS_STRUCT *> *threadsList, void *sharedMem)
{

	string connectString = string((char *)sharedMem + 1);

	PID_TID PID = 0;
	boost::filesystem::path binarypath;
	int PID_ID;
	cs_mode bitWidth = extract_pid_bitwidth_path(connectString, string("PID"), &PID, &PID_ID, &binarypath);

	PIN_PIPES localHandles;
	create_pipes_for_pin(PID, PID_ID, sharedMem, localHandles, bitWidth);

	PID_TID parentPID = getParentPID(PID); //todo: pin can do this

	binaryTarget *target;
	binaryTargets *container;

	if (clientState->testsRunning && clientState->testTargets.exists(binarypath))
		container = &clientState->testTargets;
	else
		container = &clientState->targets;

	container->getTargetByPath(binarypath, &target);

	target->applyBitWidthHint(bitWidth);

	traceRecord *trace = target->createNewTrace(PID, PID_ID, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	trace->setTraceType(eTracePurpose::eVisualiser);
	trace->notify_new_pid(PID, PID_ID, parentPID);

	container->registerChild(parentPID, trace);


	launch_new_visualiser_threads(target, trace, clientState, localHandles);

	threadsList->push_back((RGAT_THREADS_STRUCT *)trace->processThreads);

	if (clientState->waitingForNewTrace)
	{
		clientState->updateActivityStatus("New process started with PID: " + QString::number(trace->PID), 5000);
		clientState->switchTrace = trace;
		clientState->waitingForNewTrace = false;
	}

}


//listens for traces on the bootstrap pipe
void process_coordinator_listener(rgatState *clientState, vector<RGAT_THREADS_STRUCT *> *threadsList)
{
	
	HANDLE hFileMap, diskfile;
	void* pBuf;

	boost::filesystem::path bootstrapPath = clientState->getTempDir();

	bootstrapPath += "\\bootstrapMap";

	diskfile = CreateFileA(bootstrapPath.string().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (diskfile == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat] Error: Failed to create mapfile on disk" << endl;
		return;
	}
	else
	{
		cout << "opened bootstrap map " << bootstrapPath.string() << endl;
	}

	hFileMap = CreateFileMappingA(diskfile,	NULL,	PAGE_READWRITE,  0,  1024, NULL);
	if (hFileMap == NULL)
	{
		cout << "Could not create file mapping object (" << GetLastError() << ")" << endl;
		return;
	}
	
	pBuf = MapViewOfFile(hFileMap,  FILE_MAP_ALL_ACCESS,0,0,1024);
	memset(pBuf, 31, 1024);

	string buf;
	buf.resize(PIDSTRING_BUFSIZE, 0);
	while (!clientState->rgatIsExiting())
	{
		int statusc = (char)(*((char *)pBuf));
		if (statusc == 2)
		{
			process_new_pin_connection(clientState, threadsList, pBuf);
		}
		Sleep(500);
	}

	CloseHandle(hFileMap);
	CloseHandle(diskfile);
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

	RGAT_THREADS_STRUCT *processThreads = new RGAT_THREADS_STRUCT;

	processThreads->previewThread = new preview_renderer(runRecord);
	std::thread previewsthread(&preview_renderer::ThreadEntry, processThreads->previewThread);
	previewsthread.detach();
	processThreads->threads.push_back(processThreads->previewThread);

	processThreads->heatmapThread = new heatmap_renderer(runRecord);
	std::thread heatthread(&heatmap_renderer::ThreadEntry, processThreads->heatmapThread);
	heatthread.detach();
	processThreads->threads.push_back(processThreads->heatmapThread);

	processThreads->conditionalThread = new conditional_renderer(runRecord);
	Sleep(200);
	std::thread condthread(&conditional_renderer::ThreadEntry, processThreads->conditionalThread);
	condthread.detach();
	processThreads->threads.push_back(processThreads->conditionalThread);

	runRecord->processThreads = processThreads;
}

string get_options(LAUNCHOPTIONS &launchopts)
{
	stringstream optstring;

	//rgat client options
	if (launchopts.removeSleeps)
		optstring << " -caffine";

	if (launchopts.pause)
		optstring << " -sleep";

	//if (launchopts->debugMode)
	//	optstring << " -blkdebug";
	return optstring.str();
}

//take the target binary path, feed it into dynamorio/pin with all the required options
bool execute_tracer(void *binaryTargetPtr, clientConfig &config, boost::filesystem::path tmpDir, bool pin = true)
{
	if (!binaryTargetPtr) return false;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS &launchopts = target->launchopts;
	string runpath;

	bool success;
	if (pin)
		success = get_pin_pingat_commandline(config, launchopts, runpath, (target->getBitWidth() == 64), tmpDir);
	else
		success = get_dr_drgat_commandline(config, launchopts, runpath, (target->getBitWidth() == 64));
	if(!success)
		return false;
	

	runpath.append(get_options(launchopts));
	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts.args;

	cout << "[rgat]Starting execution using command line [" << runpath << "]" << endl;

	boost::process::spawn(runpath);
	return true;
}

void execute_dynamorio_compatibility_test(void *binaryTargetPtr, clientConfig &config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS &launchopts = target->launchopts;
	string runpath;
	if (!get_bbcount_path(config, launchopts, runpath, (target->getBitWidth() == 64), "bbcount"))
		return;

	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts.args;

	cout << "[rgat]Starting test using command line [" << runpath << "]" << endl;
	boost::process::spawn(runpath);
}

void execute_pin_compatibility_test(void *binaryTargetPtr, clientConfig &config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	string runpath;
	if (!get_bbcount_path(config, target->launchopts, runpath, (target->getBitWidth() == 64), "bbcount"))
		return;

	runpath = runpath + " -- \"" + target->path().string() + "\" " + target->launchopts.args;

	cout << "[rgat]Starting test using command line [" << runpath << "]" << endl;
	boost::process::spawn(runpath);
}