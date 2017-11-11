#include "fuzz_spawner.h"

#define PIDSTRING_BUFSIZE MAX_PATH + 100

//pin not connecting to named pipes, have to use sockets for now


void launch_target_fuzzing_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState)
{
	//spawns trace threads + handles module data for process
	shrike_module_handler *tPIDThread = new shrike_module_handler(target, runRecord, L"shrikeMod");

	SHRIKE_THREADS_STRUCT *processThreads = new SHRIKE_THREADS_STRUCT;
	runRecord->processThreads = processThreads;

	std::thread modthread(&shrike_module_handler::ThreadEntry, tPIDThread);
	modthread.detach();
	processThreads->modThread = tPIDThread;
	processThreads->threads.push_back(tPIDThread);

	//handles new disassembly data
	shrike_basicblock_handler *tBBHandler = new shrike_basicblock_handler(target, runRecord, L"shrikeBB");

	std::thread bbthread(&shrike_basicblock_handler::ThreadEntry, tBBHandler);
	bbthread.detach();
	processThreads->BBthread = tBBHandler;
	processThreads->threads.push_back(tBBHandler);
}


//read notifications of new traces from drgat clients over the bootstrap pipe
bool read_shrike_newPID_sleepy(vector <char> *buf, HANDLE hPipe, OVERLAPPED *ov)
{


	bool conFail = ConnectNamedPipe(hPipe, ov);
	if (conFail)
	{
		cerr << "[rgat-shrike]Warning! Bootstrap connection error" << endl;
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
	buf->resize(PIDSTRING_BUFSIZE - 1, 0);
	DWORD bread = 0;
	bool success = ReadFile(hPipe, &buf->at(0), (DWORD)buf->size(), &bread, NULL);
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

//read notifications of new traces from drgat clients over the bootstrap socket
bool read_shrike_newPID_socket(vector <char> *buf, HANDLE hPipe, OVERLAPPED *ov)
{

	bool conFail = ConnectNamedPipe(hPipe, ov);
	if (conFail)
	{
		cerr << "[rgat-shrike]Warning! Bootstrap connection error" << endl;
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
	buf->resize(PIDSTRING_BUFSIZE - 1, 0);
	DWORD bread = 0;
	bool success = ReadFile(hPipe, &buf->at(0), (DWORD)buf->size(), &bread, NULL);
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

void process_new_shrike_connection(rgatState *clientState, vector<SHRIKE_THREADS_STRUCT *> *threadsList, string buf)
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


		time_t timenow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		traceRecord *trace = target->createNewTrace(PID, PID_ID, timenow);
		trace->setTraceType(eTracePurpose::eFuzzer);

		clientState->fuzztarget_connected(PID_ID, trace);
		trace->notify_new_pid(PID, PID_ID, parentPID);

		container->registerChild(parentPID, trace);

		launch_target_fuzzing_threads(target, trace, clientState);

		threadsList->push_back((SHRIKE_THREADS_STRUCT *)trace->processThreads);

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

//listens for traces on the bootstrap pipe
void fuzz_spawner_listener(rgatState *clientState, vector<SHRIKE_THREADS_STRUCT *> *threadsList)
{
	
	HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\shrikeBootstrap",
			PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
			255, 65536, 65536, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat]CreateNamedPipe failed with error " << GetLastError() << endl;
		return;
	}
	else
		cerr << "[rgat]Created shrikepipe" << endl;

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	vector <char> buf;
	buf.resize(PIDSTRING_BUFSIZE, 0);
	while (!clientState->rgatIsExiting())
	{
		bool valid = read_shrike_newPID_sleepy(&buf, hPipe, &ov);
		if (valid)
			process_new_shrike_connection(clientState, threadsList, string(buf.begin(), buf.end()));
	}
}

/*
//listens for traces on the bootstrap socket
void fuzz_spawner_listener(rgatState *clientState, vector<SHRIKE_THREADS_STRUCT *> *threadsList)
{

	SOCKET sock = INVALID_SOCKET;
	int iFamily = AF_INET;
	int iType = SOCK_DGRAM;
	int iProtocol = IPPROTO_UDP;

	sock = socket(iFamily, iType, iProtocol);
	if (sock == INVALID_SOCKET)
		wprintf(L"socket function failed with error = %d\n", WSAGetLastError());
	else {
		wprintf(L"socket function succeeded\n");


	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	vector <char> buf;
	buf.resize(PIDSTRING_BUFSIZE, 0);
	while (!clientState->rgatIsExiting())
	{
		bool valid = read_shrike_newPID_socket(&buf, hPipe, sock);
		if (valid)
			process_new_shrike_connection(clientState, threadsList, &buf);
	}
}
*/

//spawns the trace handler then cleans up after it on exit
void shrike_process_coordinator(rgatState *clientState)
{

	vector<SHRIKE_THREADS_STRUCT *> threadsList;
	fuzz_spawner_listener(clientState, &threadsList);
	if (threadsList.empty()) return;

	//we get here when rgat is exiting
	//this tells all the child threads to die
	vector<SHRIKE_THREADS_STRUCT *>::iterator processIt;
	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
	{
		SHRIKE_THREADS_STRUCT *p = ((SHRIKE_THREADS_STRUCT *)*processIt);
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
		SHRIKE_THREADS_STRUCT *p = ((SHRIKE_THREADS_STRUCT *)*processIt);
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
		((SHRIKE_THREADS_STRUCT *)*processIt)->BBthread->kill();

	for (processIt = threadsList.begin(); processIt != threadsList.end(); ++processIt)
		while (((SHRIKE_THREADS_STRUCT *)*processIt)->BBthread->is_alive())
			Sleep(1);
}