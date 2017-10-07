#pragma once
#include "binaryTarget.h"
#include "boost\lockfree\spsc_queue.hpp"
#include <mutex>
#include <shrike\shrike_module_handler.h>
#include <shrike\shrike_basicblock_handler.h>
#include <shrike\shrike_structs.h>

void launch_target_fuzzing_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState);

class fuzzRun : base_thread
{
public:
	fuzzRun(binaryTarget *targetptr);
	~fuzzRun();

	void begin();
	void notify_new_thread(PID_TID threadID);
	void target_connected(traceRecord* trace);
	FUZZUPDATE *getUpdate();

private:
	void addUpdate(FUZZUPDATE *);
	void launch_target(boost::filesystem::path pinpath, boost::filesystem::path shrikepath);
	void main_loop();

	binaryTarget *binary;
	traceRecord *targetProcess = NULL;
	boost::lockfree::spsc_queue<FUZZUPDATE *, boost::lockfree::capacity<2048>> updateQ;
	std::mutex QMutex;
	
	vector < base_thread *> threadList;
	vector < thread_trace_reader *> readerThreadList;

	int runID;
};

