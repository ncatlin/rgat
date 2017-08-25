/*
Copyright 2017 Nia Catlin

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
Container for a binary target. Contains all traces gathered for the target in a session
*/
#pragma once

#include <boost\filesystem.hpp>
#include "traceStructs.h"
#include "traceRecord.h"
#include "clientConfig.h"
#include "osSpecific.h"
#include "locks.h"

#define MAGIC_BYTES_LENGTH 4



class binaryTarget
{
public:
	binaryTarget(boost::filesystem::path path);
	~binaryTarget();

	void performInitialStaticAnalysis();
	boost::filesystem::path path() { return filepath; }
	LAUNCHOPTIONS launchopts;
	eExeCheckResult getTraceableStatus();
	traceRecord *createNewTrace(PID_TID PID, int PIDID, long long timeStarted);
	traceRecord *getFirstTrace();
	list<traceRecord *> *getTraceListPtr(){return &traceRecords;}
	list<traceRecord *> getTraceList() { return traceRecords; }

	bool createTraceAtTime(traceRecord ** tracePtr, long long timeStarted, PID_TID PID, int PIDID);
	traceRecord *getRecordWithPID(PID_TID PID, int PID_ID);
	void applyBitWidthHint(cs_mode bitWidth);
	int getBitWidth();
	size_t traceCount() { return traceRecords.size(); }

private:
	rgatlocks::UntestableLock binaryLock;

	bool initialAnalysisCompleted = false;

	boost::filesystem::path filepath;

	uintmax_t filesize;
	vector<char> magicBytes;
	eExeCheckResult exeType = eNotInitialised;

	list<traceRecord *> traceRecords;
	map <long long, traceRecord *> runRecordTimes;
	traceRecord *activeTrace = NULL;
};

