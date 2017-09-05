#include "stdafx.h"
#include "headers\binaryTarget.h"
#include "headers\traceMisc.h"
#include "headers\traceRecord.h"
#include "graphplots\plotted_graph.h"
#include <sys/types.h>  
#include <sys/stat.h>  
#include <fstream>

binaryTarget::binaryTarget(boost::filesystem::path path)
{ 
	filepath = path; 
	processdata = new PROCESS_DATA(getBitWidth());
}

binaryTarget::~binaryTarget()
{
}

eExeCheckResult binaryTarget::getTraceableStatus()
{
	if (exeType != eNotInitialised)
		return exeType;

#ifdef _WINDOWS
	DWORD theType;
	if (!GetBinaryTypeA(filepath.string().c_str(), &theType))
	{
		exeType = eNotExecutable;
		return exeType;
	}

	//todo: .NET detection

	switch (theType)
	{
	case SCS_32BIT_BINARY:
		exeType = eBinary32Bit;
		break;
	case SCS_64BIT_BINARY:
		exeType = eBinary64Bit;
		break;
	default:
		exeType = eBinaryOther;
		break;
	}
#else
	assert(false);
#endif

	return exeType;
}

//drgat tells us what bitwidth the process it is running in has
//this assigns it to the record in case we can't get the correct info from the binary
void binaryTarget::applyBitWidthHint(cs_mode bitWidth)
{
	if (bitWidth == CS_MODE_64)
	{
		exeType = eBinary64Bit;
	}
	else if (bitWidth == CS_MODE_32)
	{
		exeType = eBinary32Bit;
	}
	else
	{
		cerr << "[rgat]ERROR: Bad bitwidth passed from drgat " << endl;
		return;
	}
};


void binaryTarget::performInitialStaticAnalysis()
{
	if (initialAnalysisCompleted) return;

	filesize = boost::filesystem::file_size(filepath);

	std::ifstream filein(filepath.string(), std::ios::binary);
	int bytesToRead = min(filesize, (uintmax_t)MAGIC_BYTES_LENGTH);

	magicBytes.resize(bytesToRead, 0);
	filein.read(&magicBytes.at(0), bytesToRead);

	initialAnalysisCompleted = true;
}


traceRecord *binaryTarget::createNewTrace(PID_TID PID, int PIDID, long long timeStarted)
{
	traceRecord *trace = new traceRecord(PID, PIDID);
	traceRecords.push_back(trace);
	trace->setBinaryPtr(this);

	runRecordTimes.emplace(make_pair(timeStarted, trace));

	return trace;
}


int binaryTarget::getBitWidth()
{
	if (exeType == eNotInitialised)
		getTraceableStatus();

	switch (exeType)
	{
	case eBinary32Bit:
		return 32;
	case eBinary64Bit:
		return 64;
	default:
		return 0;
	}
}

traceRecord *binaryTarget::getFirstTrace()
{
	if (traceRecords.empty()) return NULL;
	return traceRecords.front();
}

traceRecord *binaryTarget::getTraceWithID(int ID)
{
	if (traceRecords.empty()) return NULL;

	traceRecord *result = NULL;
	binaryLock.lock();
	for (auto it = traceRecords.begin(); it != traceRecords.end(); it++)
	{
		traceRecord *trace = *it;
		if (trace->randID == ID)
		{
			result = *it;
			break;
		}
	}
	binaryLock.unlock();

	return result;
}

traceRecord *binaryTarget::getRecordWithPID(PID_TID PID, int PID_ID = 0)
{
	traceRecord *result = NULL;
	binaryLock.lock();
	for (auto it = traceRecords.begin(); it != traceRecords.end(); it++)
	{
		traceRecord *trace = *it;
		if (trace->is_process(PID, PID_ID))
		{
			result = *it;
			break;
		}
	}
	binaryLock.unlock();

	return result;
}

//create a new trace record started at time timestarted for a saved trace
//return true and the new trace if it didn't already exist, or false and the existing trace
bool binaryTarget::createTraceAtTime(traceRecord ** tracePtr, long long timeStarted, PID_TID PID, int PIDID)
{
	auto traceIt = runRecordTimes.find(timeStarted);
	if (traceIt != runRecordTimes.end())
	{
		*tracePtr = traceIt->second;
		return false;
	}
	
	*tracePtr = createNewTrace(PID, PIDID, timeStarted);
	return true;
}

