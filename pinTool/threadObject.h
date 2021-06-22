#pragma once
#include "pin.H"
#include "blockdata.h"
#include <unordered_map>


#define TRACE_TAG_MARKER "j"
#define STEP_MARKER "S"
#define ARG_MARKER "A"
#define UNLINK_MARKER "U"
#define UNCHAIN_MARKER "u"
#define EXECUTECOUNT_MARKER "B"
#define REINSTRUMENTED_MARKER "R"
#define SATISFY_MARKER "s"
#define EXCEPTION_MARKER "X"
#define THREAD_END_MARKER "Z"
#define PIPE_SEP "\x01"


#define THREAD_CHARBUF_SIZE (PATH_MAX*2)
#define TAGCACHESIZE 5256

typedef std::map<ADDRINT, BLOCK_IDENTIFIER> BLOCKIDMAP;

struct ACTIVEREGION_EDGE {
	ADDRINT sourceBranch;
	ADDRINT destHead;
	unsigned long execCount;
};




class threadObject
{
public:
	threadObject(UINT64 uniqThreadID) {
		lastBlock = &dummyBID;
		lastBlock->blockID = -1;
		activeRegionCount = 0;
		blocksIndex = -1;
		uniqueThreadID = uniqThreadID;
		hasBusyBlocks = false;
		skipNextEdge = false;
		newEdgeSourceBlk = 0;
		PIN_MutexInit(&mutex);
	};

	~threadObject() {

		PIN_MutexFini(&mutex);
	}


	bool TestAndActivateBP(ADDRINT addr) {
		bool result = false;

		PIN_MutexLock(&mutex);
		auto it = std::find(pendingBreakpoints.begin(), pendingBreakpoints.end(), addr);
		if (it != pendingBreakpoints.end()) {
			pendingBreakpoints.erase(it);
			activeBreakpoints.push_back(addr);
			result = true;
		}
		PIN_MutexUnlock(&mutex);
		return result;
	}

	bool AddPendingBreakPoint(ADDRINT addr) {
		bool result = false;

		PIN_MutexLock(&mutex);
		auto it = std::find(pendingBreakpoints.begin(), pendingBreakpoints.end(), addr);
		if (it == pendingBreakpoints.end()) {
			pendingBreakpoints.push_back(addr);
			result = true;
		}
		PIN_MutexUnlock(&mutex);
		return result;
	}

	bool HasPendingBreakpoints() { return !pendingBreakpoints.empty(); }

	bool IsActiveBreakpoint(ADDRINT addr) {
		bool result = false;

		if (activeBreakpoints.empty()) return result;
		PIN_MutexLock(&mutex);
		auto it = std::find(activeBreakpoints.begin(), activeBreakpoints.end(), addr);
		if (it != activeBreakpoints.end()) {
			result = true;
		}
		PIN_MutexUnlock(&mutex);
		return result;
	}


	PIN_MUTEX mutex;

	int blocksIndex;
	ADDRINT tempPtr1, tempPtr2;
	char tmpcharbuf[THREAD_CHARBUF_SIZE];
	size_t charbufContentsLen;

	NATIVE_FD threadpipeHandle = -1;
	FILE *threadpipeFILE;

	//ADDRINT tagCache[TAGCACHESIZE];
	ADDRINT cacheStartAddress;
	ADDRINT targetAddresses[TAGCACHESIZE];
	BLOCK_IDENTIFIER blockIDCache[TAGCACHESIZE];
	//BLOCK_IDENTIFIER_COUNT blockID_counts[TAGCACHESIZE];

	char BXbuffer[TAGCACHESIZE]; //buffer unchaining data for output

	bool hasBusyBlocks;
	bool skipNextEdge;

	ADDRINT newEdgeSourceBlk;

	BLOCKDATA *lastBlock;
	BLOCK_IDENTIFIER lastBlock_expected_targID;
	std::vector<BLOCKDATA *> busyBlocks;

	bool unsatisfiedBlockIDs;
	ADDRINT unsatisfiedBlockIDAddress;
	std::map<ADDRINT, std::vector<BLOCKDATA *>> unsatisfiableBlockIDs;


	OS_THREAD_ID osthreadid;
	UINT64 uniqueThreadID;


	uint cacheRepeats;
	unsigned int tagIdx;
	unsigned int loopEnd;

	BLOCKDATA dummyBID;

	std::vector<ADDRINT> pendingBreakpoints;
	std::vector<ADDRINT> activeBreakpoints;

	ACTIVEREGION_EDGE activeRegionEdges[128];
	int activeRegionCount;


	//block activity tracker
	unsigned long activityLevel;

	bool requestTerminate = false;

private:
};

