#pragma once
#include "pin.H"

typedef unsigned long BLOCK_IDENTIFIER;
typedef unsigned long long BLOCK_IDENTIFIER_COUNT;
#define MAXRUNNINGTHREADS 1024

class ThreadBlockInfo
{
public:
	ThreadBlockInfo(UINT64 threadUID) {
		Reset(threadUID);
	}
	void Reset(UINT64 threadUID) {
		execCount = 0;
		activityLevel = -1;
		threadObjectID = threadUID;
	}
	UINT64 threadObjectID;
	std::vector <std::pair<ADDRINT, unsigned long>> targets;
	unsigned long execCount;
	int activityLevel;
	unsigned long resetSession;
};


struct BLOCKDATA {
	//constant block metadata
	uint numInstructions;
	ADDRINT appc;
	ADDRINT fallthrough;
	int insCount;
	BLOCK_IDENTIFIER blockID;

	//block metadata specific to each thread
	//calling dr with -thread_private is essential because of this
	ADDRINT lastTarget, lastInsAddress;
	BLOCK_IDENTIFIER lastTargetID;
	//std::vector<BLOCK_IDENTIFIER> *targets;
	unsigned long busyCounter;
	bool unchained;
	bool repexec;
	unsigned long unchainedRepeats;
	ThreadBlockInfo ** threadRecords;
	unsigned int allocatedThreadRecords;
};

