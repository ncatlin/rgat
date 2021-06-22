
/*!

a pin implementation of the drgat client
*/


//#undef _WINDOWS_H_PATH_
#include "pin.H"
//extern "C" {#include "xed-interface.h"}
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um
namespace WINDOWS {
#include "C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1A\\Include\\Windows.h"
	//#include "C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1A\\Include\\i"
};
#include "threadObject.h"
#include "utilities.h"
#include "blockdata.h"

#include "crt\include\os-apis\memory.h"
#include "crt\include\os-apis\file.h"

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <map>
#include <io.h>


#ifdef WIN32
#include "moduleload_windows.h"
#endif
/* ================================================================== */
// Global variables 
/* ================================================================== */

//declared extern in modules.h
std::vector <moduleData*> loadedModulesInfo;

moduleData* lastBBModule;

BLOCKIDMAP blockIDMap;

UINT64 uniqueBBCountIns = 0;        //number of basic blocks executed and instrumented
UINT64 uniqueBBCountNoins = 0;        //number of basic blocks executed but not instrumented

UINT64 threadCount = 0;     //total number of threads, including main thread
std::map<OS_THREAD_ID, THREADID> ThreadIDs; //map OS threadIDs to PIN thread IDs

UINT64 startTime;
std::ostream* out = &std::cerr;
static long instanceID;

unsigned long blockCounter = 0;
NATIVE_FD bbpipe, commandPipe, eventPipe;

#define BB_BUF_SIZE (1024*48)
uint8_t* basicBlockBuffer;

static  TLS_KEY tls_key = INVALID_TLS_KEY;
std::string exeModuleDir;
bool processExiting = false;

PIN_SEMAPHORE breakSem;
PIN_SEMAPHORE continueSem;
PIN_SEMAPHORE stepSem;
bool processStateBroken = false;
bool pendingSpecialInstrumentation = false;

std::map<std::string, std::string> traceOptions;

PIN_MUTEX dataMutex;


UINT64* activeThreadUniqIDs;

VOID single_step_nobranch(BLOCKDATA* blockData, ADDRINT thisAddress, ADDRINT nextAddr, THREADID threadid);
VOID single_step_conditional_branch(BLOCKDATA* blockData, ADDRINT  thisAddress, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAdderss, THREADID threadid);
VOID single_step_unconditional_branch(BLOCKDATA* blockData, ADDRINT thisAddress, ADDRINT targetBlockAddress, THREADID threadid);
VOID BreakAllThreads();
VOID ReadConfiguration();
bool ConfigValueMatches(std::string option, std::string optionValue);
VOID InstrumentNewTrace(TRACE trace, VOID* v);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobSkipSleep(KNOB_MODE_WRITEONCE, "pintool", "caffine", "0", "skip sleep calls");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<std::string> TestArgValue(KNOB_MODE_WRITEONCE, "pintool", "T", "-1", "Test Case ID");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

struct HexCharStruct
{
	unsigned char c;
	HexCharStruct(unsigned char _c) : c(_c) { }
};

inline std::ostream& operator<<(std::ostream& o, const HexCharStruct& hs)
{
	return (o << std::hex << (int)hs.c);
}

inline HexCharStruct hex(unsigned char _c)
{
	return HexCharStruct(_c);
}


std::string windowsExceptionName(INT32 excode)
{
	switch (excode)
	{
	case 0xC000008C:
		return "ARRAY BOUNDS EXCEEDED";
	case 0xC000008D:
		return "FLOATING-POINT DENORMAL OPERAND";
	case 0xC000008E:
		return "FLOATING-POINT DIVISION BY ZERO";
	case 0xC000008F:
		return "FLOATING-POINT INEXACT RESULT";
	case 0xC0000090:
		return "FLOATING-POINT INVALID OPERATION";
	case 0xC0000091:
		return "FLOATING-POINT OVERFLOW";
	case 0xC0000092:
		return "FLOATING-POINT STACK CHECK";
	case 0xC0000093:
		return "FLOATING-POINT UNDERFLOW";
	case 0xC0000094:
		return "INTEGER DIVISION BY ZERO";
	case 0xC0000095:
		return "INTEGER OVERFLOW";
	case 0xC0000096:
		return "PRIVILEGED INSTRUCTION";
	default:
		return "UNKNOWN EXCEPTION?";
	}
}

THREADID GetPINThreadID(OS_THREAD_ID tid) {
	THREADID result = NULL;
	PIN_MutexLock(&dataMutex);
	auto it = ThreadIDs.find(tid);
	if (it != ThreadIDs.end())
		result = it->second;
	PIN_MutexUnlock(&dataMutex);
	return result;
}

void RegisterThreadID(OS_THREAD_ID tid, THREADID PinID) {
	PIN_MutexLock(&dataMutex);
	ThreadIDs[tid] = PinID;
	PIN_MutexUnlock(&dataMutex);
}


void SetProcessBrokenState(bool newState)
{
	processStateBroken = newState;
	if (processStateBroken)
	{
		writeEventPipe("DBGb%d\n\n", 0);
	}
	else {
		writeEventPipe("DBGc%d\n\n", 0);
	}

}


//write to the basic block handler thread
//this is a blocking call so watch out for performance impact
void write_sync_bb(char* buf, USIZE strsize)
{

	OS_RETURN_CODE osretcd = OS_WriteFD(bbpipe, buf, &strsize);
	if (osretcd.generic_err != OS_RETURN_CODE_NO_ERROR) //fprintf truncates to internal buffer size!
	{
		printf("[pinggat]Abort called in write_sync_bb\n");
		PIN_ExitApplication(-1);
	}
	OS_FlushFD(bbpipe);
}


//benchmark to see if either is better
bool address_is_in_targets_v1(ADDRINT addr)
{
	//have to assume IMG_FindByAddress doesnt already have this optimisation. todo:benchmark
	if (lastBBModule && addr >= lastBBModule->start && addr <= lastBBModule->end)
		return lastBBModule->instrumented;

	IMG foundimage = IMG_FindByAddress(addr);
	if (IMG_Valid(foundimage))
	{
		UINT32 imgid = IMG_Id(foundimage);
		lastBBModule = loadedModulesInfo.at(imgid);
		if (lastBBModule == 0) {
			printf("Error: address 0x%lx is in valid image but has no entry in loadedModulesInfo\n", addr);
			return false;
		}
		return (lastBBModule->instrumented);
	}
	else
	{
		std::cout << "[pingat]Warning: address 0x" << std::hex << addr << " not in valid image" << std::endl;
		return false;
	}
}

bool address_is_in_targets_v2(ADDRINT addr)
{
	std::cout << "aitv2" << std::endl;
	//have to assume IMG_FindByAddress doesnt already have this optimisation. todo:benchmark
	if (lastBBModule && addr >= lastBBModule->start && addr <= lastBBModule->end)
		return lastBBModule->instrumented;
	std::cout << "locking" << std::endl;

	size_t numMods = loadedModulesInfo.size();
	std::cout << "numods " << numMods << std::endl;
	for (size_t modi = 1; modi < numMods; ++modi) //module ID's start at 1
	{
		std::cout << "modi: " << modi << std::endl;
		lastBBModule = loadedModulesInfo.at(modi);
		if (lastBBModule == NULL) continue; //shouldnt happen now

		wprintf(L"lastBBModule not null: %s\n", lastBBModule->name.c_str());

		if (addr >= lastBBModule->start && addr <= lastBBModule->end)
		{
			return lastBBModule->instrumented;
		}
		std::cout << "[pingat]addr " << addr << " not between " << lastBBModule->start << " & " << lastBBModule->end << std::endl;
	}

	//this does happen and i don't know why
	return false;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */



//magic performance number. adjust to taste
#define DEINSTRUMENTATION_LIMIT 10

/*
inline VOID process_chained_block_old(BLOCKDATA *block_data, ADDRINT target)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));


	std::cout << "unchain block 0x" << std::hex << block_data->appc << "->" << target << ", blockdata 0x" << block_data << " thread " << thread->osthreadid << std::endl;


	//thread in an area of high workload above deinstrumentation threshold
	if (thread->unchainedBlocksExist)
	{
		//this block (or its target) is new to the work area
		//rechain everything (ie: start processing it block by block)
		if ((block_data->busyCounter == 0) || (blockIDMap.count(target) == 0))
		{
			printTagCache(thread);

			std::vector<void *>::iterator unchainedIt = thread->unchainedBlocks.begin();
			for (; unchainedIt != thread->unchainedBlocks.end(); ++unchainedIt)
			{
				BLOCKDATA *chainedBlock = ((BLOCKDATA *)*unchainedIt);
				std::vector<BLOCK_IDENTIFIER>::iterator targetsIt = chainedBlock->targets->begin();


				unsigned int outputcount = 0;
				outputcount += snprintf(thread->BXbuffer, TAGCACHESIZE, EXECUTECOUNT_MARKER",%lx,%lx",chainedBlock->blockID, chainedBlock->unchainedRepeats);
				std::cout << std::hex << "Outout chainedblock 0x" << chainedBlock << " address 0x" << chainedBlock->appc << " with " << std::dec << chainedBlock->unchainedRepeats << " unchained repeats" << std::endl;
				for (; targetsIt != chainedBlock->targets->end(); ++targetsIt)
				{
					if (outputcount > TAGCACHESIZE) std::cerr << "BXbuffer overflow? output count is " << outputcount << std::endl;
					outputcount += snprintf(thread->BXbuffer + outputcount, TAGCACHESIZE - outputcount, ",%lx", *targetsIt);
				}
				fprintf(thread->threadpipeFILE, "%s\x01", thread->BXbuffer);
				fflush(thread->threadpipeFILE);

				chainedBlock->unchained = false;
				chainedBlock->busyCounter = 0;
			}
			thread->unchainedBlocks.clear();
			thread->unchainedBlocksExist = false;

			//make link between unchained nodes and new appearance
			//this also inserts current block onto graph
			fprintf(thread->threadpipeFILE, UNLINK_MARKER",%lx,%lx,%lx,%lx,%lx,%lx,%lx\x01",
				(void *)thread->lastBlock->appc,
				thread->lastBlock->blockID,
				thread->lastBlock->insCount,

				(void *)block_data->appc,
				block_data->blockID,
				block_data->insCount,

				(void *)target);

			fflush(thread->threadpipeFILE);
			thread->busyCounter = ++block_data->busyCounter;
		}

		//in an area of high workload, this block is part of it so unchain it too
		else
		{
			printTagCache(thread); //just in case

			//block_data->unchainedRepeats = 1;
			block_data->unchained = true;
			block_data->lastTarget = target;

			//debugging
			if (blockIDMap.find(target) == blockIDMap.end())
				std::cerr << "Error 342 in processblockchain" << std::endl;

			BLOCK_IDENTIFIER targBlockID = blockIDMap.find(target)->second;  //
			block_data->lastTargetID = targBlockID;
			block_data->targets->clear();
			block_data->targets->push_back(targBlockID);

			thread->unchainedBlocks.push_back((void *)block_data);
			thread->lastBlock = block_data;
			thread->lastBlock_expected_targID = targBlockID;

			//notify visualiser that this area is going to be busy and won't report back until done
			fprintf(thread->threadpipeFILE, UNCHAIN_MARKER",%lx,%lx,%lx,%lx\x01", (void *)block_data->appc, block_data->blockID, (void *)target, targBlockID);
			fflush(thread->threadpipeFILE);

		}
		return;
	}

	//area of increased activity, increase block activity counter
	if ((block_data->busyCounter == thread->busyCounter) ||
		(block_data->busyCounter == (thread->busyCounter - 1)))
	{

		//increase thread activity counter if all blocks aside from this one
		if (++block_data->busyCounter > thread->busyCounter)
			++thread->busyCounter;

		if (block_data->busyCounter >= DEINSTRUMENTATION_LIMIT)
		{
			printTagCache(thread);

			//block_data->unchainedRepeats = 1;
			block_data->unchained = true;
			block_data->lastTarget = target;

			BLOCK_IDENTIFIER targBlockID;
			BLOCKIDMAP::iterator blockIDIt = blockIDMap.find(target);
			if (blockIDIt == blockIDMap.end())
			{
				std::cout << "[pingat]@process_chained_block unsatisfied blockaddr 0x" << std::hex << target << " in thread " << PIN_GetTid() << std::endl;
				thread->unsatisfiedBlockIDs = true;
				thread->unsatisfiedBlockIDAddress = target;
				targBlockID = 0;
			}
			else
				targBlockID = blockIDIt->second;

			block_data->lastTargetID = targBlockID;
			block_data->targets->clear();
			block_data->targets->push_back(targBlockID);
			thread->unchainedBlocks.push_back(((void *)block_data));
			thread->unchainedBlocksExist = true;
			thread->lastBlock = block_data;
			thread->lastBlock_expected_targID = targBlockID;

			fprintf(thread->threadpipeFILE, UNCHAIN_MARKER",%lx,%lx,%lx,%lx\x01", (void *)block_data->appc, block_data->blockID, (void *)target, targBlockID);
			fflush(thread->threadpipeFILE);
			return;
		}
	}

	else //block busier than recent thread actvity - lower block activity to match
	{
		if (block_data->busyCounter > thread->busyCounter)
			block_data->busyCounter = thread->busyCounter;
		else
			//active block with less activity than thread - lower thread activity to match
			thread->busyCounter = ++block_data->busyCounter;
	}

	thread->lastBlock = block_data;

	unsigned int tagIdx = thread->tagIdx++;
	if (tagIdx > TAGCACHESIZE - 1)
	{
		printTagCache(thread);
		tagIdx = 0;
	}

	if (!thread->cacheRepeats)
	{
		//not in loop, record new block info in cache
		thread->blockIDCache[tagIdx] = block_data->blockID;
		thread->targetAddresses[tagIdx] = target;
		//thread->tagCache[tagIdx] = block_data->appc;
		//thread->blockID_counts[tagIdx] = block_data->blockID_numins;

		//not a back edge so no further processing
		//ideally the processing for most blocks ends here
		if ((void *)target > (void *)block_data->lastInsAddress)
			return;

		if (target == thread->cacheStartAddress)//back to start of cache
		{
			//record cache as first iteration of a loop
			thread->loopEnd = tagIdx;
			thread->cacheRepeats++;
			thread->tagIdx = 0;
		}
		else
		{
			//back to something else, dump cache
			printTagCache(thread);
		}
		return;
	}


	if (tagIdx == thread->loopEnd) //end of loop
	{
		//back to start of loop
		if (target == thread->cacheStartAddress)
		{
			//record another iteration of cache
			++thread->cacheRepeats;
			thread->tagIdx = 0;
			return;
		}

		//leaving loop. print loops up until now + progress on current loop
		--thread->tagIdx;
		printTagCache(thread);

		tagIdx = 0;
		//thread->tagCache[tagIdx] = block_data->appc;
		//thread->blockID_counts[tagIdx] = block_data->blockID_numins;
		thread->cacheStartAddress = block_data->appc;
		thread->blockIDCache[tagIdx] = block_data->blockID;
		thread->targetAddresses[tagIdx] = target;
		thread->tagIdx = 1;
		return;
	}

	//continuing in cached loop but not at end, ensure this block matches cached block
	//if ((thread->tagCache[tagIdx] != block_data->appc) || //different BB?
	//	(thread->blockID_counts[tagIdx] != block_data->blockID_numins) || //same BB start, different end?
	//	(thread->targetAddresses[tagIdx] != target)) //leaving mid loop?
	if ((thread->blockIDCache[tagIdx] != block_data->blockID) || //different BB?
		(thread->targetAddresses[tagIdx] != target))
	{
		//they don't match! print loops up til now + progress on current loop
		--thread->tagIdx;
		printTagCache(thread);

		tagIdx = 0;
		//thread->tagCache[tagIdx] = block_data->appc;
		//thread->blockID_counts[tagIdx] = block_data->blockID_numins;
		thread->cacheStartAddress = block_data->appc;
		thread->blockIDCache[tagIdx] = block_data->blockID;
		thread->targetAddresses[tagIdx] = target;
		thread->tagIdx = 1;
	}


}


VOID at_unconditional_branch_old(BLOCKDATA *block_data, ADDRINT targetBlockAddress)
{
	//std::cout << "uncond branch block 0x" << std::hex << block_data->appc << "->" << targetBlockAddress << std::endl;

	//std::cout << "uncond in thread id " << PIN_GetTid() << " appthread: " << PIN_IsApplicationThread()  << std::endl;

	if (!block_data->unchained)
	{
		process_chained_block_old(block_data, targetBlockAddress);
		return;
	}

	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));

	++block_data->unchainedRepeats;

	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		if (std::find(thread->lastBlock->targets->begin(), thread->lastBlock->targets->end(), block_data->blockID) == thread->lastBlock->targets->end())
			thread->lastBlock->targets->push_back(block_data->blockID);
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (targetBlockAddress != block_data->lastTarget)
	{
		BLOCKIDMAP::iterator blockIDit = blockIDMap.find(targetBlockAddress);
		if (blockIDit != blockIDMap.end())
		{
			std::cout << "Marking ucb unsatisfied blockid 0x" << std::hex << targetBlockAddress << " in thread " << PIN_GetTid() << std::endl;
			thread->unsatisfiedBlockIDs = true;
			thread->unsatisfiedBlockIDAddress = targetBlockAddress;
			block_data->lastTargetID = 0;
		}
		else
		{
			block_data->lastTargetID = blockIDit->second;
			if (std::find(thread->lastBlock->targets->begin(), thread->lastBlock->targets->end(), block_data->lastTargetID) == thread->lastBlock->targets->end())
				block_data->targets->push_back(block_data->lastTargetID);

		}
	}


	//update state so drgat knows which member of unchained area executed an inactive block
	thread->lastBlock = block_data;
}



//IARG_INST_PTR, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_END);
VOID at_conditional_branch_old(BLOCKDATA *block_data, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAdderss)
{

	if (!block_data->unchained)
	{
		process_chained_block_old(block_data, targetBlockAddress);
		return;
	}

	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));

	++block_data->unchainedRepeats;

	//check to see if we arrived at the expected target
	if (block_data->blockID != thread->lastBlock_expected_targID)
	{
		//nope, add a new target to previous block so it can be added to graph
		if (std::find(thread->lastBlock->targets->begin(), thread->lastBlock->targets->end(), block_data->blockID) == thread->lastBlock->targets->end())
			thread->lastBlock->targets->push_back(block_data->blockID);
		thread->lastBlock->lastTargetID = block_data->blockID;
	}

	//update state so next block can do the same check
	thread->lastBlock_expected_targID = block_data->lastTargetID;

	//check if the next target is the one block expects
	//if not then update the expected target and add it to target list
	//this avoids expensive set lookup every execution
	if (targetBlockAddress != block_data->lastTarget)
	{
		BLOCKIDMAP::iterator blockIDit = blockIDMap.find(targetBlockAddress);
		if (blockIDit != blockIDMap.end())
		{
			std::cout << "Marking cb unsatisfied blockid 0x" << std::hex << targetBlockAddress << " in thread " << PIN_GetTid() << std::endl;
			thread->unsatisfiedBlockIDs = true;
			thread->unsatisfiedBlockIDAddress = targetBlockAddress;
			block_data->lastTargetID = 0;
		}
		else
		{
			block_data->lastTargetID = blockIDit->second;
			if (std::find(block_data->targets->begin(), block_data->targets->end(), block_data->blockID) == block_data->targets->end())
				block_data->targets->push_back(block_data->lastTargetID);
		}
	}

	//update state so drgat knows which member of unchained area executed an inactive block
	thread->lastBlock = block_data;
}

*/









inline ThreadBlockInfo* GetThreadBlockInfo(threadObject* threadObj, BLOCKDATA* block_data)
{
	int threadBlocksIndex = threadObj->blocksIndex;
	ThreadBlockInfo* blockSlotCurrentThread = block_data->threadRecords[threadBlocksIndex];

	if (blockSlotCurrentThread == 0)
	{
		//this block has never seen a thread with this index, create a new object to store thread specific data for it
		block_data->threadRecords[threadBlocksIndex] = new ThreadBlockInfo(threadObj->uniqueThreadID);
		blockSlotCurrentThread = block_data->threadRecords[threadBlocksIndex];
	}
	else if (blockSlotCurrentThread->threadObjectID != threadObj->uniqueThreadID)
	{
		//repurpose the existing object from a now dead thread for this thread
		blockSlotCurrentThread->Reset(threadObj->uniqueThreadID);
	}
	return blockSlotCurrentThread;
}


VOID inline outputUnchained(threadObject* threadObj, BLOCK_IDENTIFIER finalBlock)
{
	//output all the blocks/edges that were executed in the area
	for each (BLOCKDATA * busyBlock in threadObj->busyBlocks)
	{
		int outputcount = 0;
		ThreadBlockInfo* busyBlockStats = GetThreadBlockInfo(threadObj, busyBlock);
		outputcount += snprintf(threadObj->BXbuffer + outputcount, TAGCACHESIZE - outputcount, EXECUTECOUNT_MARKER",%lx", busyBlock->blockID);
		for each (std::pair<ADDRINT, unsigned long> targCount in busyBlockStats->targets)
		{
			if (outputcount > TAGCACHESIZE) std::cerr << "BXbuffer overflow? output count is " << outputcount << std::endl;
			outputcount += snprintf(threadObj->BXbuffer + outputcount, TAGCACHESIZE - outputcount, ",%lx,%lx", targCount.first, targCount.second);
		}
		busyBlockStats->targets.clear();
		fprintf(threadObj->threadpipeFILE, "%s\x01", threadObj->BXbuffer);
	}

	
    fprintf(threadObj->threadpipeFILE, REINSTRUMENTED_MARKER",%lx\x01", threadObj->newEdgeSourceBlk);
	
	
	fflush(threadObj->threadpipeFILE);
	threadObj->busyBlocks.clear();
	threadObj->hasBusyBlocks = false;
}



/*
This adds an edge (sourceBlock->targblockAddr address) to the trace stream for this thread.

Requirements:
	1. As low CPU overhead as possible to reduce the burden on execution of every block
	2. Compressed enough output to minimise the ability of small regions of code to generate disproportionately large traces
	but
	3. Output regularly enough to make live viewing responsive (ie: don't just cache the whole trace then output at termination)

Tradeoffs to achieve this:
	* Where possible sacrifice space for time. Application memory usage is usually finite but we almost always want more speed
	* Go nuts with expensive setup operations on thread/trace creation and first block execution -
	  Slow programs are due to loops and blocking, not because of the number of unique instructions.
	* The trace can be lossy as long as rgat knows. We don't replay the exact order of block execution,
		so it's fine to say in busy areas "these {N} blocks executed for a while with edge execution counts E1:X,E2:Y,E3:Z,...".

Future improvements:
	It may be necessary to have multiple different algorithms which are used for code regions with wildly different execution profiles.

*/
inline VOID RecordEdge(threadObject* threadObj, BLOCKDATA* sourceBlock, ADDRINT targblockAddr)
{
	ThreadBlockInfo* blockStats = GetThreadBlockInfo(threadObj, sourceBlock);

	//printf("recordedge. src_%d -> targ 0x%lx blk->execs[%d] blck->act[%d] thread->act[%d]\n", sourceBlock->blockID, targblockAddr,
	//	blockStats->execCount, blockStats->activityLevel, threadObj->activityLevel);
	//PART 1: Do basic count for every block
	//record block execution and increase block activity
	blockStats->execCount += 1;
	blockStats->activityLevel += 1;

	//PART 2: update the block and thread activity levels
	if (blockStats->activityLevel != threadObj->activityLevel)
	{
		if (blockStats->activityLevel > threadObj->activityLevel) // block is more active than thread
		{
			if (blockStats->activityLevel == (threadObj->activityLevel + 1)) //thread is one behind busy blocks
			{
				//printf("__recordedge1 b>t [blkact == threadact+1] => threadact++\n");
				threadObj->activityLevel += 1; //bump thread activity level to match
			}
			else
			{
				//printf("__recordedge1 b>t [blkact != threadact+1] => blkact = threadact\n");
				blockStats->activityLevel = threadObj->activityLevel; //cool block down to thread activity level
			}
		}
		else
		{
			//printf("__recordedge1 b<t => t=b\n");
			threadObj->activityLevel = blockStats->activityLevel; //busy thread moved to a lower activity block, lower thread busy level
			if (threadObj->hasBusyBlocks && threadObj->activityLevel < DEINSTRUMENTATION_LIMIT) //did this take us out of a busy area?
			{
				//printf("____recordedge1 hasbusy+ta<LIM => oe\n");
				outputUnchained(threadObj, sourceBlock->blockID); //output everything that happened while deinstrumented
			}
		}
	}

	//PART 3: record/report this block execution
	if (threadObj->activityLevel >= DEINSTRUMENTATION_LIMIT)
	{
		if (!blockStats->targets.empty()) //this block has been seen in busy area before
		{
			int i = 0;
			for (; i < blockStats->targets.size(); i++) //find this edge in exec list and increment count
			{
				if (blockStats->targets[i].first == targblockAddr) {
					blockStats->targets[i].second += 1;
					break;
				}
			}
			if (i == blockStats->targets.size()) { //new edge
				//0 because a seperate trace tag is used to record the edge
				//printf("__recordedge2 abovelim targs new edge [0x%lx]\n",targblockAddr);
				blockStats->targets.push_back(std::make_pair(targblockAddr, 1));
				//go back to instrumented mode because we don't know if the next block has been seen yet
				//there might be some performance gains to be had by doing more logic/data storage around this - or performance losses.
				threadObj->activityLevel = blockStats->activityLevel;
				threadObj->newEdgeSourceBlk = sourceBlock->blockID;
				
			}
			else {

				//printf("__recordedge2 abovelim targs old edge [0x%lx]\n", targblockAddr);
			}
		}
		else
		{
			//printf("__recordedge2 abovelim targs first edge [0x%lx]\n", targblockAddr);
			// record the edge
			threadObj->busyBlocks.push_back(sourceBlock);
			blockStats->targets.push_back(std::make_pair(targblockAddr, 1));
			// tell rgat this block is busy 
			fprintf(threadObj->threadpipeFILE, UNCHAIN_MARKER",%lx\x01", sourceBlock->blockID);
			fflush(threadObj->threadpipeFILE);
			threadObj->newEdgeSourceBlk = sourceBlock->blockID;
			threadObj->hasBusyBlocks = true;
		}
	}
	else
	{

		//printf("__recordedge2 targs belowlim edge [0x%lx]\n", targblockAddr);
		// 
		//tell rgat about execution of this block and where the branch led to
		//todo - tag cache
		//printf("Full Instrumented Add Blockid %d \n", sourceBlock->blockID);
		fprintf(threadObj->threadpipeFILE, TRACE_TAG_MARKER"%lx,%lx\x01", sourceBlock->blockID, targblockAddr);
		fflush(threadObj->threadpipeFILE);
	}
}

VOID RecordStep(threadObject* threadObj, BLOCKDATA* block, ADDRINT thisAddress, ADDRINT nextAddress)
{
	fprintf(threadObj->threadpipeFILE, STEP_MARKER"%lx,%lx,%lx\x01", block->blockID, thisAddress, nextAddress);
	fflush(threadObj->threadpipeFILE);
}

VOID at_unconditional_branch(BLOCKDATA* block_data, ADDRINT targetBlockAddress, THREADID threadid)
{
	//std::cout << "at_unconditional_branch hit block " << block_data->blockID << std::endl;
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, targetBlockAddress);
}

VOID at_conditional_branch(BLOCKDATA* block_data, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAdderss, THREADID threadid)
{
	//std::cout << "at_conditional_branch hit block " << block_data->blockID << " address 0x"<<std::hex<<block_data->appc << std::endl;
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, taken ? targetBlockAddress : fallthroughAdderss);
}


/*
It's important that single steps are called after branch analysis functions. If the step is called first then remove_instrumentation will
wipe out the branch trace analysis func and leave a gap in the trace
*/
VOID InsertSinglestepFunc(threadObject* thread, INS ins, BLOCKDATA* block_data)
{
	if (INS_IsBranchOrCall(ins))
	{
		if (INS_HasFallThrough(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)single_step_conditional_branch, IARG_CALL_ORDER, CALL_ORDER_LAST,
				IARG_PTR, block_data, IARG_INST_PTR, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_THREAD_ID, IARG_END);
		}
		else
		{

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)single_step_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_LAST,
				IARG_PTR, block_data, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);

		}
	}
	else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)single_step_nobranch, IARG_CALL_ORDER, CALL_ORDER_LAST,
			IARG_PTR, block_data, IARG_INST_PTR, IARG_FALLTHROUGH_ADDR, IARG_THREAD_ID, IARG_END);
	}
}


/* ===================================================================== */
// Basic block instrumentation - client lock is held
/* ===================================================================== */
VOID InstrumentNewTrace(TRACE trace, VOID* v)
{
	//assume a trace can't span multiple images
	ADDRINT traceStartAddr = TRACE_Address(trace);

	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));

	if (TRACE_Address(trace) < 0x10000000)
	{
		std::cout << "New Trace Generated - 0x" << std::hex << TRACE_Address(trace) <<
			std::dec << " [" << TRACE_NumIns(trace) << " instructions, " << TRACE_NumBbl(trace) << " blocks]" << std::endl;
	}
	bool isInstrumented = address_is_in_targets_v1(traceStartAddr);

	if (!isInstrumented) { return; }

	if (thread->requestTerminate) {
		PIN_ExitThread(0);
	}

	int dbg_blockct = -1;

	bool pendingThreadBreakpoints = thread->HasPendingBreakpoints();
	bool debuggingActive = pendingThreadBreakpoints || processStateBroken;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{

		dbg_blockct++;
		++uniqueBBCountIns;

		ADDRINT blockAddress = BBL_Address(bbl);
		//std::cout << "\t TraceBlock " << std::dec << blockCounter << " generated at 0x" << std::hex << blockAddress << std::endl;
		unsigned int bufpos = 0;

		basicBlockBuffer[bufpos++] = 'B';
		memcpy(basicBlockBuffer + bufpos, (void*)&blockAddress, sizeof(ADDRINT));
		bufpos += sizeof(ADDRINT);
		basicBlockBuffer[bufpos++] = '@';
		memcpy(basicBlockBuffer + bufpos, &lastBBModule->ID, sizeof(UINT32));
		bufpos += sizeof(UINT32);
		basicBlockBuffer[bufpos++] = '@';
		basicBlockBuffer[bufpos++] = 1;
		memcpy(basicBlockBuffer + bufpos, &blockCounter, sizeof(unsigned long));
		bufpos += sizeof(UINT32);

		INS lastins = BBL_InsTail(bbl);

		BLOCKDATA* block_data = new BLOCKDATA;
		block_data->appc = blockAddress;
		block_data->blockID = blockCounter;
		block_data->insCount = BBL_NumIns(bbl);
		block_data->busyCounter = 0;
		block_data->unchained = false;
		block_data->unchainedRepeats = 0;
		block_data->lastTarget = 0;
		block_data->lastTargetID = 0;
		block_data->lastInsAddress = INS_Address(lastins);
		block_data->threadRecords = (ThreadBlockInfo**)malloc(MAXRUNNINGTHREADS * sizeof(ThreadBlockInfo*));
		blockIDMap[blockAddress] = blockCounter;


		//send opcodes off to rgat
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			basicBlockBuffer[bufpos++] = '@';
			basicBlockBuffer[bufpos++] = (uint8_t)INS_Size(ins); //15 is max
			memcpy(basicBlockBuffer + bufpos, (void*)INS_Address(ins), INS_Size(ins));
			bufpos += (unsigned int)INS_Size(ins);


			//if (INS_Address(ins) < 0x10000000)
		//	{
			//	std::cout << "\t[pingatnewTrace]Blk " << dbg_blockct << " Ins 0x" << std::hex << INS_Address(ins) << std::endl;
		//	}


			if (bufpos >= (BB_BUF_SIZE - 1))
			{
				std::cerr << "[pingat]ERROR: BB Buf overflow" << std::endl;
				PIN_ExitApplication(-1);
			}

			if (debuggingActive)
			{
				if (pendingThreadBreakpoints && thread->TestAndActivateBP(INS_Address(ins)))
				{
					std::cout << "[pingatnewTrace]placing thread BP at " << std::hex << INS_Address(ins) << std::endl;
					InsertSinglestepFunc(thread, ins, block_data);
					//hit breakpoint, going into broken mode, adorn the rest of the instructions in the block with single steps
					SetProcessBrokenState(true);
					debuggingActive = true;
				}
				else
				{
					if (processStateBroken) {
						std::cout << "[pingatnewTrace]placing SingleStep at " << std::hex << INS_Address(ins) << std::endl;
						InsertSinglestepFunc(thread, ins, block_data);
					}
				}

			}

		}


		basicBlockBuffer[bufpos] = 0;
		write_sync_bb((char*)basicBlockBuffer, bufpos);
		++blockCounter;

		if (INS_IsBranchOrCall(lastins))
		{
			if (INS_HasFallThrough(lastins))
			{
				INS_InsertCall(lastins, IPOINT_BEFORE, (AFUNPTR)at_conditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
					IARG_PTR, block_data, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_THREAD_ID, IARG_END);
			}
			else
			{

				INS_InsertCall(lastins, IPOINT_BEFORE, (AFUNPTR)at_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
					IARG_PTR, block_data, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);

			}
		}
		else if (INS_IsSyscall(lastins))
		{
			//COUNTER *pedg = Lookup(EDGE(INS_Address(ins), ADDRINT(~0), INS_NextAddress(ins), ETYPE_SYSCALL));
			//INS_InsertPredicatedCall(lastins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);
			std::cout << "syscall end" << std::endl;
		}
		else
		{
			std::cout << "WARNING: non branch/call/syscall block end at " << std::hex << block_data->lastInsAddress << std::endl;
		}
	}
}




static VOID HandleUnixContextSwitch(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom,
	CONTEXT* ctxtTo, INT32 info, VOID* v)
{
	std::stringstream ctxswitch_ss;
	ctxswitch_ss << "[pingat] Unix Context Switch from 0x" << std::hex << PIN_GetContextReg(ctxtFrom, REG_INST_PTR);

	switch (reason)
	{
	case CONTEXT_CHANGE_REASON_FATALSIGNAL:  ///< Receipt of fatal Unix signal
		std::cout << "FATALSIGNAL - Receipt of fatal Unix signal number " << std::dec << info;
		break;
	case CONTEXT_CHANGE_REASON_SIGNAL:       ///< Receipt of handled Unix signal
		std::cout << "SIGNAL - Receipt of handled Unix signal " << std::dec << info;
		break;
	case CONTEXT_CHANGE_REASON_SIGRETURN:    ///< Return from Unix signal handler
		std::cout << "SIGRETURN - Return from Unix signal handler";
		break;
	}

	ctxswitch_ss << " to 0x" << std::hex << PIN_GetContextReg(ctxtTo, REG_INST_PTR) << std::endl;
	writeEventPipe("!HandleUnixContextSwitch(): %s", ctxswitch_ss.str().c_str());
}




static VOID HandleWindowsContextSwitch(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom,
	CONTEXT* ctxtTo, INT32 info, VOID* v)
{
	std::cout << "In HandleWindowsContextSwitch" << std::endl;
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));

	std::stringstream ctxswitch_ss;
	ctxswitch_ss << "![pingat] ";

	ADDRINT srcAddress = (ctxtFrom != NULL) ? PIN_GetContextReg(ctxtFrom, REG_INST_PTR) : 0;
	std::cout << "In exception " << reason << " " << srcAddress << " " << info << std::endl;
	switch (reason)
	{
	case CONTEXT_CHANGE_REASON_APC:          ///< Receipt of Windows APC
		ctxswitch_ss << "APC - Receipt of Windows APC";
		break;
	case CONTEXT_CHANGE_REASON_EXCEPTION:    ///< Receipt of Windows exception
		ctxswitch_ss << "EXCEPTION - Receipt of windows exception code 0x" << std::hex << info << " (" << windowsExceptionName(info) << ")";
		printTagCache(threaddata);
		fprintf(threaddata->threadpipeFILE, EXCEPTION_MARKER",%lx,%lx,%lx\x01", srcAddress, info, 0);
		break;
	case CONTEXT_CHANGE_REASON_CALLBACK:      ///< Receipt of Windows call-back
		std::cout << "WINDOWS CALLBACK " << std::endl;
		ctxswitch_ss << "CALLBACK - Receipt of Windows call-back";
		break;
	}

	if (ctxtFrom)
		ctxswitch_ss << " at address 0x" << std::hex << srcAddress;
	if (ctxtTo)
	{
		ADDRINT destAddress = (ctxtTo != NULL) ? PIN_GetContextReg(ctxtTo, REG_INST_PTR) : 0;
		ctxswitch_ss << " caused context switch to address 0x" << std::hex << destAddress << std::endl;
	}
	writeEventPipe("!HandleWindowsContextSwitch(): %s", ctxswitch_ss.str().c_str());
}


/*!
* Increase counter of threads in the application.
* This function is called for every thread created by the application when it is
* about to start running (including the root thread).
*/
void AssignBlockIndex(threadObject* tdata)
{
	for (int i = 0; i < MAXRUNNINGTHREADS; i++) {
		if (activeThreadUniqIDs[i] == 0) {
			activeThreadUniqIDs[i] = tdata->uniqueThreadID;
			tdata->blocksIndex = i;
			break;
		}
	}
	if (tdata->blocksIndex < 0) {
		std::cout << "Error: No free blocks index. threadstrucs size: " << MAXRUNNINGTHREADS
			<< " Should only happen with thousands of simultaneous threads running?" << std::endl;
		PIN_ExitApplication(-1);
	}
}


/*
* @param[in]   threadIndex     ID assigned by PIN to the new thread
* @param[in]   ctxt            initial register state for the new thread
* @param[in]   flags           thread creation flags (OS specific)
* @param[in]   v               value specified by the tool in the
*                              PIN_AddThreadStartFunction function call
*/
VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v)
{
	std::cout << "in thread start " << threadIndex << std::endl;
	threadCount++;
	threadObject* tdata = new threadObject(threadCount);
	OS_GetTid(&tdata->osthreadid);
	writeEventPipe("TI@%d@", tdata->osthreadid);

	RegisterThreadID(tdata->osthreadid, threadIndex);

	AssignBlockIndex(tdata);

	char pname[1024];
	NATIVE_PID pid;
	OS_GetPid(&pid);
	snprintf_s(pname, 1024, "\\\\.\\pipe\\TR%u%ld%u", pid, instanceID, tdata->osthreadid);

	int time = 0, expiry = 6000;
	while (time < expiry)
	{
		if (tdata->threadpipeHandle == -1)
		{
			tdata->threadpipeHandle = (NATIVE_FD)WINDOWS::CreateFileA(pname,
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
				NULL);

			if (tdata->threadpipeHandle == -1 && time > 1600 && (time % 600 == 0))
			{
				std::cout << "Failing to connect to thread pipe [" << std::string(pname) << "]. Error:";
				int err = WINDOWS::GetLastError();
				if (err == 2) std::cout << " Pipe not found" << std::endl;
				else if (err == 5) std::cout << " Access Denied" << std::endl;
				else std::cout << err << std::endl;
			}
		}

		if (tdata->threadpipeHandle != -1)
		{
			std::cout << "thread pipe connected!" << std::endl;

			int fd = _open_osfhandle(tdata->threadpipeHandle, _O_APPEND);

			tdata->threadpipeFILE = fdopen(fd, "wb");


			if (!tdata->threadpipeFILE)
			{
				if (errno == EACCES)
				{
					writeEventPipe("!ERROR: Permission denied when trying to fdopen handle of %s. Error 0x%x", pname, errno);
				}
				else
				{
					writeEventPipe("!ERROR: Failed to open thread pipe. Error 0x%x", errno);
				}
				PIN_ExitProcess(1);
			}

			if (PIN_SetThreadData(tls_key, tdata, threadIndex) == FALSE)
			{
				writeEventPipe("!ERROR: PIN_SetThreadData failed");
				PIN_ExitProcess(1);
			}

			if (ConfigValueMatches("PAUSE_ON_START", "TRUE")) {
				printf("Scheduled thread %d to pause on start, removing option\n", tdata->osthreadid);
				traceOptions["PAUSE_ON_START"] = "";
				SetProcessBrokenState(true);
			}
			return;
		}

		OS_Sleep(15);
		time += 15;
	}
}

VOID ThreadEnd(THREADID threadIndex, const CONTEXT* ctxt, INT32 flags, VOID* v)
{

	std::cout << "In ThreadEnd" << std::endl;
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));


	if (threaddata->hasBusyBlocks) //did this take us out of a busy area?
	{
		outputUnchained(threaddata, 0);
	}


	//printTagCache(threaddata);

	OS_GetTid(&threaddata->osthreadid);
	writeEventPipe("TZ@%d@", threaddata->osthreadid);

	activeThreadUniqIDs[threaddata->blocksIndex] = 0;

	/*
	fprintf(threaddata->threadpipeFILE, THREAD_END_MARKER"\x01");
	fflush(threaddata->threadpipeFILE);
	OS_CloseFD(threaddata->threadpipeHandle);
	*/

	delete threaddata;
}



/*!
* Print out analysis results.
* This function is called when the application exits.
* @param[in]   code            exit code of the application
* @param[in]   v               value specified by the tool in the
*                              PIN_AddFiniFunction function call
*/
VOID process_exit_event(INT32 code, VOID* v)
{
	std::cout << "In process_exit_event" << std::endl;
	UINT64 endTime;
	OS_Time(&endTime);

	processExiting = true;

	std::cout << "===============================================" << std::endl;
	std::cout << "PINGat ended run. " << std::endl;
	std::cout << "Number of basic blocks instrumented: " << std::dec << uniqueBBCountIns << std::endl;
	std::cout << "Number of basic blocks ignored: " << std::dec << uniqueBBCountNoins << std::endl;
	std::cout << "Number of threads: " << threadCount << std::endl;
	std::cout << "Execution time: " << std::dec << ((endTime - startTime) / 1000) << " ms" << std::endl;
	std::cout << "===============================================" << std::endl;

	free(basicBlockBuffer);
	free(activeThreadUniqIDs);
	PIN_MutexFini(&dataMutex);
	PIN_SemaphoreFini(&stepSem);
	PIN_SemaphoreFini(&breakSem);
	PIN_SemaphoreFini(&continueSem);
}


std::string getAppName(int argc, char* argv[])
{
	std::string appname;
	for (int i = 0; i < argc; i++)
	{
		if (std::string(argv[i]) == "--" && i <= (argc - 1))
		{
			appname = std::string(argv[i + 1]);
			break;
		}
	}

	return appname;
}


void getSetupString(std::string programName, char* buf, int bufSize)
{
#ifdef TARGET_IA32
	int arch = 32;
#elif TARGET_IA32E
	int arch = 64;
#endif // HOSTIA32


	NATIVE_PID pid;
	OS_GetPid(&pid);
	instanceID = random();

	std::string testArgValue = TestArgValue.Value();
	long testRunID = -1;
	if (testArgValue != "-1") {
		testRunID = std::strtol(testArgValue.c_str(), NULL, 0);
		if (testRunID < 0 || testRunID >= LONG_MAX)
			testRunID = -1;
	}
	snprintf_s(buf, bufSize, "PID,%u,%d,%ld,%s,%ld", pid, arch, instanceID, programName.c_str(), testRunID);
}


DWORD connect_coordinator_pipe(std::wstring coordinatorName, NATIVE_FD& coordinatorPipe)
{
	coordinatorPipe = (NATIVE_FD)WINDOWS::CreateFileW(coordinatorName.c_str(), GENERIC_READ |  // read and write access 
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
		NULL);

	if (coordinatorPipe != -1) return 0;

	DWORD lastErr = WINDOWS::GetLastError();

	if (lastErr == ERROR_PIPE_BUSY) {
		int remaining = 10;
		do {
			coordinatorPipe = (NATIVE_FD)WINDOWS::CreateFileW(coordinatorName.c_str(), GENERIC_READ |  // read and write access 
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
				NULL);
			if (coordinatorPipe != -1) 
			{
				return 0;
			}
			DWORD lastErr = WINDOWS::GetLastError();
			PIN_Sleep(remaining);
			remaining += 30;
		} while (lastErr == ERROR_PIPE_BUSY && remaining < 2500);
	}
	return lastErr;
}

DWORD extract_pipes(std::string programname, std::string& cmdPipe, std::string& cmdResponsePipe, std::string& bbName)
{
	NATIVE_FD coordinatorPipe;
	const std::wstring coordinatorName = L"\\\\.\\pipe\\rgatCoordinator";
	DWORD lastErr = connect_coordinator_pipe(coordinatorName, coordinatorPipe);
	if (lastErr != 0)
	{
		if (lastErr == 2)
		{
			wprintf(L"%s", "[pingat]Unable to connect to rgat coordinator, is rgat running?\n");
		}
		else
		{
			wprintf(L"[pingat]Failed to connect to %S, error: 0x%x\n", coordinatorName.c_str(), lastErr);
		}
		return false;
	}

	char msg[1024];
	memset(msg, 0, sizeof(msg));
	getSetupString(programname, msg, 1024);
	USIZE count = sizeof(msg);

	OS_RETURN_CODE result = OS_WriteFD(coordinatorPipe, msg, &count);
	if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
	{
		wprintf(L"[pingat]Failed to send data to coordinator pipe %S, error: 0x%x\n", coordinatorName.c_str(), result.os_specific_err);
		return false;
	}
	else
	{
		result = OS_ReadFD(coordinatorPipe, &count, msg);
		if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
		{
			wprintf(L"[pingat]Failed to read data from coordinator pipe %S, error: 0x%x\n", coordinatorName.c_str(), result.os_specific_err);
		}
		else
		{
			wprintf(L"[pingat]Got [%d] bytes of pipe info from rgat!, msg: 0x%s\n", count, msg);
			char* marker = strtok(msg, "@");
			if (marker == NULL) return false;
			char* cmdPipeName = strtok(NULL, "@");
			if (cmdPipeName == NULL) return false;
			if (strlen(marker) < 2 || marker[0] != 'C' || marker[1] != 'M') return false;

			marker = strtok(NULL, "@");
			if (marker == NULL) return false;
			char* responsePipeName = strtok(NULL, "@");
			if (responsePipeName == NULL) return false;
			if (strlen(marker) < 2 || marker[0] != 'C' || marker[1] != 'R') return false;

			marker = strtok(NULL, "@");
			if (marker == NULL) return false;
			char* bbPipeName = strtok(NULL, "@");
			if (bbPipeName == NULL) return false;
			if (strlen(marker) < 2 || marker[0] != 'B' || marker[1] != 'B') return false;


			bbName = "\\\\.\\pipe\\" + std::string(bbPipeName);
			cmdPipe = "\\\\.\\pipe\\" + std::string(cmdPipeName);
			cmdResponsePipe = "\\\\.\\pipe\\" + std::string(responsePipeName);

			wprintf(L"[pingat]Got pipenames. Cmd: %s, Response: %s, BB: %s\n", cmdPipeName, responsePipeName, bbPipeName);

		}
	}


	return true;
}


// I can't get full duplex async named pipes to work between PIN and the .net core NamedPipeServerStream, so use seperate pipes for cmds/responses
// outgoing block (ie: disassembly) data also gets its own pipe
bool establishRGATConnection(std::string programName)
{

	std::string bbpipename, cmdpipename, eventpipename;
	if (!extract_pipes(programName, cmdpipename, eventpipename, bbpipename))
	{
		std::cout << "[pingat]Failed to establish process pipes" << std::endl;
		return false;
	}
	else
	{
		std::cout << "[pingat]Connecting to pipes " << cmdpipename << "," << eventpipename << "," << bbpipename << std::endl;
		bbpipe = -1;
		commandPipe = -1;
		eventPipe = -1;

		int time = 0;
		int expiry = 6000;
		while (time < expiry)
		{
			if (bbpipe == -1)
			{
				bbpipe = (NATIVE_FD)WINDOWS::CreateFileA(bbpipename.c_str(), GENERIC_READ |  // read and write access 
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
					NULL);

				if (bbpipe == -1 && time > 1600 & (time % 600 == 0))
				{
					std::cout << "Failing to connect to block pipe [" << bbpipename << "]. Error:";
					int err = WINDOWS::GetLastError();
					if (err == 2) std::cout << " Pipe not found" << std::endl;
					else if (err == 5) std::cout << " Access Denied" << std::endl;
					else std::cout << err << std::endl;
				}
			}

			if (eventPipe == -1)
			{
				eventPipe = (NATIVE_FD)WINDOWS::CreateFileA(eventpipename.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (eventPipe == -1 && time > 1500)
				{
					std::cout << "[pingat]Failing to connect to event pipe [" << eventpipename << "]. Error:";
					int err = WINDOWS::GetLastError();
					if (err == 2) std::cout << " Pipe not found" << std::endl;
					else if (err == 5) std::cout << " Access Denied" << std::endl;
					else std::cout << err << std::endl;
				}
			}

			if (commandPipe == -1)
			{
				commandPipe = (NATIVE_FD)WINDOWS::CreateFileA(cmdpipename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (commandPipe == -1 && time > 1500)
				{
					std::cout << "Failing to connect to commandPipe [" << cmdpipename << "]. Error:";
					int err = WINDOWS::GetLastError();
					if (err == 2) std::cout << " Pipe not found" << std::endl;
					else if (err == 5) std::cout << " Access Denied" << std::endl;
					else std::cout << err << std::endl;
				}
			}



			if (bbpipe != -1 && eventPipe != -1 && commandPipe != -1) break;
			OS_Sleep(200);
			time += 200;
		}
		if (commandPipe != -1 && eventPipe != -1)
		{
			setCommandPipe(commandPipe);
			setEventPipe(eventPipe);
			std::cout << "Connected to rgat! " << std::endl;
			return true;
		}
		else
		{
			std::cout << "Failed to connect to both pipes " << std::endl;
			return false;
		}
	}
	return false;
}


EXCEPT_HANDLING_RESULT pingat_exception_handler(THREADID threadIndex, EXCEPTION_INFO* pExceptInfo,
	PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
	std::cout << "IN PINGAT EXCEPTION " << PIN_ExceptionToString(pExceptInfo).c_str() << std::endl;
	writeEventPipe("!PINGAT FATAL ERROR: %s\n", PIN_ExceptionToString(pExceptInfo).c_str());
	//std::cout << "! [Pingat: Caught exception. " << PIN_ExceptionToString(pExceptInfo) << "] !" << std::endl << flush;
	return EHR_UNHANDLED;
}


void OutputAllThreads()
{
	for (int i = 0; i < MAXRUNNINGTHREADS; i++) {
		if (activeThreadUniqIDs[i] == 0) {
			UINT64 threadID = activeThreadUniqIDs[i];
			threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadID));
			if (threadObj->hasBusyBlocks) //did this take us out of a busy area?
			{
				outputUnchained(threadObj, 0);
			}
		}
	}
}


/*
bool GetStoppedPINThreadID(DWORD OSTID, THREADID& result)
{
	UINT32 count = PIN_GetStoppedThreadCount();
	for (UINT32 i = 0; i < count; i++)
	{
		THREADID threadID = PIN_GetStoppedThreadId(i);
		threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadID));
		if (threadObj != NULL && threadObj->osthreadid == OSTID) {
			result = threadID;
			const CONTEXT* ctx = PIN_GetStoppedThreadContext(threadID);
			std::cout << "Thread " << threadID << "\\" << OSTID << " stopped at 0x" << std::hex << PIN_GetContextReg(ctx, LEVEL_BASE::REG_INST_PTR) << std::endl;
			return true;
		}
	}
	std::cout << "!!!!!!!\n!!!!!!!!ERROR - Thread " << OSTID << " not in stopped threads N!!!!!!!!!!!!!\n\n" << std::endl;
	return false;
}
*/



VOID single_step_nobranch(BLOCKDATA* block, ADDRINT thisAddress, ADDRINT nextAddr, THREADID threadid)
{
	threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	bool isBP = threadObj->IsActiveBreakpoint(thisAddress);
	if (processStateBroken || isBP)
	{
		RecordStep(threadObj, block, thisAddress, nextAddr);
		if (isBP)
		{
			std::cout << "\n----\n----" << "Hit thread breakpoint at 0x" << std::hex << thisAddress << " (nobranch). Next addr: 0x" << nextAddr << "\n----\n----" << std::endl;
			SetProcessBrokenState(true);
		}
		else
		{
			std::cout << "\n----\n----" << "Single Stepped to  0x" << std::hex << thisAddress << " (nobranch). Next addr: 0x" << nextAddr << "\n----\n----" << std::endl;
		}

		PIN_SemaphoreWait(&stepSem);
		PIN_SemaphoreClear(&stepSem);
	}
	else
	{
		PIN_RemoveInstrumentationInRange(thisAddress, thisAddress);
	}

}




VOID single_step_conditional_branch(BLOCKDATA* block, ADDRINT thisAddress, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAddress, THREADID threadid)
{
	threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	bool isBP = threadObj->IsActiveBreakpoint(thisAddress);

	if (processStateBroken || isBP)
	{
		RecordStep(threadObj, block, thisAddress, taken ? targetBlockAddress : fallthroughAddress);
		if (isBP)
		{
			std::cout << "\n----\n----" << "Hit thread breakpoint at 0x" << std::hex << thisAddress <<
				" (conditional). Next addr: 0x" << (taken ? targetBlockAddress : fallthroughAddress) << "\n----\n----" << std::endl;

			SetProcessBrokenState(true);
		}
		else
		{
			std::cout << "\n----\n----" << "Single Stepped to  0x" << std::hex << thisAddress <<
				" (conditional). Next addr: 0x" << (taken ? targetBlockAddress : fallthroughAddress) << "\n----\n----" << std::endl;
		}


		PIN_SemaphoreWait(&stepSem);
		PIN_SemaphoreClear(&stepSem);
	}
	else
	{
		PIN_RemoveInstrumentationInRange(thisAddress, thisAddress);
	}
}


VOID single_step_unconditional_branch(BLOCKDATA* block, ADDRINT thisAddress, ADDRINT targetBlockAddress, THREADID threadid)
{
	threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	bool isBP = threadObj->IsActiveBreakpoint(thisAddress);

	if (processStateBroken || isBP)
	{
		RecordStep(threadObj, block, thisAddress, targetBlockAddress);
		if (isBP)
		{
			std::cout << "\n----\n----" << "Hit thread breakpoint at 0x" << std::hex << thisAddress << " (uncond). Next addr: 0x" << targetBlockAddress << "\n----\n----" << std::endl;

			SetProcessBrokenState(true);
		}
		else
		{
			std::cout << "\n----\n----" << "Single Stepped to  0x" << std::hex << thisAddress << " (uncond). Next addr: 0x" << targetBlockAddress << "\n----\n----" << std::endl;
		}

		PIN_SemaphoreWait(&stepSem);
		PIN_SemaphoreClear(&stepSem);
	}
	else {
		PIN_RemoveInstrumentationInRange(thisAddress, thisAddress);
	}
}


void BreakAllThreads()
{
	PIN_SemaphoreSet(&breakSem);
	PIN_Sleep(50);	//sleep long enough for the breakerthread to catch this
}


void ResumeAllThreads()
{
	PIN_SemaphoreSet(&continueSem);
	PIN_Sleep(50);	//sleep long enough for the breakerthread to catch this
}


void ProcessControlCommand(std::string cmd)
{
	std::cout << " ------\nControl command: " << cmd << "\n-----------\n" << std::endl;

	if (cmd.compare(0, 4, "EXIT") == 0) {
		std::cout << "[pingat]Exiting due to exit command" << std::endl;
		BreakAllThreads();
		OutputAllThreads();
		PIN_ExitProcess(0);
	}
	else if (cmd.compare(0, 4, "KILL") == 0) {
		DWORD OSthreadID = std::atol(cmd.substr(5, cmd.length()).c_str());
		THREADID pinThreadID = GetPINThreadID(OSthreadID);
		threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, pinThreadID));
		std::cout << "exiting thread " << std::dec << OSthreadID << std::endl;

		BreakAllThreads();
		OutputAllThreads();
		PIN_RemoveInstrumentation();
		threadObj->requestTerminate = true;
		ResumeAllThreads();

		//won't work, causes caller to execute
		//OS_RETURN_CODE ret1 = OS_ExitThread(OSthreadID);

	}
	else if (cmd.compare(0, 3, "BRK") == 0) {
		std::cout << "b1" << std::endl;
		if (processStateBroken == false) {
			std::cout << "[pingat]Pausing application threads" << std::endl;
			PIN_SemaphoreClear(&stepSem);
			BreakAllThreads();
			OutputAllThreads();
			SetProcessBrokenState(true);
		}
	}
	else if (cmd.compare(0, 3, "CTU") == 0) {
		if (processStateBroken) {
			SetProcessBrokenState(false);
			PIN_SemaphoreSet(&stepSem);
			std::cout << "[pingat]Resuming application threads" << std::endl;
			ResumeAllThreads();
		}
	}
	else if (cmd.compare(0, 3, "SIN") == 0) {
		if (processStateBroken) {
			DWORD OSthreadID = std::atol(cmd.substr(4, cmd.length()).c_str());
			std::cout << "[pingat]Stepping to next instruction of thread " << OSthreadID << std::endl;
			THREADID pinThreadID;
			PIN_SemaphoreSet(&stepSem);
		}
	}
	else if (cmd.compare(0, 4, "SOV,") == 0) {
		//remove all BPs, set a breakpoint at next instruction, continue
		if (processStateBroken) {
			int atPos = cmd.find('@');
			DWORD OSthreadID = std::atol(cmd.substr(atPos, cmd.length()).c_str());
			ADDRINT targAddr = std::strtol(cmd.substr(4, atPos).c_str(), NULL, 16);
			std::cout << "[pingat]Breaking at instruction 0x" << std::hex << targAddr << " of thread " << OSthreadID << std::endl;
			THREADID pinThreadID = GetPINThreadID(OSthreadID);
			threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, pinThreadID));
			threadObj->AddPendingBreakPoint(targAddr);
			PIN_RemoveInstrumentation();
			SetProcessBrokenState(false);
			PIN_SemaphoreSet(&stepSem);
		}
	}
	else {
		std::cout << "[pingat]!Unhandled control command: " << cmd << std::endl;
	}

}



static VOID ControlPipeReader(VOID* arg)
{
	char* outBuf = (char*)malloc(4096);
	USIZE readSize;
	while (true)
	{
		readSize = 4096;
		OS_RETURN_CODE ret = readCommandPipe(outBuf, &readSize);
		if (ret.generic_err == OS_RETURN_CODE_NO_ERROR)
		{
			if (readSize == 0) continue;
			std::string msg = std::string(outBuf);
			ProcessControlCommand(msg);
			memset(outBuf, 0, readSize);
		}
		else
		{
			std::cerr << "[pingat]ControlPipeReader() ERROR " << ret.generic_err << " -> " << ret.os_specific_err << std::endl;
			if (processExiting) return;
		}
	}
	free(outBuf);
}


//threads can't pause themselves with PIN_StopApplicationThreads, so we have to do it from an internal thread
static VOID BreakerThread(VOID* arg)
{
	int count = 0;

	THREADID thisThreadID = PIN_ThreadId();
	while (!processExiting) {
		count += 1;
		if (PIN_SemaphoreTimedWait(&breakSem, 500)) {
			std::cout << "Break semaphore set" << std::endl;
			PIN_SemaphoreClear(&breakSem);
			PIN_StopApplicationThreads(thisThreadID);
			SetProcessBrokenState(true);

			while (!processExiting) {
				if (PIN_SemaphoreTimedWait(&continueSem, 500)) {
					std::cout << "continueSem semaphore set" << std::endl;
					SetProcessBrokenState(false);
					PIN_SemaphoreClear(&continueSem);
					PIN_ResumeApplicationThreads(thisThreadID);
					break;
				}
			}
		}
	}
}


VOID GetConfigurationKeys(int count)
{
	const int maxEntrySize = 4096;
	char* recvBuf = (char*)malloc(maxEntrySize);
	USIZE readsz;

	for (int i = 0; i < count; i++)
	{
		readsz = 1024;
		readCommandPipe(recvBuf, &readsz);
		const char delim[] = "@";
		char* entryDtaPtr = (char*)recvBuf;
		strtok(entryDtaPtr, delim);
		char* key = strtok(NULL, delim);
		char* val = strtok(NULL, delim);

		traceOptions[std::string(key)] = std::string(val);
	}

}

VOID SetupConfigItems()
{
	if (traceOptions.empty()) return;

	if (ConfigValueMatches("PAUSE_ON_START", "TRUE")) {
		pendingSpecialInstrumentation = true;
	}
}

VOID ReadConfiguration()
{
	char recvBuf[100];
	USIZE readsz = 100;
	readCommandPipe(recvBuf, &readsz);
	const char startToken[] = "INCLUDELISTS";
	if (strncmp(recvBuf, startToken, sizeof(startToken) - 1) != 0) {
		std::cout << "Got: '" << recvBuf << "' size " << readsz << ", expected: " << startToken << " size (" << sizeof(startToken) << ")" << std::endl;

		DeclareTerribleEventAndExit(L"[pingat]Bad include list start token");
		return;
	}
	getModuleIncludeLists();

	readsz = 100;
	readCommandPipe(recvBuf, &readsz);
	const char startToken2[] = "CONFIGKEYS@";
	if (strncmp(recvBuf, startToken2, sizeof(startToken2) - 1) != 0) {
		printf("Err: %s\n", recvBuf);
		DeclareTerribleEventAndExit(L"[pingat]Bad config keys start token");
		return;
	}

	char* startchar = strtok(recvBuf, "@");
	int keyCount = atoi(strtok(NULL, "@"));
	if (keyCount >= 0 && keyCount <= 1024)
		GetConfigurationKeys(keyCount);

	SetupConfigItems();
}


bool GetConfigValue(std::string option, std::string& result)
{
	auto it = traceOptions.find(option);
	if (it == traceOptions.end()) return false;
	result = it->second;
	return true;
}

bool ConfigValueMatches(std::string option, std::string optionValue)
{
	std::string result;
	return (GetConfigValue(option, result) && result == optionValue);
}



//TODO - use this
//TRACE_AddSmcDetectedFunction

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/
int main(int argc, char* argv[])
{

	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
	{
		std::cerr << "[pingat] Error: PIN_Init failed. Bad command line." << std::endl;
		return -1;
	}

	PIN_AddInternalExceptionHandler(pingat_exception_handler, 0);
	PIN_SemaphoreInit(&breakSem);
	PIN_SemaphoreInit(&continueSem);
	PIN_SemaphoreInit(&stepSem);
	PIN_MutexInit(&dataMutex);

	OS_Time(&startTime);

	activeThreadUniqIDs = (UINT64*)malloc(MAXRUNNINGTHREADS * sizeof(UINT64));
	for (int i = 0; i < MAXRUNNINGTHREADS; i++) { activeThreadUniqIDs[i] = 0; }

	// Obtain  a key for TLS storage.
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY)
	{
		std::cout << "!PINGAT FATAL ERROR: number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << std::endl;
		PIN_ExitProcess(1);
	}


	PIN_InitSymbols();
	basicBlockBuffer = (uint8_t*)malloc(BB_BUF_SIZE);

	std::string programName = getAppName(argc, argv);
	if (programName.empty())
	{
		std::cerr << "Error: No app argument [-- app_path]" << std::endl;
		PIN_ExitProcess(1);
	}

	//TraceChoiceFileList.push_back(programName); for default ignore mode
	if (!establishRGATConnection(programName))
	{
		std::cerr << "Failed to establish connection to rgat" << std::endl;
		PIN_ExitProcess(1);
	}

	std::cout << "Connection established to rgat. Fetching trace settings" << std::endl;

	ReadConfiguration();


	// Register function to be called to instrument traces

	TRACE_AddInstrumentFunction(InstrumentNewTrace, 0);

	IMG_AddInstrumentFunction(moduleLoad, (void*)tls_key);

	// Register function to be called for every thread before it starts running
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadEnd, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(process_exit_event, 0);
#ifdef WIN32
	PIN_AddContextChangeFunction(HandleWindowsContextSwitch, 0);
#elif LINUX
	PIN_AddContextChangeFunction(HandleUnixContextSwitch, 0);
#endif

	loadedModulesInfo.resize(40, (moduleData*)NULL);
	lastBBModule = loadedModulesInfo[0] = new moduleData;
	lastBBModule->instrumented = 0;
	lastBBModule->start = 0;
	lastBBModule->end = 0;

	PIN_SpawnInternalThread(ControlPipeReader, NULL, 4096, NULL);
	PIN_SpawnInternalThread(BreakerThread, NULL, 4096, NULL);

	std::cout << "Calling PIN_StartProgram()" << std::endl;


	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */