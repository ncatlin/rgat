/*
a pin implementation of the drgat client
*/

//#undef _WINDOWS_H_PATH_
#include "pin.H"
//extern "C" {#include "xed-interface.h"}
#include "windows_include.h"
#include "threadObject.h"
#include "utilities.h"
#include "blockdata.h"
#include "instlib.H"

#include "crt\include\os-apis\memory.h"
#include "crt\include\os-apis\file.h"

#include <io.h>
#include <iostream>
#include <string>

#define RGAT_VERSION "0.6.2"

#ifdef WIN32
#include "moduleload_windows.h"
#endif
/* ================================================================== */
// Global variables 
/* ================================================================== */

//magic performance number. adjust to taste
//This many tags will be sent per block before it is pseudo-deinstrumented
#define DEINSTRUMENTATION_LIMIT 10

//declared extern in modules.h
std::vector <moduleData*> loadedModulesInfo;
std::map <ADDRINT, regionData*> loadedRegionInfo;

//Optimisations to reduce the time spent checking if code should be instrumented or not
moduleData* lastBBModule = 0;
regionData* lastNonImgRegion = 0;

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
bool singleShotInstrumentation = false;

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

KNOB<std::string> TestArgValue(KNOB_MODE_WRITEONCE, "pintool", "T", "-1", "Test case ID");

KNOB<std::string> PipeNameValue(KNOB_MODE_WRITEONCE, "pintool", "P", "change_me", "rgat coordinator pipe name");

KNOB<bool> LibraryFlag(KNOB_MODE_WRITEONCE, "pintool", "L", "0", "library tracing flag");

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
		printf("[pingat]Abort called in write_sync_bb\n");
		PIN_ExitApplication(-1);
	}
	OS_FlushFD(bbpipe);
}


//benchmark to see if either is better
bool address_is_in_targets_v1(ADDRINT addr)
{
	//if this address is in the range of the last module we looked at, return same result
	//have to assume IMG_FindByAddress doesnt already have this optimisation. todo:benchmark
	if (lastBBModule && addr >= lastBBModule->start && addr <= lastBBModule->end)
	{
		lastNonImgRegion = 0;
		return lastBBModule->instrumented;
	}

	//if this address is in the range of the last non-image region we looked at, return same result
	if (lastNonImgRegion &&
		(addr >= (ADDRINT)lastNonImgRegion->start && addr < ((ADDRINT)lastNonImgRegion->end)))
	{
		lastBBModule = 0;
		return lastNonImgRegion->instrumented;
	}

	IMG foundimage = IMG_FindByAddress(addr);
	if (IMG_Valid(foundimage))
	{
		//Address is in executable mapped memory, return if we are interested in it
		UINT32 imgid = IMG_Id(foundimage);
		lastBBModule = loadedModulesInfo.at(imgid);

		if (lastBBModule == 0) {
			writeEventPipe("! Error: address 0x%lx is in valid image but has no entry in loadedModulesInfo\n", addr);
			return false;
		}

		return (lastBBModule->instrumented);
	}


	//Address is not in an image region
	NATIVE_PID pid;
	OS_GetPid(&pid);
	OS_MEMORY_AT_ADDR_INFORMATION info;
	if (OS_QueryMemory(pid, (void*)addr, &info).generic_err == OS_RETURN_CODE_NO_ERROR)
	{
		//If we have looked at this region before, return previous verdict
		auto regionIt = loadedRegionInfo.find((ADDRINT)info.BaseAddress);
		if (regionIt != loadedRegionInfo.end())
		{
			lastNonImgRegion = regionIt->second;
			return lastNonImgRegion->instrumented;
		}
		else
		{
			//new memory region, record it
			regionData* r = new regionData();
			r->start = (ADDRINT)info.BaseAddress;
			r->end = (ADDRINT)info.BaseAddress + info.MapSize;
			/*
			* TODO
			This bit is dubious.We want to look at this memory if execution came from an instrumented area.
			What this *actually* does is test if the last analyzed code was from an instrumented area
			Fix:       pass thread object to this function and, uh - figure it out
			Next step: create a multi-threaded test case that breaks
			*/
			if (lastBBModule == 0 && lastNonImgRegion != 0)
			{
				r->instrumented = lastNonImgRegion->instrumented;
			}
			else if (lastBBModule != 0 && lastNonImgRegion == 0)
			{
				r->instrumented = lastBBModule->instrumented;
			}
			else
			{
				return true; //??
			}
			loadedRegionInfo[r->start] = r; //todo - size limit, better data structure (something with binary search)
			writeEventPipe("XMEM@" PTR_prefix "@" PTR_prefix "@%d", r->start, r->end, r->instrumented);
			lastNonImgRegion = r;
			return r->instrumented;
		}
	}
	writeEventPipe("! Warning: address 0x%lx not in valid image [%d] and mem query failed", addr, lastBBModule->instrumented);
	return false;

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
			outputcount += snprintf(threadObj->BXbuffer + outputcount, TAGCACHESIZE - outputcount, "," PTR_prefix ",%lx", targCount.first, targCount.second);
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
	3. Output regularly enough to make live viewing responsive (ie: don't just cache the whole trace then
	output at termination). Low priority: The UI can just poll for this.

Tradeoffs to achieve this:
	* Where possible sacrifice space for time. Application memory usage is usually finite but we almost always want more speed
	* Go nuts with expensive setup operations on thread/trace creation and first block execution -
	  Slow programs are due to loops and blocking, not because of the number of unique instructions.
	* The trace can be lossy as long as rgat knows. We don't replay the exact order of block execution,
		so it's fine to say in busy areas "these {N} blocks executed for a while with edge execution counts E1:X,E2:Y,E3:Z,..."
		without preserving the exact order.

Future improvements:
	It may be necessary to have multiple different algorithms which are used for code regions with wildly different execution profiles.

*/
inline VOID RecordEdge(threadObject* threadObj, BLOCKDATA* sourceBlock, ADDRINT targblockAddr)
{
	ThreadBlockInfo* blockStats = GetThreadBlockInfo(threadObj, sourceBlock);
	threadObj->lastBlock = sourceBlock;

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
			if (blockStats->activityLevel == (threadObj->activityLevel + 1)) //if thread is 1 level behind busy blocks
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
			if (threadObj->hasBusyBlocks && threadObj->activityLevel < DEINSTRUMENTATION_LIMIT) //if this block took the thread out of a busy area
			{
				//printf("____recordedge1 hasbusy+ta<LIM => oe\n");
				outputUnchained(threadObj, sourceBlock->blockID); //output everything that happened while deinstrumented
			}
		}
	}


	//PART 3: record/report that this block execution
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
			/*
			else {
				printf("__recordedge2 abovelim targs old edge [0x%lx]\n", targblockAddr);
			}
			*/
		}
		else
		{
			//printf("__recordedge2 abovelim targs first edge [0x%lx]\n", targblockAddr);
			// record the edge
			threadObj->busyBlocks.push_back(sourceBlock);
			blockStats->targets.push_back(std::make_pair(targblockAddr, 1));
			// tell rgat this block has become busy 
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

		fprintf(threadObj->threadpipeFILE, TRACE_TAG_MARKER"%lx," PTR_prefix "\x01", sourceBlock->blockID, targblockAddr);
		fflush(threadObj->threadpipeFILE);
	}
}


VOID RecordStep(threadObject* threadObj, BLOCKDATA* block, ADDRINT thisAddress, ADDRINT nextAddress)
{
	fprintf(threadObj->threadpipeFILE, STEP_MARKER"%lx," PTR_prefix "," PTR_prefix "\x01", block->blockID, thisAddress, nextAddress);
	fflush(threadObj->threadpipeFILE);
}


VOID at_unconditional_branch(BLOCKDATA* block_data, ADDRINT targetBlockAddress, THREADID threadid)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, targetBlockAddress);
}


VOID at_unconditional_branch_oneshot(BLOCKDATA* block_data, ADDRINT targetBlockAddress, THREADID threadid)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, targetBlockAddress);
	PIN_RemoveInstrumentationInRange(block_data->appc, block_data->appc);
}


VOID at_conditional_branch(BLOCKDATA* block_data, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAddress, THREADID threadid)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, taken ? targetBlockAddress : fallthroughAddress);
}


VOID at_conditional_branch_oneshot(BLOCKDATA* block_data, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAddress, THREADID threadid)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, taken ? targetBlockAddress : fallthroughAddress);
	PIN_RemoveInstrumentationInRange(block_data->appc, block_data->appc);
}


VOID at_non_branch_oneshot(BLOCKDATA* block_data, ADDRINT nextIns, THREADID threadid)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, nextIns);
	PIN_RemoveInstrumentationInRange(block_data->appc, block_data->appc);
}




ADDRINT at_first_rep(BLOCKDATA* block_data, bool isFirst, bool isExec, ADDRINT nextIns, THREADID threadid)
{
	threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	if (isFirst && isExec && !block_data->repexec)
	{
		block_data->repexec = true;
		fprintf(threadObj->threadpipeFILE, REP_EXEC_MARKER",%lx\x01", block_data->blockID);
		fflush(threadObj->threadpipeFILE);
	}

	RecordEdge(threadObj, block_data, nextIns);
	return true;
}



ADDRINT at_first_rep_oneshot(BLOCKDATA* block_data, bool isFirst, bool isExec, ADDRINT nextIns, THREADID threadid)
{
	threadObject* threadObj = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	if (isFirst && isExec && !block_data->repexec)
	{
		block_data->repexec = true;
		fprintf(threadObj->threadpipeFILE, REP_EXEC_MARKER",%lx\x01", block_data->blockID);
		fflush(threadObj->threadpipeFILE);
	}

	RecordEdge(threadObj, block_data, nextIns);
	PIN_RemoveInstrumentationInRange(block_data->appc, block_data->appc);
	return true;
}





VOID single_ins_block(BLOCKDATA* block_data, ADDRINT afterAddress, THREADID threadid)
{

	writeEventPipe("!At single insinstruction 0x" PTR_prefix ". ", block_data->appc);// repCountBefore);

	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadid));
	RecordEdge(thread, block_data, afterAddress);
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

	/*
	if (TRACE_Address(trace) < 0x10000000)
	{
		std::cout << "New Trace Generated - 0x" << std::hex << TRACE_Address(trace) <<
			std::dec << " [" << TRACE_NumIns(trace) << " instructions, " << TRACE_NumBbl(trace) << " blocks]" << std::endl;
	}
	*/
	bool isInstrumented = address_is_in_targets_v1(traceStartAddr);

	if (!isInstrumented) {
		//std::cout << "\t uninsTraceBlock " << std::dec << blockCounter << " generated at 0x" << 
		//	std::hex << traceStartAddr << " with insct " << TRACE_NumIns(trace) << std::endl;	
		return;
	}

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
		unsigned int bufpos = 0;

		basicBlockBuffer[bufpos++] = 'B';
		memcpy(basicBlockBuffer + bufpos, (void*)&blockAddress, sizeof(ADDRINT));
		bufpos += sizeof(ADDRINT);
		basicBlockBuffer[bufpos++] = '@';
		INT32 modID = lastBBModule != 0 ? lastBBModule->ID : -1;
		memcpy(basicBlockBuffer + bufpos, &modID, sizeof(INT32));
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

		block_data->allocatedThreadRecords = 0;
		memset(block_data->threadRecords, 0, MAXRUNNINGTHREADS * sizeof(ThreadBlockInfo*)); //todo - performance improvement by getting rid of this and using allocatedThreadRecords

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
					InsertSinglestepFunc(thread, ins, block_data);
					//hit breakpoint, going into broken mode, adorn the rest of the instructions in the block with single steps
					SetProcessBrokenState(true);
					debuggingActive = true;
				}
				else
				{
					if (processStateBroken) {
						InsertSinglestepFunc(thread, ins, block_data);
					}
				}

			}

		}


		basicBlockBuffer[bufpos] = 0;
		write_sync_bb((char*)basicBlockBuffer, bufpos);
		++blockCounter;

		AFUNPTR instrumentationFunction = NULL;
		if (INS_IsBranchOrCall(lastins))
		{
			if (INS_HasFallThrough(lastins))
			{
				instrumentationFunction = !singleShotInstrumentation ? (AFUNPTR)at_conditional_branch : (AFUNPTR)at_conditional_branch_oneshot;
				INS_InsertCall(lastins, IPOINT_BEFORE, instrumentationFunction, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
					IARG_PTR, block_data, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_THREAD_ID, IARG_END);
			}
			else
			{

				instrumentationFunction = !singleShotInstrumentation ? (AFUNPTR)at_unconditional_branch : (AFUNPTR)at_unconditional_branch_oneshot;
				INS_InsertCall(lastins, IPOINT_BEFORE, (AFUNPTR)at_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
					IARG_PTR, block_data, IARG_BRANCH_TARGET_ADDR, IARG_THREAD_ID, IARG_END);

			}
		}
		else if (INS_RepPrefix(lastins) || INS_RepnePrefix(lastins))
		{
			instrumentationFunction = !singleShotInstrumentation ? (AFUNPTR)at_first_rep : (AFUNPTR)at_first_rep_oneshot;

			block_data->repexec = false;
			//https://trello.com/c/I89DMjjh/160-repxx-handling-with-ecx-0
			INS_InsertCall(lastins,
				IPOINT_AFTER,
				(AFUNPTR)at_first_rep,
				IARG_PTR, block_data,
				IARG_FIRST_REP_ITERATION,
				IARG_EXECUTING,
				IARG_ADDRINT, INS_Address(lastins) + INS_Size(lastins),
				//IARG_REG_VALUE, INS_RepCountRegister(lastins),
				IARG_THREAD_ID,
				IARG_END);
			/*
			INS_InsertCall(lastins, IPOINT_AFTER, (AFUNPTR)at_non_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
				IARG_PTR, block_data, IARG_ADDRINT, INS_Address(lastins) + INS_Size(lastins),  IARG_THREAD_ID, IARG_END);
				*/
		}
		else if (INS_IsSyscall(lastins))
		{
			std::string disas = INS_Disassemble(lastins);
			//writeEventPipe("!Error: Unhandled block end syscall instruction 0x" PTR_prefix ": %s", INS_Address(lastins), disas.c_str());
			//COUNTER *pedg = Lookup(EDGE(INS_Address(ins), ADDRINT(~0), INS_NextAddress(ins), ETYPE_SYSCALL));
			//INS_InsertPredicatedCall(lastins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);

			//error!
			//INS_InsertCall(lastins, IPOINT_ANYWHERE, (AFUNPTR)at_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
			//	IARG_PTR, block_data, IARG_ADDRINT, INS_Address(lastins) + INS_Size(lastins), IARG_THREAD_ID, IARG_END);
		}
		else if (!INS_IsBranch(lastins))
		{
			std::string disas = INS_Disassemble(lastins);
			//writeEventPipe("!Non branch block end instruction 0x" PTR_prefix ": %s", INS_Address(lastins), disas.c_str());
			if (INS_IsValidForIpointAfter(lastins))
			{
				INS_InsertCall(lastins, IPOINT_AFTER, (AFUNPTR)at_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
					IARG_PTR, block_data, IARG_ADDRINT, INS_Address(lastins) + INS_Size(lastins), IARG_THREAD_ID, IARG_END);
			}
			else 
			{
				std::cout << "NonBranch, non i point after: " << disas << std::endl;
				std::cout << "nopstate: " << INS_IsNop(lastins) << std::endl;
				std::cout << INS_IsControlFlow(lastins) << std::endl;
				std::cout << INS_IsNop(lastins) << std::endl;
				//if (!INS_)
				//{
				//	INS_InsertCall(lastins, IPOINT_ANYWHERE, (AFUNPTR)at_unconditional_branch, IARG_CALL_ORDER, CALL_ORDER_DEFAULT,
				//		IARG_PTR, block_data, IARG_ADDRINT, INS_Address(lastins) + INS_Size(lastins), IARG_THREAD_ID, IARG_END);
				//}
			}
		}
		else
		{
			std::string disas = INS_Disassemble(lastins);
			writeEventPipe("!Error: Unhandled block end instruction 0x" PTR_prefix ": %s", INS_Address(lastins), disas.c_str());
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
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));

	std::stringstream ctxswitch_ss;
	ctxswitch_ss << "![pingat] ";

	ADDRINT srcAddress = (ctxtFrom != NULL) ? PIN_GetContextReg(ctxtFrom, REG_INST_PTR) : 0;
	switch (reason)
	{
	case CONTEXT_CHANGE_REASON_APC:          ///< Receipt of Windows APC
#ifdef DEBUG
		std::cout << "[pingat]HandleWindowsContextSwitch: Exception reason " << reason << " src address 0x" << std::hex << srcAddress << " info: " << info << std::endl;
#endif
		ctxswitch_ss << "APC - Receipt of Windows APC";
		break;
	case CONTEXT_CHANGE_REASON_EXCEPTION:    ///< Receipt of Windows exception
#ifdef DEBUG
		std::cout << "[pingat]HandleWindowsContextSwitch: Exception reason " << reason << " src address 0x" << std::hex << srcAddress << " info: " << info << std::endl;
#endif
		ctxswitch_ss << "EXCEPTION - Receipt of windows exception code 0x" << std::hex << info << " (" << windowsExceptionName(info) << ")";
		printTagCache(threaddata);
		fprintf(threaddata->threadpipeFILE, EXCEPTION_MARKER"," PTR_prefix ",%lx,%lx\x01", srcAddress, info, 0); //address, code, flags
		break;
	case CONTEXT_CHANGE_REASON_CALLBACK:      ///< Receipt of Windows call-back
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
	//wprintf(L"%s", "[pingat]in thread start 32\n");
	threadCount++;
	threadObject* tdata = new threadObject(threadCount);
	OS_GetTid(&tdata->osthreadid);

	ADDRINT startAddr = PIN_GetContextReg(ctxt, REG::REG_INST_PTR);

	writeEventPipe("TI@%d@" PTR_prefix "@", tdata->osthreadid, startAddr);

	RegisterThreadID(tdata->osthreadid, threadIndex);
	AssignBlockIndex(tdata);

	char pname[1024];
	NATIVE_PID pid;
	OS_GetPid(&pid);
	snprintf_s(pname, 1024, "\\\\.\\pipe\\TR%u%ld%u", pid, instanceID, tdata->osthreadid);
#ifdef DEBUG
	cout << "[pingat]Connecting to thread pipe " << tdata->osthreadid << " " << pname << std::endl;
#endif

	int time = 0, expiry = 3000;
	while (time < expiry)
	{
		if (tdata->threadpipeHandle == -1)
		{
#ifdef DEBUG
			std::cout << "[pingat]pipe -1, doing createfile " << tdata->osthreadid << std::endl;
#endif		
			//KNOWN BUG: Sometimes blocks and never returns, probably alertable syscall

			tdata->threadpipeHandle = (NATIVE_FD)WINDOWS::CreateFileA(pname,
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

			int err = WINDOWS::GetLastError();
#ifdef DEBUG
			std::cout << "[pingat]pipe -1, after createfile err 0x" << err << "  " << tdata->osthreadid << std::endl;
#endif
			if (tdata->threadpipeHandle == -1 && time > 1600 && (time % 600 == 0))
			{
				std::cout << "[pingat]Failed to connect thread pipe after 1600 ms - err " << err << std::endl;
				std::stringstream errstr;
				errstr << "Failing to connect to thread pipe [" << std::string(pname) << "]. Error:";
				if (err == 2) errstr << " Pipe not found" << std::endl;
				else if (err == 5)errstr << " Access Denied" << std::endl;
				else errstr << err << std::endl;
				writeEventPipe("! Thread Connection Failure: %s", errstr.str().c_str());
			}
		}

		if (tdata->threadpipeHandle != -1)
		{

#ifdef DEBUG
			std::cout << "thread pipe connected!" << std::endl;
#endif
			//convert file HANDLE to FILE*
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

		writeEventPipe("!ThreadStart connection failed %d", tdata->osthreadid);
		OS_Sleep(200);
		time += 200;
	}

	cout << "[pingat]Failed to connect thread pipe, exiting process" << std::endl;
	PIN_ExitProcess(1);
}

VOID ThreadStart_openFD(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v)
{
	//wprintf(L"%s", "[pingat]in thread start 32\n");
	threadCount++;
	threadObject* tdata = new threadObject(threadCount);
	OS_GetTid(&tdata->osthreadid);

	ADDRINT startAddr = PIN_GetContextReg(ctxt, REG::REG_INST_PTR);

	writeEventPipe("TI@%d@" PTR_prefix "@", tdata->osthreadid, startAddr);

	RegisterThreadID(tdata->osthreadid, threadIndex);

	AssignBlockIndex(tdata);

	char pname[1024];
	NATIVE_PID pid;
	OS_GetPid(&pid);
	snprintf_s(pname, 1024, "\\\\?\\pipe\\TR%u%ld%u", pid, instanceID, tdata->osthreadid);
	cout << "[pingat]Connecting to thread pipe " << tdata->osthreadid << " " << pname << std::endl;

	int time = 0, expiry = 6000;
	while (time < expiry)
	{
		if (tdata->threadpipeHandle == -1)
		{
			std::cout << "[pingat]pipe -1, doing OS_OpenFD " << tdata->osthreadid << std::endl;

			OS_RETURN_CODE rtncd = OS_OpenFD(pname, OPEN_EXISTING, 0, &tdata->threadpipeHandle);

			std::cout << "[pingat]pipe -1, after createfile err 0x" << std::hex << rtncd.generic_err << " - "
				<< rtncd.os_specific_err << "  " << tdata->osthreadid << " HAND: " << tdata->threadpipeHandle << std::endl;

			if (tdata->threadpipeHandle == -1 && time > 1600 && (time % 600 == 0))
			{
				std::cout << "[pingat]Failed to connect after 1600 - err " << tdata->osthreadid << std::endl;
				std::stringstream errstr;
				errstr << "Failing to connect to thread pipe [" << std::string(pname) << "]. Error:";
				if (tdata->osthreadid == 2) errstr << " Pipe not found" << std::endl;
				else if (tdata->osthreadid == 5)errstr << " Access Denied" << std::endl;
				else errstr << tdata->osthreadid << std::endl;

				writeEventPipe("! 1600err %s", errstr.str().c_str());
			}
			OS_Sleep(50);
		}

		if (tdata->threadpipeHandle != -1)
		{

#ifdef DEBUG
			std::cout << "thread pipe connected!" << std::endl;
#endif

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

			std::cout << "[pingat] thread start done, retting " << tdata->osthreadid << std::endl;
			return;
	}

		writeEventPipe("!T8 failed %d", tdata->osthreadid);
		OS_Sleep(200);
		time += 200;
}

	cout << "Failed to connect thread pipe, exiting process" << std::endl;
	PIN_ExitProcess(1);
	}

VOID ThreadEnd(THREADID threadIndex, const CONTEXT* ctxt, INT32 flags, VOID* v)
{

	//std::cout << "In ThreadEnd" << std::endl;
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));


	if (threaddata->hasBusyBlocks) //did this take us out of a busy area?
	{
		outputUnchained(threaddata, 0);
	}


	//printTagCache(threaddata);

	OS_GetTid(&threaddata->osthreadid);
	writeEventPipe("TZ@%d@", threaddata->osthreadid);

	activeThreadUniqIDs[threaddata->blocksIndex] = 0;

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
	UINT64 endTime;
	OS_Time(&endTime);

	NATIVE_PID pid;
	OS_GetPid(&pid);
	writeEventPipe("PX@%ld@", pid);

	processExiting = true;

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
			//"[path]\pin.exe" -t "[path]\pinTool.dll" -P [pipename] -- "[path]\[target].exe" 
			if (LibraryFlag == false)
			{
				appname = std::string(argv[i + 1]);
				break;
			}
			//"[path]\pin.exe" -t "[path]\pinTool.dll" -P [pipename] -L -- "[path]\DLLLoader[X].exe" "[path]\[target].dll",[optional ordinal]
			else
			{
				if (i <= (argc - 2))
				{
					appname = std::string(argv[i + 2]);
					break;
				}
			}

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
	snprintf_s(buf, bufSize, "PID@%s@%u@%d@%d@%ld@%s@%ld", RGAT_VERSION, pid, arch, LibraryFlag.Value(), instanceID, programName.c_str(), testRunID);
}


DWORD connect_coordinator_pipe(std::string coordinatorName, NATIVE_FD& coordinatorPipe)
{

	coordinatorPipe = (NATIVE_FD)WINDOWS::CreateFileA(coordinatorName.c_str(), GENERIC_READ |  // read and write access 
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
		NULL);

	if (coordinatorPipe != -1) return 0;

	DWORD lastErr = WINDOWS::GetLastError();

	if (lastErr == ERROR_PIPE_BUSY) {
		int remaining = 10;
		do {
			coordinatorPipe = (NATIVE_FD)WINDOWS::CreateFileA(coordinatorName.c_str(), GENERIC_READ |  // read and write access 
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

DWORD extract_pipes(std::string programname, std::string coordinatorPipeName, std::string& cmdPipe, std::string& cmdResponsePipe, std::string& bbName)
{
	NATIVE_FD coordinatorPipe;
	const std::string coordinatorPath = "\\\\.\\pipe\\" + coordinatorPipeName;
	DWORD lastErr = connect_coordinator_pipe(coordinatorPath, coordinatorPipe);
	if (lastErr != 0)
	{
		if (lastErr == 2)
		{
			wprintf(L"%s", "[pingat]Unable to connect to rgat coordinator, is rgat running?\n");
		}
		else
		{
			wprintf(L"[pingat]Failed to connect to %S, error: 0x%x\n", coordinatorPath.c_str(), lastErr);
		}
		return false;
	}

	char msg[2048];
	memset(msg, 0, sizeof(msg));
	getSetupString(programname, msg, 2048);
	USIZE count = sizeof(msg);

	OS_RETURN_CODE result = OS_WriteFD(coordinatorPipe, msg, &count);
	if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
	{
		wprintf(L"[pingat]Failed to send data to coordinator pipe %S, error: 0x%x\n", coordinatorPath.c_str(), result.os_specific_err);
		return false;
	}
	else
	{
		result = OS_ReadFD(coordinatorPipe, &count, msg);
		if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
		{
			wprintf(L"[pingat]Failed to read data from coordinator pipe %S, error: 0x%x\n", coordinatorPath.c_str(), result.os_specific_err);
		}
		else
		{
#ifdef DEBUG
			wprintf(L"[pingat]Got [%d] bytes of pipe info from rgat!, msg: 0x%s\n", count, msg);
#endif
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
#ifdef DEBUG
			wprintf(L"[pingat]Got pipenames. Cmd: %s, Response: %s, BB: %s\n", cmdPipeName, responsePipeName, bbPipeName);
#endif
		}
		}


	return true;
	}


// I can't get full duplex async named pipes to work between PIN and the .net core NamedPipeServerStream, so use seperate pipes for cmds/responses
// outgoing block (ie: disassembly) data also gets its own pipe
bool establishRGATConnection(std::string programName, std::string coordinatorPipeName)
{
	std::string bbpipename, cmdpipename, eventpipename;
	if (!extract_pipes(programName, coordinatorPipeName, cmdpipename, eventpipename, bbpipename))
	{
		std::cout << "[pingat]Failed to establish process pipes" << std::endl;
		return false;
	}
	else
	{
#ifdef DEBUG
		std::cout << "[pingat]Connecting to pipes " << cmdpipename << "," << eventpipename << "," << bbpipename << std::endl;
#endif
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

				if (bbpipe == -1 && time > 1600 && (time % 600 == 0))
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
			//std::cout << "Connected to rgat! " << std::endl;
			return true;
		}
		else
		{
			std::cout << "[pingat]Failed to connect to both pipes " << std::endl;
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
#ifdef DEBUG
	std::cout << "------\nControl command: " << cmd << "\n"------" << std::endl;
#endif

		if (cmd.compare(0, 4, "EXIT") == 0) {

#ifdef DEBUG
			std::cout << "[pingat]Exiting due to exit command" << std::endl;
#endif
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
#ifdef DEBUG
			std::cout << "Break semaphore set" << std::endl;
#endif
			PIN_SemaphoreClear(&breakSem);
			PIN_StopApplicationThreads(thisThreadID);
			SetProcessBrokenState(true);

			while (!processExiting) {
				if (PIN_SemaphoreTimedWait(&continueSem, 500)) {
#ifdef DEBUG
					std::cout << "continueSem semaphore set" << std::endl;
#endif
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

	if (ConfigValueMatches("SINGLE_SHOT_INSTRUMENTATION", "TRUE")) {
		singleShotInstrumentation = true;
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
		DeclareTerribleEventAndExit(L"[pingat]Bad include list start token. You may need to reset the connection.");
		return;
	}
	getModuleIncludeLists();

	readsz = 100;
	readCommandPipe(recvBuf, &readsz);
	const char startToken2[] = "CONFIGKEYS@";
	if (strncmp(recvBuf, startToken2, sizeof(startToken2) - 1) != 0) {
		printf("[pingat]ReadConfiguration error: %s\n", recvBuf);
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


BOOL ChildProcess(CHILD_PROCESS chpd, void* v)
{
	writeEventPipe("ch@%d@%d@", PIN_GetPid(), CHILD_PROCESS_GetId(chpd));
	return true;
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

	std::string coordinatorPipeName = PipeNameValue.Value();
	if (coordinatorPipeName == "change_me")
	{
		std::cerr << "Error: No coordinator pipe name argument [-P]" << std::endl;
		PIN_ExitProcess(1);
	}

	//TraceChoiceFileList.push_back(programName); for default ignore mode
	if (!establishRGATConnection(programName, coordinatorPipeName))
	{
		std::cerr << "Failed to establish connection to rgat" << std::endl;
		PIN_ExitProcess(1);
	}

#ifdef DEBUG
	std::cout << "Connection established to rgat. Fetching trace settings" << std::endl;
#endif //  DEBUG

	ReadConfiguration();

#ifdef DEBUG
	std::cout << "Settings fetched, registering callbacks" << std::endl;
#endif //  DEBUG

	// Register function to be called to instrument traces

	TRACE_AddInstrumentFunction(InstrumentNewTrace, 0);

	PIN_AddFollowChildProcessFunction(ChildProcess, 0);
	IMG_AddInstrumentFunction(moduleLoad, (void*)tls_key);

	// Register function to be called for every thread before it starts running
	PIN_AddThreadStartFunction(ThreadStart, 0);
	//PIN_AddThreadStartFunction(ThreadStart_openFD, 0); //leaving this around in case a fix turns up

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

	// Start the program, never returns
	PIN_StartProgram();
	return 0;
	}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
