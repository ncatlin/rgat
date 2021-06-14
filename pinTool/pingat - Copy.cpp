
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
std::vector <moduleData *> loadedModulesInfo;

moduleData *lastBBModule;

BLOCKIDMAP blockIDMap;

UINT64 uniqueBBCountIns = 0;        //number of basic blocks executed and instrumented
UINT64 uniqueBBCountNoins = 0;        //number of basic blocks executed but not instrumented

UINT64 threadCount = 0;     //total number of threads, including main thread
UINT64 startTime;
std::ostream * out = &std::cerr;
static long instanceID;

unsigned long blockCounter = 0;
NATIVE_FD bbpipe, ctrlpipe;

#define BB_BUF_SIZE (1024*48)
uint8_t *basicBlockBuffer;

static  TLS_KEY tls_key = INVALID_TLS_KEY;
std::string exeModuleDir;


std::vector <threadObject> threadStructs;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobSkipSleep(KNOB_MODE_WRITEONCE, "pintool", 
	"caffine", "0", "skip sleep calls");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE, "pintool",
	"count", "1", "count instructions, basic blocks and threads in the application");

KNOB<std::string> PipeNamesData(KNOB_MODE_WRITEONCE, "pintool",
	"P", "", "Pipe Names Data");

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
	std::cout << "numods "<< numMods << std::endl;
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
		std::cout << "[pingat]addr " << addr << " not between "<< lastBBModule->start << " & "<< lastBBModule->end << std::endl;
	}

	//this does happen and i don't know why
	return false;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */



//magic performance number. adjust to taste
#define DEINSTRUMENTATION_LIMIT 10

inline VOID process_chained_block(BLOCKDATA *block_data, ADDRINT target)
{
	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));

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

			block_data->unchainedRepeats = 1;
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

		//increase thread activity counter if all blocks aside from from this one
		if (++block_data->busyCounter > thread->busyCounter)
			++thread->busyCounter;

		if (block_data->busyCounter >= DEINSTRUMENTATION_LIMIT)
		{
			printTagCache(thread);

			block_data->unchainedRepeats = 1;
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
		if (block_data->busyCounter > thread->busyCounter)
			block_data->busyCounter = thread->busyCounter;
		else
			//active block with less activity than thread - lower thread activity to match
			thread->busyCounter = ++block_data->busyCounter;

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


VOID at_unconditional_branch(BLOCKDATA *block_data, ADDRINT targetBlockAddress)
{
	//std::cout << "uncond branch block 0x" << std::hex << block_data->appc << "->" << targetBlockAddress << std::endl;

	//std::cout << "uncond in thread id " << PIN_GetTid() << " appthread: " << PIN_IsApplicationThread()  << std::endl;

	if (!block_data->unchained)
	{
		process_chained_block(block_data, targetBlockAddress);
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
VOID at_conditional_branch(BLOCKDATA *block_data, bool taken, ADDRINT targetBlockAddress, ADDRINT fallthroughAdderss)
{
	/*
	std::cout << "cond branch block 0x" << block_data->appc << "->" << std::hex;
	if (taken)
		std::cout << "taken " << targetBlockAddress << std::endl;
	else
		std::cout << "skipped " << fallthroughAdderss << std::endl;
		*/
	if (!block_data->unchained)
	{
		process_chained_block(block_data, targetBlockAddress);
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





/* ===================================================================== */
// Basic block instrumentation - client lock is held
/* ===================================================================== */
VOID Trace(TRACE trace, VOID *v)
{
	//assume a trace can't span multiple images
	ADDRINT traceStartAddr = TRACE_Address(trace);

	threadObject* thread = static_cast<threadObject*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));
	
	if (TRACE_Address(trace) < 0x10000000)
	{
		std::cout << "New Trace Generated - 0x" << std::hex << TRACE_Address(trace) <<
			std::dec << " [" << TRACE_NumIns(trace) << " instructions, " << TRACE_NumBbl(trace) << " blocks]" << std::endl;
	}

	//if (!thread->unsatisfiableBlockIDs.empty()))
	//	std::cout << "Thread " << PIN_GetTid() << " has unsatisfiable blockIDs" << std::endl;


	if (thread->unsatisfiedBlockIDs)
	{
#ifdef DEBUG_LOGGING
		dr_fprintf(dbgfile, "Current unsatisfied block addr: "ADDR_FMT"\n", thread->unsatisfiedBlockIDAddress);
#endif
		if (thread->unsatisfiedBlockIDAddress == traceStartAddr)
		{
			thread->lastBlock_expected_targID = blockCounter;
		}
		else
		{
			std::cout << "[pingat]Thread " << PIN_GetTid() << " has unsatisfied blockIDs 0x" <<
				thread->unsatisfiedBlockIDAddress << " trace start addr 0x" << traceStartAddr << std::endl;

			BLOCKIDMAP::iterator blockIDIt = blockIDMap.find(thread->unsatisfiedBlockIDAddress);
			if (blockIDIt != blockIDMap.end())
			{
				thread->lastBlock_expected_targID = blockIDIt->second;
			}
			else
			{
				thread->unsatisfiableBlockIDs[thread->unsatisfiedBlockIDAddress].push_back(thread->lastBlock);
				thread->lastBlock_expected_targID = 0;
			}
		}
		thread->unsatisfiedBlockIDAddress = 0;
		thread->unsatisfiedBlockIDs = false;
}

	//sometimes a block requests the ID for a target BB but it doesn't appear for ages
	//this watches for it and sends rgat an update to it can draw the edge for it
	if (!thread->unsatisfiableBlockIDs.empty())
	{
		auto unsatIt = thread->unsatisfiableBlockIDs.find(traceStartAddr);
		if (unsatIt != thread->unsatisfiableBlockIDs.end())
		{
			std::vector<BLOCKDATA *>::iterator requestorIt = unsatIt->second.begin();
			for (; requestorIt != unsatIt->second.end(); ++requestorIt)
			{
				BLOCKDATA *requestor = *requestorIt;
#ifdef DEBUG_LOGGING
				fprintf(thread->threadpipeFILE, "Unsatisfied block satisfied. Requestor:"ADDR_FMT",%lx Block:"ADDR_FMT",%lx@", requestor->appc, requestor->blockID, firstiPC, blockID);
#endif
				fprintf(thread->threadpipeFILE, SATISFY_MARKER",%p,%lx,%p,%lx\x01", requestor->appc, requestor->blockID, traceStartAddr, blockCounter);
			}
			thread->unsatisfiableBlockIDs.erase(unsatIt);
		}
	}


	bool isInstrumented = address_is_in_targets_v1(traceStartAddr);

	if (!isInstrumented) { return; }

	int dbg_blockct = -1;
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		dbg_blockct++;
		++uniqueBBCountIns;

		ADDRINT blockAddress = BBL_Address(bbl);

		unsigned int bufpos = 0;

		basicBlockBuffer[bufpos++] = 'B';
		memcpy(basicBlockBuffer + bufpos, (void *)&blockAddress, sizeof(ADDRINT));
		bufpos += sizeof(ADDRINT);
		basicBlockBuffer[bufpos++] = '@';
		memcpy(basicBlockBuffer + bufpos, &lastBBModule->ID, sizeof(UINT32));
		bufpos += sizeof(UINT32);
		basicBlockBuffer[bufpos++] = '@';
		basicBlockBuffer[bufpos++] = 1;
		memcpy(basicBlockBuffer + bufpos, &blockCounter, sizeof(unsigned long));
		bufpos += sizeof(UINT32);

		INS lastins = BBL_InsTail(bbl);

		BLOCKDATA *block_data = new BLOCKDATA;
		block_data->appc = blockAddress;
		block_data->blockID = blockCounter;
		block_data->insCount = BBL_NumIns(bbl);
		block_data->busyCounter = 0;
		block_data->unchained = false;
		block_data->unchainedRepeats = 0;
		block_data->targets = new std::vector<BLOCK_IDENTIFIER>;
		block_data->lastTarget = 0;
		block_data->lastTargetID = 0;
		block_data->lastInsAddress = INS_Address(lastins);
		blockIDMap[blockAddress] = blockCounter;


		//send opcodes off to rgat
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			basicBlockBuffer[bufpos++] = '@';
			basicBlockBuffer[bufpos++] = (uint8_t)INS_Size(ins); //15 is max
			memcpy(basicBlockBuffer + bufpos, (void *)INS_Address(ins), INS_Size(ins));
			bufpos += (unsigned int)INS_Size(ins);

			/*
			if (INS_Address(ins) < 0x10000000)
			{
				std::cout << "\tBlk " <<dbg_blockct<<" Ins 0x" << std::hex << INS_Address(ins) << std::endl;
			}
			*/

			if (bufpos >= (BB_BUF_SIZE - 1))
			{
				std::cerr << "[pingat]ERROR: BB Buf overflow" << std::endl;
				PIN_ExitApplication(-1);
			}
		}

		basicBlockBuffer[bufpos] = 0;
		write_sync_bb((char *)basicBlockBuffer, bufpos); 
		++blockCounter;
			
		if (INS_IsBranchOrCall(lastins))
		{
			if (INS_HasFallThrough(lastins))
			{
				INS_InsertCall(lastins, IPOINT_BEFORE, (AFUNPTR)at_conditional_branch, IARG_PTR, block_data, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_END);
			}
			else
			{
				INS_InsertCall(lastins, IPOINT_BEFORE, (AFUNPTR)at_unconditional_branch, IARG_PTR, block_data, IARG_BRANCH_TARGET_ADDR, IARG_END);
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



static VOID HandleUnixContextSwitch(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom,
	CONTEXT *ctxtTo, INT32 info, VOID *v)
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
	write_sync_mod("!%s", ctxswitch_ss.str().c_str());
}

std::wstring windowsExceptionName(INT32 excode)
{
	switch (excode)
	{
	case 0XC000008C:
		return L"ARRAY BOUNDS EXCEEDED";
	case 0XC000008D:
		return L"FLOATING-POINT DENORMAL OPERAND";
	case 0XC000008E:
		return L"FLOATING-POINT DIVISION BY ZERO";
	case 0XC000008F:
		return L"FLOATING-POINT INEXACT RESULT";
	case 0XC0000090:
		return L"FLOATING-POINT INVALID OPERATION";
	case 0XC0000091:
		return L"FLOATING-POINT OVERFLOW";
	case 0XC0000092:
		return L"FLOATING-POINT STACK CHECK";
	case 0XC0000093:
		return L"FLOATING-POINT UNDERFLOW";
	case 0XC0000094:
		return L"INTEGER DIVISION BY ZERO";
	case 0XC0000095:
		return L"INTEGER OVERFLOW";
	case 0XC0000096:
		return L"PRIVILEGED INSTRUCTION";
	default:
		return L"UNKNOWN EXCEPTION?";
	}
}

static VOID HandleWindowsContextSwitch(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom,
	CONTEXT *ctxtTo, INT32 info, VOID *v)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));

	std::wstringstream ctxswitch_ss;
	ctxswitch_ss << "![pingat] ";

	ADDRINT srcAddress = (ctxtFrom != NULL) ? PIN_GetContextReg(ctxtFrom, REG_INST_PTR) : 0;
	std::cout << "In exception " << reason<<" "<< srcAddress << " " << info << std::endl;
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
		std::cout << "WINDOWS CALLBACK " <<  std::endl;
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
	write_sync_mod("!%s", ctxswitch_ss.str().c_str());
}


/*!
* Increase counter of threads in the application.
* This function is called for every thread created by the application when it is
* about to start running (including the root thread).
* @param[in]   threadIndex     ID assigned by PIN to the new thread
* @param[in]   ctxt            initial register state for the new thread
* @param[in]   flags           thread creation flags (OS specific)
* @param[in]   v               value specified by the tool in the
*                              PIN_AddThreadStartFunction function call
*/

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	threadObject* tdata = new threadObject;
	OS_GetTid(&tdata->osthreadid);
	write_sync_mod("TI@%d@", tdata->osthreadid);
	threadCount++;

	char pname[1024];
	NATIVE_PID pid;
	OS_GetPid(&pid);
	snprintf_s(pname, 1024, "\\\\.\\pipe\\TR%u%ld%u", pid, instanceID , tdata->osthreadid);

	int time = 0, expiry = 6000;
	while (time < expiry)
	{
		if (tdata->threadpipeHandle == -1)
		{
			tdata->threadpipeHandle = (NATIVE_FD)WINDOWS::CreateFileA(pname,  
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
				NULL);

			if (tdata->threadpipeHandle == -1 && time > 1600 & (time % 600 == 0))
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
					write_sync_mod("!ERROR: Permission denied when trying to fdopen handle of %s. Error 0x%x",pname,errno);
				}
				else
				{
					write_sync_mod("!ERROR: Failed to open thread pipe. Error 0x%x", errno);
				}
				PIN_ExitProcess(1);
			}

			if (PIN_SetThreadData(tls_key, tdata, threadIndex) == FALSE)
			{
				write_sync_mod("!ERROR: PIN_SetThreadData failed");
				PIN_ExitProcess(1);
			}
			return;
		}

		OS_Sleep(15);
		time += 15;
	}
}

VOID ThreadEnd(THREADID threadIndex, const CONTEXT *ctxt, INT32 flags, VOID *v)
{

	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tls_key, threadIndex));

	printTagCache(threaddata);

	threadObject* tdata = new threadObject;
	OS_GetTid(&tdata->osthreadid);
	write_sync_mod("TZ@%d@", tdata->osthreadid);

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
VOID process_exit_event(INT32 code, VOID *v)
{
	UINT64 endTime;
	OS_Time(&endTime);

	std::cout << "===============================================" << std::endl;
	std::cout << "PINGat ended run. " << std::endl;
	std::cout << "Number of basic blocks instrumented: " << std::dec << uniqueBBCountIns << std::endl;
	std::cout << "Number of basic blocks ignored: " << std::dec << uniqueBBCountNoins << std::endl;
	std::cout << "Number of threads: " << threadCount << std::endl;
	std::cout << "Execution time: " << std::dec << ((endTime - startTime) / 1000) << " ms" << std::endl;
	std::cout << "===============================================" << std::endl;

	free(basicBlockBuffer);
}

std::string getAppName(int argc, char *argv[])
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


void getSetupString(std::string programName, char *buf, int bufSize)
{
#ifdef TARGET_IA32
	int arch = 32;
#elif TARGET_IA32E
	int arch = 64;
#endif // HOSTIA32


	NATIVE_PID pid;
	OS_GetPid(&pid);
	instanceID = random();
	snprintf_s(buf, bufSize, "PID,%u,%d,%ld,%s", pid, arch, instanceID, programName.c_str());
}


bool extract_pipes(std::string pipesblob, std::string programname, std::string &ctrlName, std::string &bbName)
{
	std::wstring coordinatorName = L"\\\\.\\pipe\\rgatCoordinator";
	NATIVE_FD coordinatorPipe = (NATIVE_FD)WINDOWS::CreateFileW(coordinatorName.c_str(), GENERIC_READ |  // read and write access 
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
		NULL);

	if (coordinatorPipe == -1)
	{
		if (WINDOWS::GetLastError() == 2) {
			wprintf(L"%s", "[pingat]Unable to connect to rgat coordinator, is rgat running?\n");
			return false;
		}
		wprintf(L"[pingat]Failed to connect to %s, error: 0x%x\n", coordinatorName, WINDOWS::GetLastError());
		return false;
	}
	else
	{
		char msg[1024];
		memset(msg, 0, sizeof(msg));
		getSetupString(programname, msg, 1024);
		USIZE count = sizeof(msg);

		OS_RETURN_CODE result = OS_WriteFD(coordinatorPipe, msg, &count);
		if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
		{
			wprintf(L"[pingat]Failed to send data to %s, error: 0x%x\n", coordinatorName, result.os_specific_err);
			return false;
		}
		else
		{
			result = OS_ReadFD(coordinatorPipe, &count, msg);
			if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
			{
				wprintf(L"[pingat]Failed to read data to %s, error: 0x%x\n", coordinatorName, result.os_specific_err);
			}
			else
			{
				wprintf(L"[pingat]Got [%d] bytes of pipe info from rgat!, msg: 0x%s\n",count, msg);
				char *marker = strtok(msg, "@");
				if (marker == NULL) return false;
				char *controlPipeName = strtok(NULL, "@");
				if (controlPipeName == NULL) return false;
				if (strlen(marker) < 2 || marker[0] != 'C' || marker[1] != 'T') return false;

				marker = strtok(NULL, "@");
				if (marker == NULL) return false;
				char *bbPipeName = strtok(NULL, "@");
				if (bbPipeName == NULL) return false;
				if (strlen(marker) < 2 || marker[0] != 'B' || marker[1] != 'B') return false;


				bbName = "\\\\.\\pipe\\" + std::string(bbPipeName);
				ctrlName = "\\\\.\\pipe\\" + std::string(controlPipeName);

				wprintf(L"[pingat]Got pipenames. Control: %s, BB: %s\n", controlPipeName, bbPipeName);
				
			}
		}
	}

	return true;
}

//pin won't connect to named pipes on windows (at the time of writing) so we have to 
//faff around with passing the duplicated handles through a mapped file, synchronised with a lockfile
bool establishRGATConnection(std::string programName)
{

	std::string pipesblob = PipeNamesData.Value();
	std::string bbpipename, ctrlpipename;
	if (!extract_pipes(pipesblob, programName, ctrlpipename, bbpipename))
	{
		std::cout << "Failed to establish process pipes" << std::endl;
		return false;
	}
	else
	{
		std::cout << "Connecting to pipes "<< ctrlpipename <<","<< bbpipename << std::endl;
		bbpipe = -1;
		ctrlpipe = -1;
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

			if (ctrlpipe == -1)
			{
				ctrlpipe = (NATIVE_FD)WINDOWS::CreateFileA(ctrlpipename.c_str(), GENERIC_READ |  // read and write access 
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0,
					NULL);

				if (ctrlpipe == -1 && time > 1500)
				{
					std::cout << "Failing to connect to control pipe ["<< ctrlpipename<<"]. Error:";
					int err = WINDOWS::GetLastError();
					if (err == 2) std::cout << " Pipe not found" <<std::endl;
					else if (err == 5) std::cout << " Access Denied" << std::endl;
					else std::cout << err << std::endl;
				}
			}
			if (bbpipe != -1 && ctrlpipe != -1) break;
			OS_Sleep(200);
			time += 200;
		}
		if (bbpipe != -1 && ctrlpipe != -1)
		{
			setControlPipe(ctrlpipe);
			std::cout << "Connected to rgat! "<< std::endl;
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

EXCEPT_HANDLING_RESULT pingat_exception_handler(THREADID threadIndex, EXCEPTION_INFO * pExceptInfo,
	PHYSICAL_CONTEXT * pPhysCtxt, VOID *v)
{
	std::cout << "IN PINGAT EXCEPTION " << PIN_ExceptionToString(pExceptInfo).c_str() << std::endl;
	write_sync_mod("!PINGAT FATAL ERROR: %s\n", PIN_ExceptionToString(pExceptInfo).c_str());
	//std::cout << "! [Pingat: Caught exception. " << PIN_ExceptionToString(pExceptInfo) << "] !" << std::endl << flush;
	return EHR_UNHANDLED;
}

ROOT_THREAD_FUNC ControlThread()
{
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
	std::cout << "in control thread" << std::endl;
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
int main(int argc, char *argv[])
{

	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
	{
		std::cerr << "[pingat] Error: PIN_Init failed. Bad command line." << std::endl;
		return -1;
	}

	OS_Time(&startTime);

	// Obtain  a key for TLS storage.
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY)
	{
		std::cout << "!PINGAT FATAL ERROR: number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << std::endl;
		PIN_ExitProcess(1);
	}


	PIN_InitSymbols(); 
	basicBlockBuffer = (uint8_t *)malloc(BB_BUF_SIZE);

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

	getModuleIncludeLists();

		// Register function to be called to instrument traces
	TRACE_AddInstrumentFunction(Trace, 0);

	IMG_AddInstrumentFunction(moduleLoad, (void *)tls_key);

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
	PIN_AddInternalExceptionHandler(pingat_exception_handler, 0);

	loadedModulesInfo.resize(40, (moduleData *)NULL);
	lastBBModule = loadedModulesInfo[0] = new moduleData;
	lastBBModule->instrumented = 0;
	lastBBModule->start = 0;
	lastBBModule->end = 0;

	PIN_SpawnInternalThread(ControlThread, NULL, 4096, NULL);
	PIN_ExitProcess(1);
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
