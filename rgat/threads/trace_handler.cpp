/*
Copyright 2016-2017 Nia Catlin

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
The thread that builds a graph for each trace
*/
#include "stdafx.h"
#include "trace_handler.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "traceStructs.h"
#include "b64.h"
#include "OSspecific.h"
#include "boost\tokenizer.hpp"

//todo move to trace structs
//waits for the disassembly of instrumented code at the specified address
bool thread_trace_handler::find_internal_at_address(MEM_ADDRESS address, int attempts)
{
	while (!piddata->disassembly.count(address))
	{
		Sleep(1);
		if (!attempts--) return false;
	}
	return true;
}

//takes an instruction as input
//returns whether current thread has executed this instruction, places its vert in vertIdxOut
bool thread_trace_handler::set_target_instruction(INS_DATA *instruction)
{
	piddata->getDisassemblyReadLock();
	unordered_map<PID_TID, NODEINDEX>::iterator vertIdIt = instruction->threadvertIdx.find(thisgraph->get_TID());
	piddata->dropDisassemblyReadLock();

	if (vertIdIt != instruction->threadvertIdx.end())
	{
		targVertID = vertIdIt->second;
		return true;
	}
	else 
		return false;
}

inline void thread_trace_handler::BB_addNewEdge(bool alreadyExecuted, int instructionIndex, unsigned long repeats)
{
	NODEPAIR edgeIDPair = make_pair(lastVertID, targVertID);

	//only need to do this for bb index 0
	edge_data *e;
	if (thisgraph->edge_exists(edgeIDPair, &e))
	{
		//cout << "repeated internal edge from " << lastVertID << "->" << targVertID << endl;
		return;
	}

	if (lastNodeType == eFIRST_IN_THREAD) return;

	edge_data newEdge;
	newEdge.chainedWeight = 0;

	if (instructionIndex > 0)
		newEdge.edgeClass = alreadyExecuted ? eEdgeOld : eEdgeNew;
	else
	{
		if (alreadyExecuted)
			newEdge.edgeClass = eEdgeOld;
		else
			switch (lastNodeType)
			{
			case eNodeReturn:
				newEdge.edgeClass = eEdgeReturn;
				break;
			case eNodeException:
				newEdge.edgeClass = eEdgeException;
				break;
			case eNodeCall:
				newEdge.edgeClass = eEdgeCall;
				break;
			default:
				newEdge.edgeClass = eEdgeNew;
				break;
			}
	}
	thisgraph->add_edge(newEdge, thisgraph->safe_get_node(lastVertID), thisgraph->safe_get_node(targVertID));
	//cout << "added internal edge from " << lastVertID << "->" << targVertID << endl;
}

//place basic block 'tag' on graph 'repeats' times
void thread_trace_handler::runBB(TAG *tag, int repeats = 1)
{
	int numInstructions = tag->insCount;
	INSLIST *block = piddata->getDisassemblyBlock(tag->blockaddr, tag->blockID, &die, 0);

	for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
	{
		INS_DATA *instruction = block->at(instructionIndex);

		if (lastNodeType != eFIRST_IN_THREAD && !thisgraph->node_exists(lastVertID))
		{
			cerr << "\t\t[rgat]ERROR: RunBB- Last vert " << lastVertID << " not found" << endl;
			assert(0);
		}



		//target vert already on this threads graph?
		bool alreadyExecuted = set_target_instruction(instruction);
		if (!alreadyExecuted)
		{
			targVertID = thisgraph->handle_new_instruction(instruction, tag->blockID, repeats);
		}
		else
		{
			thisgraph->handle_previous_instruction(targVertID, repeats);
		}

		if (lastVertID == 6 && targVertID == 8)
			cout << " f ";

		if (loopState == BUILDING_LOOP)
		{
			firstLoopVert = targVertID;
			loopState = LOOP_PROGRESS;
		}

		BB_addNewEdge(alreadyExecuted, instructionIndex, repeats);

		//setup conditions for next instruction
		switch (instruction->itype)
		{
			case eInsCall: 
				lastNodeType = eNodeCall;
				break;
				
			case eInsJump:
				lastNodeType = eNodeJump;
				break;

			case eInsReturn:
				lastNodeType = eNodeReturn;
				break;

			default:
				lastNodeType = eNodeNonFlow;
				break;
		}
		lastVertID = targVertID;
	}
}

//run a basic block which generated an exception (and therefore didn't run to completion)
void thread_trace_handler::run_faulting_BB(TAG *tag)
{
	BB_DATA *foundExtern = NULL;
	INSLIST *block = piddata->getDisassemblyBlock(tag->blockaddr, tag->blockID, &die, &foundExtern);
	if (!block)
	{ 
		if (foundExtern)
			cerr << "[rgat]Warning - faulting block was in uninstrumented code at " << tag->blockaddr << endl;
		return; 
	}

	for (unsigned int instructionIndex = 0; instructionIndex <= tag->insCount; ++instructionIndex)
	{
		INS_DATA *instruction = block->at(instructionIndex);

		if (lastNodeType != eFIRST_IN_THREAD && !thisgraph->node_exists(lastVertID))
		{
			cerr << "\t\t[rgat]ERROR: RunBB- Last vert " << lastVertID << " not found" << endl;
			assert(0);
		}

		//target vert already on this threads graph?
		bool alreadyExecuted = set_target_instruction(instruction);
		if (!alreadyExecuted)
			targVertID = thisgraph->handle_new_instruction(instruction, tag->blockID, 1);
		else
			++thisgraph->safe_get_node(targVertID)->executionCount;

		BB_addNewEdge(alreadyExecuted, instructionIndex, 1);

		//setup conditions for next instruction
		if (instructionIndex < tag->insCount)
			lastNodeType = eNodeNonFlow;
		else
		{
			lastNodeType = eNodeException;
			EnterCriticalSection(&thisgraph->highlightsCritsec);
			thisgraph->exceptionSet.insert(thisgraph->exceptionSet.end(),targVertID);
			LeaveCriticalSection(&thisgraph->highlightsCritsec);
		}

		lastVertID = targVertID;
	}
}

//decodes argument and places in processing queue, processes if all decoded for that call
void thread_trace_handler::handle_arg(char * entry, size_t entrySize) {
	MEM_ADDRESS funcpc, sourcepc;
	string argidx_s = string(strtok_s(entry + 4, ",", &entry));
	int argpos;
	if (!caught_stoi(argidx_s, &argpos, 10)) {
		cerr << "[rgat]ERROR: Trace corruption. handle_arg index int ERROR: " << argidx_s << endl;
		assert(0);
	}

	string funcpc_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(funcpc_s, &funcpc, 16)) {
		cerr << "[rgat]ERROR: Trace corruption. handle_arg funcpc address ERROR:" << funcpc_s << endl;
		assert(0);
	}

	string source_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(source_s, &sourcepc, 16)) {
		cerr << "[rgat]ERROR:Trace corruption. handle_arg returnpc address ERROR: " << source_s << endl;
		assert(0);
	}

	if (!pendingCalledFunc) {
		pendingCalledFunc = funcpc;
		pendingFuncCaller = sourcepc;
	}

	string moreargs_s = string(strtok_s(entry, ",", &entry));
	bool callDone = moreargs_s.at(0) == 'E' ? true : false;
	char b64Marker = strtok_s(entry, ",", &entry)[0];

	string contents;
	if (entry && entry < entry + entrySize)
	{
		contents = string(entry).substr(0, entrySize - (size_t)entry);
		if (b64Marker == ARG_BASE64)
			contents = base64_decode(contents);
	}
	else
		contents = string("NULL");

	pendingArgs.push_back(make_pair(argpos, contents));
	if (!callDone) return;

	//func been called in thread already? if not, have to place args in holding buffer
	if (pendingcallargs.count(pendingCalledFunc) == 0)
	{
		map <MEM_ADDRESS, vector<ARGLIST>> *newmap = new map <MEM_ADDRESS, vector<ARGLIST>>;
		pendingcallargs.emplace(pendingCalledFunc, *newmap);
	}

	if (pendingcallargs.at(pendingCalledFunc).count(pendingFuncCaller) == 0)
	{
		vector<ARGLIST> *newvec = new vector<ARGLIST>;
		pendingcallargs.at(pendingCalledFunc).emplace(make_pair(pendingFuncCaller, *newvec));
	}
		
	ARGLIST::iterator pendcaIt = pendingArgs.begin();
	ARGLIST thisCallArgs;
	for (; pendcaIt != pendingArgs.end(); ++pendcaIt)
		thisCallArgs.push_back(*pendcaIt);

	pendingcallargs.at(pendingCalledFunc).at(pendingFuncCaller).push_back(thisCallArgs);

	pendingArgs.clear();
	pendingCalledFunc = 0;
	pendingFuncCaller = 0;

	process_new_args();
}


bool thread_trace_handler::run_external(MEM_ADDRESS targaddr, unsigned long repeats, NODEPAIR *resultPair)
{
	//start by examining our caller
	node_data *lastNode = thisgraph->safe_get_node(lastVertID);
	if (lastNode->external) return false;
	assert(lastNode->ins->numbytes);
	
	//if caller is also external then we are not interested in this
	if (piddata->activeMods.at(lastNode->nodeMod) == UNINSTRUMENTED_MODULE)
		return false;

	BB_DATA *thisbb = 0;
	do { 
		piddata->get_extern_at_address(targaddr, &thisbb);
		} while (!thisbb);

	//see if caller already called this
	//if so, get the destination node so we can just increase edge weight
	auto x = thisbb->thread_callers.find(TID);
	piddata->getExternCallerReadLock();
	if (x != thisbb->thread_callers.end())
	{
		EDGELIST::iterator vecit = x->second.begin();
		for (; vecit != x->second.end(); ++vecit)
		{
			if (vecit->first != lastVertID) continue;

			piddata->dropExternCallerReadLock();
			
			//this instruction in this thread has already called it
			//cout << "repeated external edge from " << lastVertID << "->" << targVertID << endl;

			targVertID = vecit->second;

			node_data *targNode = thisgraph->safe_get_node(targVertID);
			targNode->executionCount += repeats;
			targNode->calls += repeats;
			lastVertID = targVertID;

			return true;
		}
		//else: thread has already called it, but from a different place
	}
	//else: thread hasn't called this function before

	piddata->dropExternCallerReadLock();

	lastNode->childexterns += 1;
	targVertID = thisgraph->get_num_nodes();

	piddata->getExternCallerWriteLock();

	//has this thread executed this basic block before?
	auto callersIt = thisbb->thread_callers.find(thisgraph->get_TID());
	if (callersIt == thisbb->thread_callers.end())
	{
		EDGELIST callervec;
		callervec.push_back(make_pair(lastVertID, targVertID));
		thisbb->thread_callers.emplace(TID, callervec);
	}
	else
		callersIt->second.push_back(make_pair(lastVertID, targVertID));

	piddata->dropExternCallerWriteLock();

	int module = thisbb->modnum;

	//make new external/library call node
	node_data newTargNode;
	newTargNode.nodeMod = module;
	newTargNode.external = true;
	newTargNode.address = targaddr;
	newTargNode.index = targVertID;
	newTargNode.parentIdx = lastVertID;
	newTargNode.executionCount = 1;

	thisgraph->insert_node(targVertID, newTargNode); //this invalidates all node_data* pointers
	lastNode = &newTargNode;

	*resultPair = std::make_pair(lastVertID, targVertID);

	edge_data newEdge;
	newEdge.chainedWeight = 0;
	newEdge.edgeClass = eEdgeLib;
	thisgraph->add_edge(newEdge, thisgraph->safe_get_node(lastVertID), thisgraph->safe_get_node(targVertID));
	//cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
	lastNodeType = eNodeExternal;
	lastVertID = targVertID;
	return true;
}

bool thread_trace_handler::lookup_extern_func_calls(MEM_ADDRESS called_function_address, EDGELIST &callEdges)
{
	piddata->getExternDictReadLock();
	piddata->getExternCallerReadLock();

	map<MEM_ADDRESS, BB_DATA*>::iterator externIt;
	externIt = piddata->externdict.find(called_function_address);
	if (externIt == piddata->externdict.end() || !externIt->second->thread_callers.count(TID))
	{
		piddata->dropExternDictReadLock();
		piddata->dropExternCallerReadLock();
		return false;

	}

	callEdges = externIt->second->thread_callers.at(TID);

	piddata->dropExternDictReadLock();
	piddata->dropExternCallerReadLock();

	return true;
}

//function call arguments are sent over from drgat seperately from the trace data 
//this iterates through the arguments we receive and matches them up to their relevant nodes
void thread_trace_handler::process_new_args()
{
	//target function		caller  		args
	map<MEM_ADDRESS, map <MEM_ADDRESS, vector<ARGLIST>>>::iterator pendingCallArgIt = pendingcallargs.begin();
	while (pendingCallArgIt != pendingcallargs.end())
	{

		EDGELIST threadCalls;
		//each function can have multiple nodes in a thread, so we have to get the list of 
		//every edge that has this extern as a target
		if (!lookup_extern_func_calls(pendingCallArgIt->first, threadCalls))
		{
			++pendingCallArgIt;
			continue;
		}
		
		//run through each edge, trying to match args to the right caller-callee pair
		//running backwards should be more efficient as the lastest node is likely to hit the latest arguments
		EDGELIST::reverse_iterator callEdgeIt = threadCalls.rbegin();
		while (callEdgeIt != threadCalls.rend()) 
		{
			node_data *callerNode = thisgraph->safe_get_node(callEdgeIt->first);
			MEM_ADDRESS callerAddress = callerNode->ins->address; //this breaks if call not used?
			node_data *functionNode = thisgraph->safe_get_node(callEdgeIt->second);

			obtainMutex(&thisgraph->externGuardMutex, 1048);
			map <MEM_ADDRESS, vector<ARGLIST>>::iterator caller_args_vec_IT = pendingCallArgIt->second.begin();
			
			while (caller_args_vec_IT != pendingCallArgIt->second.end())
			{
				//check if we have found the source of the call that used these arguments
				if (caller_args_vec_IT->first != callerAddress)
				{ 
					++caller_args_vec_IT;
					continue;
				}

				vector<ARGLIST> &calls_arguments_list = caller_args_vec_IT->second;

				ARGLIST args;
				foreach(args, calls_arguments_list)
				{
					//each node can only have a certain number of arguments to prevent simple DoS
					//todo: should be a launch option though
					if (functionNode->callRecordsIndexs.size() < arg_storage_capacity)
					{
						EXTERNCALLDATA callRecord;
						callRecord.edgeIdx = *callEdgeIt;
						callRecord.argList = args;

						thisgraph->externCallRecords.push_back(callRecord);
						functionNode->callRecordsIndexs.push_back(thisgraph->externCallRecords.size() - 1);
					}
					else
						break;
				}
				calls_arguments_list.clear();

				if (caller_args_vec_IT->second.empty())
					caller_args_vec_IT = pendingCallArgIt->second.erase(caller_args_vec_IT);
				else
					++caller_args_vec_IT;
			}
			dropMutex(&thisgraph->externGuardMutex);

			++callEdgeIt;
		}
		if (pendingCallArgIt->second.empty())
			pendingCallArgIt = pendingcallargs.erase(pendingCallArgIt);
		else
			++pendingCallArgIt;
	}
}

//#define VERBOSE
void thread_trace_handler::handle_exception_tag(TAG *thistag)
{
#ifdef VERBOSE
	cout << "handling tag 0x" << thistag->blockaddr << " jmpmod:" << thistag->jumpModifier;
	if (thistag->jumpModifier == 2)
		cout << " - sym: " << piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr];
	cout << endl;
#endif
	if (thistag->jumpModifier == INSTRUMENTED_MODULE)
	{
		run_faulting_BB(thistag);

		thisgraph->totalInstructions += thistag->insCount;

		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag->jumpModifier == UNINSTRUMENTED_MODULE) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//find caller,external vertids if old + add node to graph if new
		NODEPAIR resultPair;
		cout << "[rgat]WARNING: Exception handler in uninstrumented module reached." <<
			"I have no idea if this code will handle it; Let me know when you reach the other side..." << endl;
		run_external(thistag->blockaddr, 1, &resultPair);
		thisgraph->set_active_node(resultPair.second);
	}
	else
	{
		cerr << "[rgat]Error: Bad jump tag" << endl;
		assert(0);
	}
}

//#define VERBOSE
void thread_trace_handler::handle_tag(TAG *thistag, unsigned long repeats = 1)
{
#ifdef VERBOSE
	cout << "handling tag 0x"<<std::hex<< thistag->blockaddr <<std::dec
		<< " jmpmod:" << thistag->jumpModifier << " inscount:"<<thistag->insCount << " repeats:"<<repeats;
	//if (thistag->jumpModifier == 2)
	//	cout << " - sym: "<< piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr];
	cout << endl;
#endif
	if (thistag->jumpModifier == INSTRUMENTED_MODULE)
	{
		runBB(thistag, repeats);
		thisgraph->totalInstructions += thistag->insCount*repeats;
		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag->jumpModifier == UNINSTRUMENTED_MODULE) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//find caller,external vertids if old + add node to graph if new
		NODEPAIR resultPair;
		run_external(thistag->blockaddr, repeats, &resultPair);
		process_new_args();
		thisgraph->set_active_node(resultPair.second);
	}
	else
	{
		cerr << "[rgat]Handle_tag dead code assert" << endl;
		assert(0);
	}
}

//returns the module starting before and ending after the provided address
//if that's none of them, assume its a new code area in calling module
//TODO: this assumption is bad; any self modifying dll may cause problems
int thread_trace_handler::find_containing_module(MEM_ADDRESS address)
{
	const size_t numModules = piddata->modBounds.size();
	for (int modNo = 0; modNo < numModules; ++modNo)
	{
		piddata->getDisassemblyReadLock();
		//todo: bug: sometimes modNo not in modBounds
		pair<MEM_ADDRESS, MEM_ADDRESS> *moduleBounds = &piddata->modBounds.at(modNo);
		piddata->dropDisassemblyReadLock();
		if (address >= moduleBounds->first && address <= moduleBounds->second)
		{
			if (piddata->activeMods.at(modNo) == INSTRUMENTED_MODULE)
				return INSTRUMENTED_MODULE;
			else 
				return UNINSTRUMENTED_MODULE;
		}
	}
	return UNKNOWN_MODULE;
}

//updates graph entry for each tag in the trace loop cache
void thread_trace_handler::dump_loop()
{
	assert(loopState == BUILDING_LOOP);

	if (loopCache.empty())
	{
		loopState = NO_LOOP;
		return;
	}

	//put the verts/edges on the graph
	for (unsigned int cacheIdx = 0; cacheIdx < loopCache.size(); ++cacheIdx)
	{
		TAG *thistag = &loopCache[cacheIdx];
		handle_tag(thistag, loopIterations);

		ANIMATIONENTRY animUpdate;
		animUpdate.blockAddr = thistag->blockaddr;
		animUpdate.blockID = thistag->blockID;
		animUpdate.count = loopIterations;
		animUpdate.entryType = eAnimLoop;
		if (piddata->get_extern_at_address(animUpdate.blockAddr, 0, 0))
		{
			pair<MEM_ADDRESS, BLOCK_IDENTIFIER> uniqueExternID = make_pair(thistag->blockaddr, thistag->blockID);
			animUpdate.callCount = externFuncCallCounter[uniqueExternID]++;
		}

		thisgraph->push_anim_update(animUpdate);
	}

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimLoopLast;
	thisgraph->push_anim_update(animUpdate);

	loopCache.clear();
	loopIterations = 0;
	loopState = NO_LOOP;
}

//todo: move this to piddata class
INSLIST *thread_trace_handler::find_block_disassembly(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID)
{
	map <MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blocklistIt;
	map<BLOCK_IDENTIFIER, INSLIST *>::iterator mutationIt;

	piddata->getDisassemblyReadLock();
	blocklistIt = piddata->blocklist.find(blockaddr);
	
	//code at address hasn't been disassembled ever
	if (blocklistIt == piddata->blocklist.end()) { piddata->dropDisassemblyReadLock(); return 0; }

	mutationIt = blocklistIt->second.find(blockID);
	piddata->dropDisassemblyReadLock();

	
	if (mutationIt == blocklistIt->second.end()) 
		//required "mutation" of block hasn't been disassembled
		return 0; 
	else
		return mutationIt->second;
}

void thread_trace_handler::satisfy_pending_edges()
{
	vector<NEW_EDGE_BLOCKDATA>::iterator pendIt = pendingEdges.begin();
	while (pendIt != pendingEdges.end())
	{
		INSLIST *source = find_block_disassembly(pendIt->sourceAddr, pendIt->sourceID);
		if (!source) {
			++pendIt;
			continue;
		}

		INSLIST *targ = find_block_disassembly(pendIt->targAddr, pendIt->targID);
		if (!targ) {
			++pendIt;
			continue;
		}

		thisgraph->insert_edge_between_BBs(source, targ);
		pendIt = pendingEdges.erase(pendIt);

		//not sure what causes these to happen but haven't seen any get satisfied
		cout << "Satisfied an edge request!" << endl;
	}
}

//peforms non-sequence critical graph updates
//update nodes with cached execution counts and new edges from unchained runs
//also updates graph with delayed edge notifications
bool thread_trace_handler::assign_blockrepeats()
{
	lastRepeatUpdate = GetTickCount64();

	if (!pendingEdges.empty())
		satisfy_pending_edges();

	if (blockRepeatQueue.empty()) return true;

	vector<BLOCKREPEAT>::iterator repeatIt = blockRepeatQueue.begin();
	while (repeatIt != blockRepeatQueue.end())
	{
		//first find the blocks instruction list
		MEM_ADDRESS blockaddr = repeatIt->blockaddr;
		BLOCK_IDENTIFIER blockID = repeatIt->blockID;
		node_data *n = 0;

		if(!repeatIt->blockInslist)
		{
			repeatIt->blockInslist = find_block_disassembly(blockaddr, blockID);
			if (!repeatIt->blockInslist) {
				++repeatIt; continue;
			}

			//first/last vert not on drawn yet? skip until it is
			if (repeatIt->blockInslist->front()->threadvertIdx.count(TID) == 0 || repeatIt->blockInslist->back()->threadvertIdx.count(TID) == 0) {
				++repeatIt; continue;
			}

			//increase weight of all of its instructions
			INSLIST::iterator blockIt = repeatIt->blockInslist->begin();
			for (; blockIt != repeatIt->blockInslist->end(); ++blockIt)
			{
				INS_DATA *ins = *blockIt;
				n = thisgraph->safe_get_node(ins->threadvertIdx.at(TID));
				n->executionCount += repeatIt->totalExecs;
				thisgraph->totalInstructions += repeatIt->totalExecs;
				if (--repeatIt->insCount == 0)
					break;
			}
		}
		else
		{
			INS_DATA* lastIns = repeatIt->blockInslist->at(repeatIt->blockInslist->size() - 1);
			n = thisgraph->safe_get_node(lastIns->threadvertIdx.at(TID));
		}
		
		//create any new edges between unchained nodes
		vector<pair<MEM_ADDRESS, BLOCK_IDENTIFIER>>::iterator targCallIt = repeatIt->targBlocks.begin();
		while (targCallIt != repeatIt->targBlocks.end())
		{
			INSLIST* targetBlock = find_block_disassembly(targCallIt->first, targCallIt->second);
			if (!targetBlock)
			{
				//external libraries will not be found by find_block_disassembly, but will be handled by run_external
				//this notices it has been handled and drops it from pending list
				bool alreadyPresent = false;
				set<unsigned int>::iterator calledIt = n->outgoingNeighbours.begin();
				for (; calledIt != n->outgoingNeighbours.end(); ++calledIt)
					if (thisgraph->safe_get_node(*calledIt)->address == targCallIt->first)
					{
						alreadyPresent = true;
						break;
					}

				if (alreadyPresent)
					targCallIt = repeatIt->targBlocks.erase(targCallIt);
				else
					++targCallIt;
	
				continue;
			}

			INS_DATA *firstIns = targetBlock->front();
			if (!firstIns->threadvertIdx.count(TID)) { ++targCallIt; continue; }

			targCallIt = repeatIt->targBlocks.erase(targCallIt);
		}

		if (repeatIt->targBlocks.empty())
			repeatIt = blockRepeatQueue.erase(repeatIt);
		else
			++repeatIt;
		
	}

	return blockRepeatQueue.empty();
}

void thread_trace_handler::add_unchained_update(char *entry)
{
	MEM_ADDRESS blockAddr;
	string block_ip_s = string(strtok_s(entry + 3, ",", &entry));
	if (!caught_stoull(block_ip_s, &blockAddr, 16)) {
		cerr << "[rgat]ERROR: UC handling addr STOL: " << block_ip_s << endl;
		assert(0);
	}

	BLOCK_IDENTIFIER blockId;
	string block_id_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(block_id_s, &blockId, 16)) {
		cerr << "[rgat]ERROR: UC handling ID STOL: " << block_ip_s << endl;
		assert(0);
	}

	MEM_ADDRESS targAddr;
	block_ip_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(block_ip_s, &targAddr, 16)) {
		cerr << "[rgat]ERROR: UC handling addr STOL: " << block_ip_s << endl;
		assert(0);
	}

	BLOCK_IDENTIFIER targId;
	block_id_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(block_id_s, &targId, 16)) {
		cerr << "[rgat]ERROR: UC handling ID STOL: " << block_ip_s << endl;
		assert(0);
	}

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimUnchained;
	animUpdate.blockAddr = blockAddr;
	animUpdate.blockID = blockId;
	animUpdate.targetAddr = targAddr;
	animUpdate.targetID = targId;
	thisgraph->push_anim_update(animUpdate);
}

void thread_trace_handler::add_satisfy_update(char *entry)
{
	NEW_EDGE_BLOCKDATA edgeNotification;

	string s_ip_s = string(strtok_s(entry + 4, ",", &entry));
	if (!caught_stoull(s_ip_s, &edgeNotification.sourceAddr, 16)) assert(0);

	string s_ID_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(s_ID_s, &edgeNotification.sourceID, 16)) assert(0);

	string t_ip_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(t_ip_s, &edgeNotification.targAddr, 16)) assert(0);

	string t_ID_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(t_ID_s, &edgeNotification.targID, 16)) assert(0);

	pendingEdges.push_back(edgeNotification);
}

void thread_trace_handler::add_exception_update(char *entry)
{
	MEM_ADDRESS e_ip;
	string e_ip_s = string(strtok_s(entry + 4, ",", &entry));
	if (!caught_stoull(e_ip_s, &e_ip, 16)) {

		assert(0);
	}

	DWORD e_code;
	string e_code_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(e_code_s, &e_code, 16)) {
		cerr << "[rgat]ERROR: Exception handling STOL: " << e_code_s << endl;
		assert(0);
	}

	DWORD e_flags;
	string e_flags_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(e_flags_s, &e_flags, 16)) {
		cerr << "[rgat]ERROR: Exception handling STOL: " << e_code_s << endl;
		assert(0);
	}

	cout << "[rgat]Exception detected in PID: " << runRecord->getPID() << " TID: " << TID
	<< "[code " << std::hex << e_code << " flags: " << e_flags << "] at address 0x" << hex << e_ip << endl;

	piddata->getDisassemblyReadLock();
	//problem here: no way of knowing which mutation of the faulting instruction was executed
	//going to have to assume it's the most recent mutation
	if (!piddata->disassembly.count(e_ip))
	{
		piddata->dropDisassemblyReadLock();
		Sleep(100);
		piddata->getDisassemblyReadLock();
		if (!piddata->disassembly.count(e_ip))
		{
			piddata->dropDisassemblyReadLock();
			cerr << "[rgat]Exception address 0x" << hex << e_ip << " not found in disassembly" << endl;
			return;
		}
	}
	INS_DATA *exceptingins = piddata->disassembly.at(e_ip).back();
	//problem here: no way of knowing which mutation of the faulting block was executed
	//going to have to assume it's the most recent mutation
	pair<MEM_ADDRESS, BLOCK_IDENTIFIER> *faultingBB = &exceptingins->blockIDs.back();
	piddata->dropDisassemblyReadLock();

	INSLIST *interruptedBlock = piddata->getDisassemblyBlock(faultingBB->first, faultingBB->second, &die, 0);
	INSLIST::iterator blockIt = interruptedBlock->begin();
	int instructionsUntilFault = 0;
	for (; blockIt != interruptedBlock->end(); ++blockIt)
	{
		if (((INS_DATA *)*blockIt)->address == e_ip) break;
		++instructionsUntilFault;
	}

	TAG interruptedBlockTag;
	interruptedBlockTag.blockaddr = faultingBB->first;
	interruptedBlockTag.insCount = instructionsUntilFault;
	interruptedBlockTag.blockID = faultingBB->second;
	interruptedBlockTag.jumpModifier = INSTRUMENTED_MODULE;
	handle_exception_tag(&interruptedBlockTag);

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimExecException;
	animUpdate.blockAddr = interruptedBlockTag.blockaddr;
	animUpdate.blockID = interruptedBlockTag.blockID;
	animUpdate.count = instructionsUntilFault;
	thisgraph->push_anim_update(animUpdate);
}

void thread_trace_handler::add_exec_count_update(char *entry)
{
	BLOCKREPEAT newRepeat;
	newRepeat.totalExecs = 0;

	string block_address_string = string(strtok_s(entry + 3, ",", &entry));
	if (!caught_stoull(block_address_string, &newRepeat.blockaddr, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << block_address_string << endl;
		assert(0);
	}

	unsigned long long id_count;
	string block_id_count_string = string(strtok_s(entry, ",", &entry));
	id_count = stoll(block_id_count_string, 0, 16);
	newRepeat.insCount = id_count & 0xffffffff;
	newRepeat.blockID = id_count >> 32;

	string executions_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(executions_s, &newRepeat.totalExecs, 16)) {
		cerr << "[rgat]ERROR: BX handling execcount STOL: " << executions_s << endl;
		assert(0);
	}

	while (true)
	{
		if (!entry || !entry[0]) break;
		MEM_ADDRESS targ;
		string targ_s = string(strtok_s(entry, ",", &entry));
		if (!caught_stoull(targ_s, &targ, 16)) {
			cerr << "[rgat]ERROR: BX handling addr STOL: " << targ_s << endl;
			assert(0);
		}

		//not happy to be using ulong and casting it to BLOCK_IDENTIFIER
		//std:stoi is throwing out of range on <=0xffffffff though?
		unsigned long blockID;
		string BID_s = string(strtok_s(entry, ",", &entry));
		if (!caught_stoul(BID_s, &blockID, 16)) {
			cerr << "[rgat]ERROR: BX handling count STOI: " << BID_s << endl;
			assert(0);
		}
		newRepeat.targBlocks.push_back(make_pair(targ, (BLOCK_IDENTIFIER)blockID));
	}

	blockRepeatQueue.push_back(newRepeat);

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimUnchainedResults;
	animUpdate.blockAddr = newRepeat.blockaddr;
	animUpdate.blockID = newRepeat.blockID;
	animUpdate.count = newRepeat.totalExecs;
	thisgraph->push_anim_update(animUpdate);
}

void thread_trace_handler::add_unlinking_update(char *entry)
{
	MEM_ADDRESS sourceAddr;
	BLOCK_IDENTIFIER sourceID;
	unsigned long long id_count;

	string block_address_string = string(strtok_s(entry + 3, ",", &entry));
	if (!caught_stoull(block_address_string, &sourceAddr, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << block_address_string << endl;
		assert(0);
	}
	string block_id_count_string = string(strtok_s(entry, ",", &entry));
	id_count = stoll(block_id_count_string, 0, 16);
	sourceID = id_count >> 32;

	INSLIST* lastBB = find_block_disassembly(sourceAddr, sourceID);
	if (!lastBB) {
		Sleep(50);
		if (die || thisgraph->terminated) return;
		cerr << "[rgat]ERROR: Failed to find UL source block: " << hex << sourceAddr << endl;
		assert(0);
	}
	INS_DATA* lastIns = lastBB->back();

	unordered_map<PID_TID, NODEINDEX>::iterator vertIt = lastIns->threadvertIdx.find(TID);
	if (vertIt == lastIns->threadvertIdx.end()) {
		Sleep(50);
		if (die || thisgraph->terminated) return;
		cerr << "[rgat]ERROR: Failed to find UL last node: " << hex << sourceAddr << endl;
		assert(0);
	}
	lastVertID = vertIt->second;

	TAG thistag;

	//wtf is this then?
	string target_address_string = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(target_address_string, &thistag.blockaddr, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << target_address_string << endl;
		assert(0);
	}

	id_count = stoll(entry, 0, 16);
	thistag.insCount = id_count & 0xffffffff;
	thistag.blockID = id_count >> 32;
	thistag.jumpModifier = 1;
	handle_tag(&thistag);

	string targ2_s = string(entry);
	MEM_ADDRESS targ2;
	if (!caught_stoull(targ2_s, &targ2, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << targ2_s << endl;
		assert(0);
	}

	if (find_containing_module(targ2) == UNINSTRUMENTED_MODULE)
	{
		BB_DATA* foundExtern = 0;
		bool addressFound = piddata->get_extern_at_address(targ2, &foundExtern, 3);
		assert(addressFound);

		bool targetFound = false;
		piddata->getExternCallerReadLock();
		map <PID_TID, EDGELIST>::iterator callerIt = foundExtern->thread_callers.find(TID);

		if (callerIt != foundExtern->thread_callers.end())
		{
			int num = foundExtern->thread_callers.at(TID).size();
			for (int i = 0; i < num; i++)
			{
				NODEPAIR edge = foundExtern->thread_callers.at(TID).at(i);
				if (edge.first == targVertID)
				{
					targetFound = true;
					lastVertID = foundExtern->thread_callers.at(TID).at(0).second;
					node_data *lastnode = thisgraph->safe_get_node(lastVertID);
					++lastnode->executionCount;
					break;
				}
			}
			if (!targetFound)
				cerr << "[rgat]Warning: 0x" << std::hex << targ2 << " in " << piddata->modpaths.at(foundExtern->modnum) << " not found. Heatmap accuracy may suffer." << endl;
		}
		else
		{
			/*
			i've only seen this fail when unlinking happens at the end of a program. eg:
				int main()
				{
					for (many iterations){ do a thing; }
					return 0;  <- targ2 points to address outside program... can't draw an edge to it
				}
			which is not a problem.
			could come up with a way to only warn if the thread continues but it will be messy
			*/
			cerr << "[rgat]Warning,  unseen code executed after a busy block. (Module: " 
				 << piddata->modpaths.at(foundExtern->modnum) <<" Addr: " << std::hex << targ2 << ")" << endl;
			cerr << "\t If this happened at a thread exit it is not a problem and can be ignored" << std::dec << endl;
		}
		piddata->dropExternCallerReadLock();
	}

	ANIMATIONENTRY animUpdate;
	animUpdate.blockAddr = thistag.blockaddr;
	animUpdate.blockID = thistag.blockID;
	animUpdate.entryType = eAnimUnchainedDone;
	thisgraph->push_anim_update(animUpdate);
}

void thread_trace_handler::process_trace_tag(char *entry)
{
	TAG thistag;
	MEM_ADDRESS nextBlock;

	thistag.blockaddr = stoull(strtok_s(entry + 1, ",", &entry), 0, 16);
	nextBlock = stoull(strtok_s(entry, ",", &entry), 0, 16);

	unsigned long long id_count = stoll(strtok_s(entry, ",", &entry), 0, 16);
	thistag.insCount = id_count & 0xffffffff;
	thistag.blockID = id_count >> 32;

	thistag.jumpModifier = INSTRUMENTED_MODULE;
	if (loopState == BUILDING_LOOP)
		loopCache.push_back(thistag);
	else
	{
		handle_tag(&thistag);

		ANIMATIONENTRY animUpdate;
		animUpdate.blockAddr = thistag.blockaddr;
		animUpdate.blockID = thistag.blockID;
		animUpdate.entryType = eAnimExecTag;
		thisgraph->push_anim_update(animUpdate);
	}

	//fallen through/failed conditional jump
	if (nextBlock == 0) return;

	int modType = find_containing_module(nextBlock);
	if (modType == INSTRUMENTED_MODULE) return;

	//modType could be known unknown here
	//in case of unknown, this waits until we know. hopefully rare.
	int attempts = 1;
	while (!die)
	{
		//this is most likely to be called and looping is rare - usually
		if (piddata->get_extern_at_address(nextBlock, &thistag.foundExtern, attempts))
		{
			modType = UNINSTRUMENTED_MODULE;
			break;
		}
		if (find_internal_at_address(nextBlock, attempts))
		{
			modType = INSTRUMENTED_MODULE;
			break;
		}

		if (attempts++ > 10)
		{
			cerr << "[rgat] (tid:" << TID << " pid:" << runRecord->getPID() << ")Warning: Failing to find address " <<
				std::hex << nextBlock << " in instrumented or external code. Block tag(addr: " <<
				thistag.blockaddr << " insQty: " << thistag.insCount << "id: " <<
				thistag.blockID << " modtype: " << modType << endl;
			Sleep(60);
		}
	}

	if (modType == INSTRUMENTED_MODULE) return;

	thistag.blockaddr = nextBlock;
	thistag.jumpModifier = UNINSTRUMENTED_MODULE;
	thistag.insCount = 0;

	if (loopState == BUILDING_LOOP)
		loopCache.push_back(thistag);
	else
	{
		handle_tag(&thistag);

		ANIMATIONENTRY animUpdate;
		animUpdate.blockAddr = thistag.blockaddr;
		animUpdate.blockID = thistag.blockID;
		animUpdate.entryType = eAnimExecTag;
		animUpdate.callCount = externFuncCallCounter[make_pair(thistag.blockaddr, thistag.blockID)]++;
		thisgraph->push_anim_update(animUpdate);
	}

}

void thread_trace_handler::process_loop_marker(char *entry)
{
	if (entry[1] == LOOP_START_MARKER)
	{
		loopState = BUILDING_LOOP;
		string repeats_s = string(strtok_s(entry + 2, ",", &entry));
		if (!caught_stoul(repeats_s, &loopIterations, 10))
			cerr << "[rgat]ERROR: Loop start STOL " << repeats_s << endl;

		return;
	}

	else if (entry[1] == LOOP_END_MARKER)
	{
		dump_loop();
		return;
	}

	cerr << "[rgat] ERROR: Fell through bad loop tag?" << entry << endl;
	assert(0);
}

//build graph for a thread as the trace data arrives from the reader thread
void thread_trace_handler::main_loop()
{
	alive = true;

	unsigned long itemsDone = 0;

	string *message;
	clock_t endwait = clock() + 1;
	while (!die)
	{
		clock_t timenow = clock();
		if (timenow > endwait)
		{
			endwait = timenow + 1;
			thisgraph->setBacklogOut(itemsDone);
			itemsDone = 0;
		}

		message = reader->get_message(thisgraph->traceBufferSize);
		if (!message)
		{
			assign_blockrepeats();
			Sleep(5);
			continue;
		}

		if(repeatsUpdateDue())
			assign_blockrepeats();

		if ((int)message == -1) //thread pipe closed
		{
			if (!loopCache.empty())
			{
				loopState = BUILDING_LOOP;
				dump_loop();
			}
			
			thisgraph->set_terminated();
			thisgraph->updated = true;
			break;
		}

		while (*saveFlag && !die) 
			Sleep(20); //writing while saving -> corrupt save

		++itemsDone;

		boost::char_separator<char> sep("@");
		boost::tokenizer< boost::char_separator<char> > tok(*message, sep);
		for (boost::tokenizer< boost::char_separator<char> >::iterator beg = tok.begin(); beg != tok.end(); ++beg)
		{
			string entry = *beg;
			if (entry.empty()) break;

			//cout << "TID"<<TID<<" Processing entry: ["<<entry<<"]"<<endl;

			if (entry[0] == TRACE_TAG_MARKER)
			{
				process_trace_tag((char *)entry.c_str());
				continue;
			}

			if (entry[0] == LOOP_MARKER)
			{	
				process_loop_marker((char *)entry.c_str());
				continue;
			}

			//wrapped function arguments
			if (entry.substr(0, 3) == "ARG")
			{
				handle_arg((char *)entry.c_str(), entry.size());
				continue;
			}

			//unchained ended - link last unchained block to new block
			if (entry.substr(0, 2) == "UL")
			{
				add_unlinking_update((char *)entry.c_str());
				continue;
			}

			//block unchaining notification
			if (entry.substr(0, 2) == "UC")
			{
				add_unchained_update((char *)entry.c_str());
				continue;
			}

			//block execution count + targets after end of unchained execution
			if (entry.substr(0, 2) == "BX")
			{
				add_exec_count_update((char *)entry.c_str());
				continue;
			}

			if (entry.substr(0, 3) == "SAT")
			{
				add_satisfy_update((char *)entry.c_str());
				continue;
			}

			if (entry.substr(0, 3) == "EXC")
			{
				add_exception_update((char *)entry.c_str());
				continue;
			}

			cerr << "[rgat]ERROR: Trace handler TID " <<dec<< TID << " unhandled line " << 
				entry << " ("<<entry.size()<<" bytes)"<<endl;
			assert(0);
		}
	}

	int max = 10;
	while (max-- && !assign_blockrepeats())
		Sleep(5);

	if (!assign_blockrepeats())
	{
		cerr << "[rgat] WARNING: " << blockRepeatQueue.size() << " unsatisfied blocks!\n" << endl;
		std::vector<BLOCKREPEAT>::iterator repeatIt = blockRepeatQueue.begin();
		for (; repeatIt != blockRepeatQueue.end(); ++repeatIt)
		{
			cerr << "\t Block Addr: 0x" << hex << repeatIt->blockaddr << endl;
			cerr << "\t Targeted unavailable blocks: ";

			vector<pair<MEM_ADDRESS, unsigned long>>::iterator targIt = repeatIt->targBlocks.begin();
			for (; targIt != repeatIt->targBlocks.end(); ++targIt)
				cerr << "[0x" << targIt->first << "] " << endl;
			cerr << endl;
		}
	}

	thisgraph->terminationFlag = true;
	thisgraph->terminated = true;
	thisgraph->active = false;
	thisgraph->finalNodeID = lastVertID;
	runRecord->notify_tid_end(TID);

	alive = false;
}

