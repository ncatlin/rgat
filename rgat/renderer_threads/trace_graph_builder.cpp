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
The thread that builds a graph for each trace from the drgat trace stream (which is delivered by the trace_reader thread). 
*/

#include "stdafx.h"
#include "trace_graph_builder.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "traceStructs.h"
#include "b64.h"
#include "OSspecific.h"
#include "boost\tokenizer.hpp"

//todo move to trace structs
//waits for the disassembly of instrumented code at the specified address
bool trace_graph_builder::find_internal_at_address(ADDRESS_OFFSET offset, int attempts)
{
	while (!piddata->disassembly.count(offset))
	{
		Sleep(1);
		if (!attempts--) return false;
	}
	return true;
}

//takes an instruction as input
//returns whether current thread has executed this instruction, places its vert in vertIdxOut
bool trace_graph_builder::set_target_instruction(INS_DATA *instruction)
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

inline void trace_graph_builder::BB_addNewEdge(bool alreadyExecuted, int instructionIndex, unsigned long repeats)
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

//place basic block [tag] on graph [repeats] times
void trace_graph_builder::runBB(TAG *tag, int repeats = 1)
{
	INSLIST *block = piddata->getDisassemblyBlock(tag->blockaddr, tag->blockID, &die, 0);
	int numInstructions = block->size();

	for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
	{
		INS_DATA *instruction = block->at(instructionIndex);

		//start possible #ifdef DEBUG  candidate
		if (lastNodeType != eFIRST_IN_THREAD)
		{
			if (!thisgraph->node_exists(lastVertID))
			{
				//had an odd error here where it returned false with idx 0 and node list size 1. can only assume race condition?
				cerr << "\t\t[rgat]ERROR: RunBB- Last vert " << lastVertID << " not found. Node list size is: " << thisgraph->nodeList.size() << endl;
				assert(0);
			}
		}
		//end possible  #ifdef DEBUG candidate

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
void trace_graph_builder::run_faulting_BB(TAG *tag)
{
	ROUTINE_STRUCT *foundExtern = NULL;
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
		
		//BB_addExceptionEdge(alreadyExecuted, instructionIndex, 1);

		//setup conditions for next instruction
		if (instructionIndex < tag->insCount)
			lastNodeType = eNodeNonFlow;
		else
		{
			lastNodeType = eNodeException;
			thisgraph->highlightsLock.lock();
			thisgraph->exceptionSet.insert(thisgraph->exceptionSet.end(),targVertID);
			thisgraph->highlightsLock.unlock();
		}

		lastVertID = targVertID;
	}
}

//decodes argument and places in processing queue, processes if all decoded for that call
void trace_graph_builder::handle_arg(char * entry, size_t entrySize) 
{

	MEM_ADDRESS funcpc, sourcepc;
	string argidx_s = string(strtok_s(entry + 1, ",", &entry));
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


bool trace_graph_builder::run_external(MEM_ADDRESS targaddr, unsigned long repeats, NODEPAIR *resultPair)
{
	//start by examining our caller
	node_data *lastNode = thisgraph->safe_get_node(lastVertID);
	if (lastNode->external) return false;
	assert(lastNode->ins->numbytes);
	
	//if caller is also external then we are not interested in this
	if (!runRecord->activeMods.at(lastNode->globalModID))
		return false;

	ROUTINE_STRUCT *thisbb = 0;
	int modnum;
	bool found = runRecord->find_containing_module(targaddr, modnum);
	assert(found);
	piddata->get_extern_at_address(targaddr, modnum, &thisbb);
	assert(thisbb != NULL);

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
			targNode->currentCallIndex += repeats;
			lastVertID = targVertID;

			return true;
		}
		//else: thread has already called it, but from a different place
	}
	//else: thread hasn't called this function before

	piddata->dropExternCallerReadLock();

	lastNode->childexterns += 1;
	targVertID = (NODEINDEX)thisgraph->get_num_nodes();

	piddata->getExternCallerWriteLock();

	//has this thread executed this basic block before?
	auto callersIt = thisbb->thread_callers.find(thisgraph->get_TID());
	if (callersIt == thisbb->thread_callers.end())
	{
		EDGELIST callervec;
		//cout << "add extern addr " << std::hex<<  targaddr << " mod " << std::dec << modnum << endl;
		callervec.push_back(make_pair(lastVertID, targVertID));
		thisbb->thread_callers.emplace(TID, callervec);
	}
	else
		callersIt->second.push_back(make_pair(lastVertID, targVertID));

	piddata->dropExternCallerWriteLock();

	int module = thisbb->globalmodnum;

	//make new external/library call node
	node_data newTargNode;
	newTargNode.globalModID = module;
	newTargNode.external = true;
	newTargNode.address = targaddr;
	newTargNode.index = targVertID;
	newTargNode.parentIdx = lastVertID;
	newTargNode.executionCount = 1;

	thisgraph->insert_node(targVertID, newTargNode); //this invalidates all node_data* pointers
	lastNode = &newTargNode;

	*resultPair = std::make_pair(lastVertID, targVertID);

	piddata->getExternDictWriteLock();
	piddata->externdict.insert(make_pair(targaddr, thisbb));
	piddata->dropExternDictWriteLock();




	edge_data newEdge;
	newEdge.chainedWeight = 0;
	newEdge.edgeClass = eEdgeLib;
	thisgraph->add_edge(newEdge, thisgraph->safe_get_node(lastVertID), thisgraph->safe_get_node(targVertID));
	//cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
	lastNodeType = eNodeExternal;
	lastVertID = targVertID;
	return true;
}

bool trace_graph_builder::lookup_extern_func_calls(MEM_ADDRESS called_function_address, EDGELIST &callEdges)
{
	piddata->getExternDictReadLock();
	piddata->getExternCallerReadLock();

	map<MEM_ADDRESS, ROUTINE_STRUCT*>::iterator externIt;
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
void trace_graph_builder::process_new_args()
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

			thisgraph->externCallsLock.lock();
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
			thisgraph->externCallsLock.unlock();

			++callEdgeIt;
		}
		if (pendingCallArgIt->second.empty())
			pendingCallArgIt = pendingcallargs.erase(pendingCallArgIt);
		else
			++pendingCallArgIt;
	}
}

//#define VERBOSE
void trace_graph_builder::handle_exception_tag(TAG *thistag)
{
#ifdef VERBOSE
	cout << "handling tag 0x" << thistag->blockaddr << " jmpmod:" << thistag->jumpModifier;
	if (thistag->jumpModifier == 2)
		cout << " - sym: " << piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr];
	cout << endl;
#endif
	if (thistag->jumpModifier == INSTRUMENTED_CODE)
	{
		run_faulting_BB(thistag);

		thisgraph->totalInstructions += thistag->insCount;

		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag->jumpModifier == UNINSTRUMENTED_CODE) //call to (uninstrumented) external library
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
		cerr << "[rgat]Error: Bad jump tag while handling exception" << endl;
		assert(0);
	}
}

//#define VERBOSE
void trace_graph_builder::handle_tag(TAG *thistag, unsigned long repeats = 1)
{
#ifdef VERBOSE
	cout << "handling tag 0x"<<std::hex<< thistag->blockaddr <<std::dec
		<< " jmpmod:" << thistag->jumpModifier << " inscount:"<<thistag->insCount << " repeats:"<<repeats;
	//if (thistag->jumpModifier == 2)
	//	cout << " - sym: "<< piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr];
	cout << endl;
#endif
	if (thistag->jumpModifier == INSTRUMENTED_CODE)
	{
		runBB(thistag, repeats);
		thisgraph->totalInstructions += thistag->insCount*repeats;
		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag->jumpModifier == UNINSTRUMENTED_CODE)
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



//updates graph entry for each tag in the trace loop cache
void trace_graph_builder::dump_loop()
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

		int module;
		if (runRecord->find_containing_module(animUpdate.blockAddr, module) == UNINSTRUMENTED_CODE)
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

/*
//todo: move this to piddata class
INSLIST *trace_graph_builder::find_block_disassembly(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID)
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
*/

void trace_graph_builder::satisfy_pending_edges()
{
	vector<NEW_EDGE_BLOCKDATA>::iterator pendIt = pendingEdges.begin();
	while (pendIt != pendingEdges.end())
	{
		if (piddata->blockList.size() <= pendIt->sourceID) {
			++pendIt;
			continue;
		}
		INSLIST *source = piddata->blockList.at(pendIt->sourceID).second->inslist;

		
		if (piddata->blockList.size() <= pendIt->targID) {
			++pendIt;
			continue;
		}
		assert(piddata->blockList.at(pendIt->targID).second->blockType == eBlockInternal);
		INSLIST *targ = piddata->blockList.at(pendIt->targID).second->inslist;

		thisgraph->insert_edge_between_BBs(source, targ);
		pendIt = pendingEdges.erase(pendIt);

		//not sure what causes these to happen but haven't seen any get satisfied
		cout << "Satisfied an edge request!" << endl;
	}
}

//peforms non-sequence critical graph updates
//update nodes with cached execution counts and new edges from unchained runs
//also updates graph with delayed edge notifications
bool trace_graph_builder::assign_blockrepeats()
{
	lastRepeatUpdate = GetTickCount64();

	if (!pendingEdges.empty())
		satisfy_pending_edges();

	if (blockRepeatQueue.empty()) return true;

	vector<BLOCKREPEAT>::iterator repeatIt = blockRepeatQueue.begin();
	while (repeatIt != blockRepeatQueue.end())
	{
		//first find the blocks instruction list
		BLOCK_IDENTIFIER blockID = repeatIt->blockID;
		node_data *n = 0;

		if(!repeatIt->blockInslist)
		{
			if (piddata->blockList.size() <= blockID) {
				++repeatIt; continue;
			}
			assert(piddata->blockList.at(blockID).second->blockType == eBlockInternal);
			repeatIt->blockInslist = piddata->blockList.at(blockID).second->inslist;

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
		vector<BLOCK_IDENTIFIER>::iterator targCallIDIt = repeatIt->targBlocks.begin();
		while (targCallIDIt != repeatIt->targBlocks.end())
		{
			
			if (piddata->blockList.size() <= *targCallIDIt)
			{
				//external libraries will not be found by find_block_disassembly, but will be handled by run_external
				//this notices it has been handled and drops it from pending list
				bool alreadyPresent = false;
				set<NODEINDEX>::iterator calledIt = n->outgoingNeighbours.begin();
				for (; calledIt != n->outgoingNeighbours.end(); ++calledIt)
					if (thisgraph->safe_get_node(*calledIt)->blockID == *targCallIDIt)
					{
						alreadyPresent = true;
						break;
					}

				if (alreadyPresent)
					targCallIDIt = repeatIt->targBlocks.erase(targCallIDIt);
				else
					++targCallIDIt;
	
				continue;
			}

			BLOCK_IDENTIFIER blockid = *targCallIDIt;
			assert(piddata->blockList.at(blockid).second->blockType == eBlockInternal);
			INSLIST* targetBlock = piddata->blockList.at(blockid).second->inslist;
			INS_DATA *firstIns = targetBlock->front();
			if (!firstIns->threadvertIdx.count(TID)) {
				++targCallIDIt; 
				cout << "block " <<dec << blockid << " addr " << hex << firstIns->address << " not on graph " << endl;
			continue; }

			targCallIDIt = repeatIt->targBlocks.erase(targCallIDIt);
		}

		if (repeatIt->targBlocks.empty())
			repeatIt = blockRepeatQueue.erase(repeatIt);
		else
			++repeatIt;
		
	}

	return blockRepeatQueue.empty();
}

void trace_graph_builder::add_unchained_update(char *entry)
{
	MEM_ADDRESS blockAddr;
	string block_ip_s = string(strtok_s(entry + 1, ",", &entry));
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

void trace_graph_builder::add_satisfy_update(char *entry)
{
	NEW_EDGE_BLOCKDATA edgeNotification;

	string s_ip_s = string(strtok_s(entry + 1, ",", &entry));
	if (!caught_stoull(s_ip_s, &edgeNotification.sourceAddr, 16)) assert(0);

	string s_ID_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(s_ID_s, &edgeNotification.sourceID, 16)) assert(0);

	string t_ip_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoull(t_ip_s, &edgeNotification.targAddr, 16)) assert(0);

	string t_ID_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(t_ID_s, &edgeNotification.targID, 16)) assert(0);

	pendingEdges.push_back(edgeNotification);
}

void trace_graph_builder::add_exception_update(char *entry)
{
	MEM_ADDRESS e_ip;
	string e_ip_s = string(strtok_s(entry + 1, ",", &entry));
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
	interruptedBlockTag.jumpModifier = INSTRUMENTED_CODE;
	handle_exception_tag(&interruptedBlockTag);

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimExecException;
	animUpdate.blockAddr = interruptedBlockTag.blockaddr;
	animUpdate.blockID = interruptedBlockTag.blockID;
	animUpdate.count = instructionsUntilFault;
	thisgraph->push_anim_update(animUpdate);
}

void trace_graph_builder::add_exec_count_update(char *entry)
{
	BLOCKREPEAT newRepeat;
	newRepeat.totalExecs = 0;

	string block_ID_string = string(strtok_s(entry + 1, ",", &entry));
	if (!caught_stoul(block_ID_string, &newRepeat.blockID, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << block_ID_string << endl;
		assert(0);
	}

	string executions_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stoul(executions_s, &newRepeat.totalExecs, 16)) {
		cerr << "[rgat]ERROR: BX handling execcount STOL: " << executions_s << endl;
		assert(0);
	}

	while (true)
	{
		if (!entry || !entry[0]) break;
		BLOCK_IDENTIFIER targblockID;
		string targ_ID_s = string(strtok_s(entry, ",", &entry));
		if (!caught_stoul(targ_ID_s, &targblockID, 16)) {
			cerr << "[rgat]ERROR: BX handling ID STOL: " << targblockID << endl;
			assert(0);
		}

		newRepeat.targBlocks.push_back(targblockID);
	}

	blockRepeatQueue.push_back(newRepeat);

	ANIMATIONENTRY animUpdate;
	animUpdate.entryType = eAnimUnchainedResults;
	animUpdate.blockAddr = newRepeat.blockaddr;
	animUpdate.blockID = newRepeat.blockID;
	animUpdate.count = newRepeat.totalExecs;
	thisgraph->push_anim_update(animUpdate);
}

void trace_graph_builder::add_unlinking_update(char *entry)
{
	MEM_ADDRESS sourceAddr;
	BLOCK_IDENTIFIER sourceID;
	unsigned long long id_count;

	string block_address_string = string(strtok_s(entry + 1, ",", &entry));
	if (!caught_stoull(block_address_string, &sourceAddr, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << block_address_string << endl;
		assert(0);
	}
	string block_id_count_string = string(strtok_s(entry, ",", &entry));
	id_count = stoll(block_id_count_string, 0, 16);
	sourceID = id_count >> 32;



	if (piddata->blockList.size() <= sourceID) {
		Sleep(50);
		if (die || thisgraph->terminated) return;
		cerr << "[rgat]ERROR: Failed to find UL source block: " << hex << sourceAddr << endl;
		assert(0);
	}
	assert(piddata->blockList.at(sourceID).second->blockType == eBlockInternal);
	INSLIST* lastBB = piddata->blockList.at(sourceID).second->inslist;
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

	block_id_count_string = string(strtok_s(entry, ",", &entry)); //string(entry);
	id_count = stoll(block_id_count_string, 0, 16);
	thistag.insCount = id_count & 0xffffffff;
	thistag.blockID = id_count >> 32;
	thistag.jumpModifier = INSTRUMENTED_CODE;
	handle_tag(&thistag);

	string targ2_s = string(strtok_s(entry, ",", &entry)); //string(entry);
	MEM_ADDRESS targ2;
	if (!caught_stoull(targ2_s, &targ2, 16)) {
		cerr << "[rgat]ERROR: BX handling addr STOL: " << targ2_s << endl;
		assert(0);
	}

	int modnum;
	if (runRecord->find_containing_module(targ2, modnum) == UNINSTRUMENTED_CODE)
	{
		ROUTINE_STRUCT* foundExtern = 0;
		piddata->get_extern_at_address(targ2, modnum, &foundExtern);

		bool targetFound = false;
		piddata->getExternCallerReadLock();
		map <PID_TID, EDGELIST>::iterator callerIt = foundExtern->thread_callers.find(TID);

		if (callerIt != foundExtern->thread_callers.end())
		{
			size_t num = foundExtern->thread_callers.at(TID).size();
			for (size_t i = 0; i < num; i++)
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
			{
				cerr << "[rgat]Warning: 0x" << std::hex << targ2 << " in " << piddata->modpaths.at(foundExtern->globalmodnum) << " not found. Heatmap accuracy may suffer." << endl;
			}
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
			which is not a problem. this happens in the nestedloops tests

			Could come up with a way to only warn if the thread continues (eg: if anything at all comes after this from the trace pipe).
			For now as it hasn't been a problem i've improvised by checking if we return to code after the BaseThreadInitThunk symbol, 
				but this is not reliable outside of my runtime environment
			*/

			ADDRESS_OFFSET offset = targ2 - runRecord->get_piddata()->modBounds.at(foundExtern->globalmodnum)->first;
			string sym;
			//i haven't added a good way of looking up the nearest symbol. this requirement should be rare, but if not it's a todo
			bool foundsym = false;
			for (int i = 0; i < 4096; i++)
			{
				if (piddata->get_sym(foundExtern->globalmodnum, offset - i, sym))
				{
					foundsym = true;
					break;
				}
			}
			if (!foundsym) sym = "Unknown Symbol";

			if (sym != "BaseThreadInitThunk")
			{
				cerr << "[rgat]Warning,  unseen code executed after a busy block. (Module: "
					<< piddata->modpaths.at(foundExtern->globalmodnum) << " +0x" << std::hex << offset << "): '" << sym << "'"<< endl;

				cerr << endl << "\t If this happened at a thread exit it is not a problem and can be ignored" << std::dec << endl;
			}
		}
		piddata->dropExternCallerReadLock();
	}

	ANIMATIONENTRY animUpdate;
	animUpdate.blockAddr = thistag.blockaddr;
	animUpdate.blockID = thistag.blockID;
	animUpdate.entryType = eAnimUnchainedDone;
	thisgraph->push_anim_update(animUpdate);
}

void trace_graph_builder::process_trace_tag(char *entry)
{

	TAG thistag;
	MEM_ADDRESS nextBlockAddress;

	thistag.blockID = stoull(strtok_s(entry + 1, ",", &entry), 0, 16);
	thistag.blockaddr = piddata->blockList.at(thistag.blockID).first;
	nextBlockAddress = stoull(strtok_s(entry, ",", &entry), 0, 16);

	thistag.jumpModifier = INSTRUMENTED_CODE; //todo enum
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
	if (nextBlockAddress == 0) return;

	int modnum;
	int modType = runRecord->find_containing_module(nextBlockAddress, modnum);
	if (modType == INSTRUMENTED_CODE) return;

	//modType could be known unknown here
	//in case of unknown, this waits until we know. hopefully rare.
	int attempts = 1;

	TAG externTag;
	externTag.jumpModifier = UNINSTRUMENTED_CODE;
	externTag.blockaddr = nextBlockAddress;

	if (loopState == BUILDING_LOOP)
		loopCache.push_back(externTag);
	else
	{
		handle_tag(&externTag);

		ANIMATIONENTRY animUpdate;
		animUpdate.blockAddr = nextBlockAddress;
		animUpdate.entryType = eAnimExecTag;
		animUpdate.blockID = -1;
		animUpdate.callCount = externFuncCallCounter[make_pair(thistag.blockaddr, thistag.blockID)]++;
		thisgraph->push_anim_update(animUpdate);
	}

	/*
	//this is most likely to be called and looping is rare - usually
	if (piddata->get_extern_at_address(nextBlockAddress, &thistag.foundExtern, attempts))
	{
		modType = UNINSTRUMENTED_CODE;

		//run a known external
	}
	else
	{
		//create a new external
	}
	*/
	return;
	//delete below here
	if (attempts++ > 10)
	{
		cerr << "[rgat] (tid:" << TID << " pid:" << runRecord->getPID() << ")Warning: Failing to find address " <<
			std::hex << nextBlockAddress << " in instrumented or external code. Block tag(addr: " <<
			thistag.blockaddr << " insQty: " << thistag.insCount << "id: " <<
			thistag.blockID << " modtype: " << modType << endl;
		Sleep(60);
	}

	if (modType == INSTRUMENTED_CODE) return;

	thistag.blockaddr = nextBlockAddress;
	thistag.jumpModifier = UNINSTRUMENTED_CODE;
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

void trace_graph_builder::process_loop_marker(char *entry)
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
void trace_graph_builder::main_loop()
{
	alive = true;

	unsigned long itemsDone = 0;

	string *message;
	clock_t backlogUpdateTimer = clock() + 1;
	while (true) //todo: 'killed'
	{
		clock_t timenow = clock();
		if (timenow > backlogUpdateTimer)
		{
			backlogUpdateTimer = timenow + 1;
			thisgraph->setBacklogOut(itemsDone);
			itemsDone = 0;
		}

		message = reader->get_message();
		if (!message)
		{
			assign_blockrepeats();
			Sleep(5);
			continue;
		}

		if (repeatsUpdateDue())
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
			char entrytag = entry[0];
			switch (entrytag)
			{
			case TRACE_TAG_MARKER:
				process_trace_tag((char *)entry.c_str());

				//not thrilled about this comparison being done for every tag but it's the cleanest place to put it
				//tempted to make process_trace_tag a function pointer and have it point to process_first_trace_tag initially
				if (thisgraph->exeModuleID == -1 && !thisgraph->nodeList.empty())
					thisgraph->assign_modpath();

				continue;

			case LOOP_MARKER:
				process_loop_marker((char *)entry.c_str());
				continue;

				//wrapped function arguments
			case ARG_MARKER:
				handle_arg((char *)entry.c_str(), entry.size());
				continue;

				//unchained ended - link last unchained block to new block
			case UNLINK_MARKER:
				add_unlinking_update((char *)entry.c_str());
				continue;

				//block unchaining notification
			case UNCHAIN_MARKER:
				add_unchained_update((char *)entry.c_str());
				continue;

				//block execution count + targets after end of unchained execution
			case EXECUTECOUNT_MARKER:
				add_exec_count_update((char *)entry.c_str());
				continue;

			case SATISFY_MARKER:
				add_satisfy_update((char *)entry.c_str());
				continue;

			case EXCEPTION_MARKER:
				add_exception_update((char *)entry.c_str());
				continue;

			default:
				cerr << "[rgat]ERROR: Trace handler TID " << dec << TID << " unhandled line " <<
					entry << " (" << entry.size() << " bytes)" << endl;
				assert(0);
			}
		}
	}

	int max = 10;
	while (max-- && !assign_blockrepeats())
		Sleep(5);

	if (!assign_blockrepeats())
	{
		cerr << "[rgat] WARNING: " << blockRepeatQueue.size() << " unsatisfied blocks! blocklist size: " << piddata->blockList.size() << endl;
		std::vector<BLOCKREPEAT>::iterator repeatIt = blockRepeatQueue.begin();
		for (; repeatIt != blockRepeatQueue.end(); ++repeatIt)
		{
			cerr << "\t Block ID: " << dec << repeatIt->blockID << " addr: "<< hex << piddata->blockList.at(repeatIt->blockID).second->inslist->front()->address <<  endl;
			cerr << "\t Targeted unavailable blocks: ";

			vector<BLOCK_IDENTIFIER>::iterator targIt = repeatIt->targBlocks.begin();
			for (; targIt != repeatIt->targBlocks.end(); ++targIt)
				cerr << std::dec<< "[ID " << *targIt << " addr: "<<hex<< piddata->blockList.at(*targIt).second->inslist->front()->address<<"] " << endl;
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

