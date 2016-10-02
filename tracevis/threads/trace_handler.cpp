/*
Copyright 2016 Nia Catlin

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
Header for the thread that builds a graph for each trace
*/
#include "stdafx.h"
#include "trace_handler.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "traceStructs.h"
#include "b64.h"
#include "OSspecific.h"

bool thread_trace_handler::find_internal_at_address(MEM_ADDRESS address, int attempts)
{
	while (!piddata->disassembly.count(address))
	{
		Sleep(1);
		if (!attempts--) return false;
	}
	return true;
}

bool thread_trace_handler::get_extern_at_address(MEM_ADDRESS address, BB_DATA **BB, int attempts = 1) {
	obtainMutex(piddata->externDictMutex, 1041);
	map<MEM_ADDRESS, BB_DATA*>::iterator externIt = piddata->externdict.find(address);
	while (externIt == piddata->externdict.end())
	{
		if (!attempts--) { 
			dropMutex(piddata->externDictMutex); 
			return false; 
		}
		dropMutex(piddata->externDictMutex);
		Sleep(1);
		obtainMutex(piddata->externDictMutex, 1042);
		externIt = piddata->externdict.find(address);
	}

	if(BB)
		*BB = externIt->second;
	dropMutex(piddata->externDictMutex);
	return true;
}

void thread_trace_handler::insert_edge(edge_data e, NODEPAIR edgePair)
{
	thisgraph->add_edge(e, edgePair);
	if (e.weight > thisgraph->maxWeight)
		thisgraph->maxWeight = e.weight;
}

//takes an instruction as input
//returns whether current thread has executed this instruction, places its vert in vertIdxOut
bool thread_trace_handler::set_target_instruction(INS_DATA *instruction)
{
	obtainMutex(piddata->disassemblyMutex, 1043);
	unordered_map<int,int>::iterator vertIdIt = instruction->threadvertIdx.find(TID);
	dropMutex(piddata->disassemblyMutex);

	if (vertIdIt != instruction->threadvertIdx.end())
	{
		targVertID = vertIdIt->second;
		return true;
	}
	else 
		return false;
}

//update conditional taken/failed status of lastNode now we know the address it is going to
void thread_trace_handler::update_conditional_state(MEM_ADDRESS nextAddress)
{
	if (!thisgraph->get_num_nodes()) return;

	node_data *lastNode = thisgraph->get_node(lastVertID);
	int lastNodeCondStatus = lastNode->conditional;
	if (lastNodeCondStatus & CONDPENDING)
	{
		bool everTaken = lastNodeCondStatus & CONDTAKEN;
		bool everFailed = lastNodeCondStatus & CONDFELLTHROUGH;

		if (!everFailed && (nextAddress == lastNode->ins->condDropAddress))
		{
			lastNodeCondStatus |= CONDFELLTHROUGH;
			everFailed = true;
		}

		if (!everTaken && (nextAddress == lastNode->ins->condTakenAddress))
		{
			lastNodeCondStatus |= CONDTAKEN;
			everTaken = true;
		}

		if (everTaken && everFailed)
			lastNodeCondStatus = CONDCOMPLETE;
		lastNode->conditional = lastNodeCondStatus;
	}
}

//creates a node for a newly excecuted instruction
void thread_trace_handler::handle_new_instruction(INS_DATA *instruction, BLOCK_IDENTIFIER blockID)
{

	node_data thisnode;
	thisnode.ins = instruction;
	if (instruction->conditional) thisnode.conditional = CONDPENDING;

	targVertID = thisgraph->get_num_nodes();
	int a = 0, b = 0;
	int bMod = 0;

	
	if (lastRIPType == FIRST_IN_THREAD)
	{	
		a = 0;
		b = 0;
	}
	else
	{
		node_data *lastNode = thisgraph->get_node(lastVertID);
		VCOORD lastnodec = lastNode->vcoord;
		a = lastnodec.a;
		b = lastnodec.b;
		bMod = lastnodec.bMod;

		if (afterReturn)
		{
			lastRIPType = AFTERRETURN;
			afterReturn = false;
		}
		//place vert on sphere based on how we got here
		positionVert(&a, &b, &bMod, thisnode.ins->address);

	}

	thisnode.vcoord.a = a;
	thisnode.vcoord.b = b;
	thisnode.vcoord.bMod = bMod;// +(mutation * 3);//helps spread out clashing mutations
	thisnode.index = targVertID;
	thisnode.ins = instruction;
	thisnode.address = instruction->address;
	thisnode.mutation = blockID;

	updateStats(a, b, bMod);
	usedCoords[a][b] = true;

	if (thisgraph->node_exists(targVertID))
		assert(0);
	thisgraph->insert_node(targVertID, thisnode);

	obtainMutex(piddata->disassemblyMutex, 1044);
	instruction->threadvertIdx[TID] = targVertID;
	dropMutex(piddata->disassemblyMutex);
}


void thread_trace_handler::increaseWeight(edge_data *edge, unsigned long executions)
{
	edge->weight += executions;
	if (edge->weight > thisgraph->maxWeight)
		thisgraph->maxWeight = edge->weight;
}

void thread_trace_handler::handle_existing_instruction(INS_DATA *instruction)
{
	obtainMutex(piddata->disassemblyMutex, 1045);
	targVertID = instruction->threadvertIdx.at(TID);
	dropMutex(piddata->disassemblyMutex);
}

void thread_trace_handler::runBB(TAG *tag, int startIndex, int repeats = 1)
{
	int numInstructions = tag->insCount;
	INSLIST *block = getDisassemblyBlock(tag->blockaddr, tag->blockID, piddata->disassemblyMutex, &piddata->blocklist, &die);

	for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
	{

		if (piddata->should_die()) return;
		INS_DATA *instruction = block->at(instructionIndex);

		if (lastRIPType != FIRST_IN_THREAD && !thisgraph->node_exists(lastVertID))
		{
			cerr << "\t\t[rgat]ERROR: RunBB- Last vert " << lastVertID << " not found" << endl;
			assert(0);
		}
		
		//target vert already on this threads graph?
		bool alreadyExecuted = set_target_instruction(instruction);
		if (!alreadyExecuted)
			handle_new_instruction(instruction, tag->blockID);

		if (loopState == BUILDING_LOOP)
		{
			firstLoopVert = targVertID;
			loopState = LOOP_PROGRESS;
		}

		MEM_ADDRESS nextAddress = instruction->address + instruction->numbytes;
		NODEPAIR edgeIDPair = make_pair(lastVertID, targVertID);
		edge_data *oldEdge;

		if (thisgraph->edge_exists(edgeIDPair, &oldEdge))
			increaseWeight(oldEdge, repeats);
		else 
			if (lastRIPType != FIRST_IN_THREAD)
			{
				edge_data newEdge;
				newEdge.weight = repeats;
			
				if (lastRIPType == RETURN)
					newEdge.edgeClass = IRET;
				else 
					if (alreadyExecuted)
						newEdge.edgeClass = IOLD;
					else
					{
						if (lastRIPType == CALL)
							newEdge.edgeClass = ICALL;
						else
							newEdge.edgeClass = INEW;
					}						

				insert_edge(newEdge, edgeIDPair);
			}

		//setup conditions for next instruction
		switch (instruction->itype)
		{
			case OPCALL: 
				{
					lastRIPType = CALL;

					//let returns find their caller if and only if they have one
					callStack.push_back(make_pair(nextAddress, lastVertID));
					break;
				}
				
			case OPJMP:
				lastRIPType = JUMP;
				break;

			case OPRET:
				lastRIPType = RETURN;
				break;

			default:
				lastRIPType = NONFLOW;
				break;
		}
		lastVertID = targVertID;
	}
}

//tracking how big the graph gets
void thread_trace_handler::updateStats(int a, int b, unsigned int bMod) 
{
	//the extra work of 2xabs() happens so rarely that its worth avoiding
	//the stack allocations of a variable every call
	if (abs(a) > thisgraph->maxA) thisgraph->maxA = abs(a);
	if (abs(b) > thisgraph->maxB) thisgraph->maxB = abs(b);
	if (bMod > thisgraph->bigBMod) thisgraph->bigBMod = bMod;
}

//takes position of a node as pointers
//performs an action (call,jump,etc), places new position in pointers
void thread_trace_handler::positionVert(int *pa, int *pb, int *pbMod, MEM_ADDRESS address)
{
	int a = *pa;
	int b = *pb;
	int bMod = *pbMod;
	int clash = 0;

	switch (lastRIPType)
	{
	/*
	The initial post-return node is placed near the caller on the stack.
	Makes a mess if we place whole block there, so this moves it farther away
	but it also means sequential instruction edges looking like jumps.
	Something for consideration
	*/
	case AFTERRETURN:
		a = min(a - 20, -(thisgraph->maxA + 2));
		b += 7 * BMULT;
		break;

	//small vertical distance between instructions in a basic block
	case NONFLOW:
		{
			//conditional jumps are assume non-flow control until their target is seen
			//if it's taken then fall through to jump
			node_data *lastNode = thisgraph->get_node(lastVertID);
			if (!lastNode->conditional || address != lastNode->ins->condTakenAddress)
			{
				bMod += 1 * BMULT;
				break;
			}
		}
	//long diagonal separation to show distinct basic blocks
	case JUMP:
		{
			a += JUMPA;
			b += JUMPB * BMULT;

			while (usedCoords[a][b])
			{
				a += JUMPA_CLASH;
				++clash;
			}

			if (clash > 15)
				cerr << "[rgat]WARNING: Dense Graph Clash (jump) - " << clash << " attempts" << endl;

			break;
		}
	//long purple line to show possible distinct functional blocks of the program
	case CALL:
		{
			b += CALLB * BMULT;

			while (usedCoords[a][b] == true)
			{
				a += CALLA_CLASH;
				b += CALLB_CLASH * BMULT;
				++clash;
			}

			if (clash)
			{
				a += CALLA_CLASH;
				if (clash > 15)
					cerr << "[rgat]WARNING: Dense Graph Clash (call) - " << clash <<" attempts"<<endl;
			}
			break;
		}

	case RETURN:
		afterReturn = true;
		//previous externs handled same as previous returns
	case EXTERNAL:
		{
			//returning to address in call stack?
			int result = -1;
			vector<pair<MEM_ADDRESS, int>>::iterator stackIt;
			for (stackIt = callStack.begin(); stackIt != callStack.end(); ++stackIt)
				if (stackIt->first == address)
				{
					result = stackIt->second;
					break;
				}

			//if so, position next node near caller
			if (result != -1)
			{
				VCOORD *caller = &thisgraph->get_node(result)->vcoord;
				a = caller->a + RETURNA_OFFSET;
				b = caller->b + RETURNB_OFFSET;
				bMod = caller->bMod;
				
				//may not have returned to the last item in the callstack
				//delete everything inbetween
				callStack.resize(stackIt-callStack.begin());
			}
			else
			{
				a += EXTERNA;
				b += EXTERNB * BMULT;
			}
		
			while (usedCoords[a][b])
			{
				a += JUMPA_CLASH;
				b += 1;
				++clash;
			}

			if (clash > 15)
				cerr << "[rgat]WARNING: Dense Graph Clash (extern) - " << clash << " attempts" << endl;
			break;
		}
	default:
		if (lastRIPType != FIRST_IN_THREAD)
			cerr << "[rgat]ERROR: Unknown Last RIP Type "<< lastRIPType << endl;
		break;
	}
	*pa = a;
	*pb = b;
	*pbMod = bMod;
	return;
}

//decodes argument and places in processing queue, processes if all decoded for that call
void thread_trace_handler::handle_arg(char * entry, size_t entrySize) {
	MEM_ADDRESS funcpc, returnpc;
	string argidx_s = string(strtok_s(entry + 4, ",", &entry));
	int argpos;
	if (!caught_stoi(argidx_s, &argpos, 10)) {
		cerr << "[rgat]ERROR: Trace corruption. handle_arg index int ERROR: " << argidx_s << endl;
		assert(0);
	}

	string funcpc_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stol(funcpc_s, &funcpc, 16)) {
		cerr << "[rgat]ERROR: Trace corruption. handle_arg funcpc address ERROR:" << funcpc_s << endl;
		assert(0);
	}

	string retaddr_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stol(retaddr_s, &returnpc, 16)) {
		cerr << "[rgat]ERROR:Trace corruption. handle_arg returnpc address ERROR: " << retaddr_s << endl;
		assert(0);
	}

	if (!pendingFunc) {
		pendingFunc = funcpc;
		pendingRet = returnpc;
	}

	string moreargs_s = string(strtok_s(entry, ",", &entry));
	bool callDone = moreargs_s.at(0) == 'E' ? true : false;
	char b64Marker = strtok_s(entry, ",", &entry)[0];

	string contents;
	if (entry < entry + entrySize)
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
	if (thisgraph->pendingcallargs.count(pendingFunc) == 0)
	{
		map <MEM_ADDRESS, vector<ARGLIST>> *newmap = new map <MEM_ADDRESS, vector<ARGLIST>>;
		thisgraph->pendingcallargs.emplace(pendingFunc, *newmap);
	}

	if (thisgraph->pendingcallargs.at(pendingFunc).count(pendingRet) == 0)
	{
		vector<ARGLIST> *newvec = new vector<ARGLIST>;
		thisgraph->pendingcallargs.at(pendingFunc).emplace(pendingRet, *newvec);
	}
		
	ARGLIST::iterator pendcaIt = pendingArgs.begin();
	ARGLIST thisCallArgs;
	for (; pendcaIt != pendingArgs.end(); pendcaIt++)
		thisCallArgs.push_back(*pendcaIt);

	thisgraph->pendingcallargs.at(pendingFunc).at(pendingRet).push_back(thisCallArgs);

	pendingArgs.clear();
	pendingFunc = 0;
	pendingRet = 0;

	process_new_args();
}


bool thread_trace_handler::run_external(MEM_ADDRESS targaddr, unsigned long repeats, NODEPAIR *resultPair)
{
	//start by examining our caller
	node_data *lastNode = thisgraph->get_node(lastVertID);
	assert(lastNode->ins->numbytes);
	
	int callerModule = lastNode->nodeMod;
	//if caller is also external, not interested in this
	if (piddata->activeMods[callerModule] == MOD_UNINSTRUMENTED) 
		return false;

	BB_DATA *thisbb = 0;
	while (!thisbb)
		get_extern_at_address(targaddr, &thisbb);

	//see if caller already called this
	//if so, get the destination node so we can just increase edge weight
	auto x = thisbb->thread_callers.find(TID);
	if (x != thisbb->thread_callers.end())
	{
		EDGELIST::iterator vecit = x->second.begin();
		for (; vecit != x->second.end(); ++vecit)
		{
			if (vecit->first != lastVertID) continue;

			//this instruction in this thread has already called it
			targVertID = vecit->second;
			node_data *targNode = thisgraph->get_node(targVertID);

			*resultPair = std::make_pair(vecit->first, vecit->second);
			increaseWeight(thisgraph->get_edge(*resultPair), repeats);
			targNode->calls += repeats;

			return true;
		}
		//else: thread has already called it, but from a different place
	}
	//else: thread hasnt called this function before

	lastNode->childexterns += 1;
	targVertID = thisgraph->get_num_nodes();
	//todo: check thread safety. crashes
	if (!thisbb->thread_callers.count(TID))
	{
		EDGELIST callervec;
		callervec.push_back(make_pair(lastVertID, targVertID));
		thisbb->thread_callers.emplace(TID, callervec);
	}
	else
		thisbb->thread_callers.at(TID).push_back(make_pair(lastVertID, targVertID));
	
	int module = thisbb->modnum;

	//make new external/library call node
	node_data newTargNode;
	newTargNode.nodeMod = module;

	int parentExterns = thisgraph->get_node(lastVertID)->childexterns;
	VCOORD lastnodec = thisgraph->get_node(lastVertID)->vcoord;

	//if parent calls multiple children, spread them out around caller
	newTargNode.vcoord.a = lastnodec.a + 2 * parentExterns + 5;
	newTargNode.vcoord.b = lastnodec.b + parentExterns + 5;
	newTargNode.vcoord.bMod = lastnodec.bMod;
	newTargNode.external = true;
	newTargNode.address = targaddr;
	newTargNode.index = targVertID;
	newTargNode.parentIdx = lastVertID;

	thisgraph->insert_node(targVertID, newTargNode); //this invalidates lastnode
	lastNode = &newTargNode;

	obtainMutex(thisgraph->funcQueueMutex, 1046);
	thisgraph->externList.push_back(targVertID);
	dropMutex(thisgraph->funcQueueMutex);
	*resultPair = std::make_pair(lastVertID, targVertID);

	edge_data newEdge;
	newEdge.weight = repeats;
	newEdge.edgeClass = ILIB;
	insert_edge(newEdge, *resultPair);
	lastRIPType = EXTERNAL;
	return true;
}

//places args for extern calls on screen and in storage if space
void thread_trace_handler::process_new_args()
{
	//function				caller		args
	map<MEM_ADDRESS, map <MEM_ADDRESS, vector<ARGLIST>>>::iterator pcaIt = thisgraph->pendingcallargs.begin();
	while (pcaIt != thisgraph->pendingcallargs.end())
	{
		MEM_ADDRESS funcad = pcaIt->first;

		obtainMutex(piddata->externDictMutex, 1047);
		map<MEM_ADDRESS, BB_DATA*>::iterator externIt;
		externIt = piddata->externdict.find(funcad);
		if (externIt == piddata->externdict.end() ||
			!externIt->second->thread_callers.count(TID)) {
			dropMutex(piddata->externDictMutex);
			++pcaIt; 
			continue; 
		}

		EDGELIST callvs = externIt->second->thread_callers.at(TID);
		dropMutex(piddata->externDictMutex);

		EDGELIST::iterator callvsIt = callvs.begin();
		while (callvsIt != callvs.end()) //run through each function with a new arg
		{
			node_data *parentn = thisgraph->get_node(callvsIt->first);
			//this breaks if call not used!
			MEM_ADDRESS callerAddress = parentn->ins->address;

			node_data *targn = thisgraph->get_node(callvsIt->second);

			map <MEM_ADDRESS, vector<ARGLIST>>::iterator callersIt = pcaIt->second.begin();
			while (callersIt != pcaIt->second.end())//run through each caller to this function
			{
				if (callersIt->first != callerAddress) 
				{ 
					++callersIt; 
					continue;
				}

				vector<ARGLIST> callsvector = callersIt->second;
				vector<ARGLIST>::iterator callsIt = callsvector.begin();

				obtainMutex(thisgraph->funcQueueMutex, 1048);
				while (callsIt != callsvector.end())//run through each call made by caller
				{

					EXTERNCALLDATA ex;
					ex.edgeIdx = make_pair(parentn->index, targn->index);
					ex.nodeIdx = targn->index;
					ex.callerAddr = parentn->ins->address;
					ex.externPath = piddata->modpaths.at(piddata->externdict.at(funcad)->modnum);
					ex.argList = *callsIt;

					assert(parentn->index != targn->index);
					thisgraph->floatingExternsQueue.push(ex);
					
					if (targn->funcargs.size() < arg_storage_capacity)
						targn->funcargs.push_back(*callsIt);
					callsIt = callsvector.erase(callsIt);
				}
				dropMutex(thisgraph->funcQueueMutex);
				callersIt->second.clear();

				if (callersIt->second.empty())
					callersIt = pcaIt->second.erase(callersIt);
				else
					callersIt++;
			}

			callvsIt++;
		}
		if (pcaIt->second.empty())
			pcaIt = thisgraph->pendingcallargs.erase(pcaIt);
		else
			++pcaIt;
	}
}

//#define VERBOSE
void thread_trace_handler::handle_tag(TAG *thistag, unsigned long repeats = 1)
{
#ifdef VERBOSE
	cout << "handling tag 0x"<< thistag->blockaddr << " jmpmod:" << thistag->jumpModifier;
	if (thistag->jumpModifier == 2)
		cout << " - sym: "<< piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr];
	cout << endl;
#endif

	update_conditional_state(thistag->blockaddr);

	if (thistag->jumpModifier == MOD_INSTRUMENTED)
	{

		runBB(thistag, 0, repeats);

		if (!basicMode)
		{
			//store for animation and replay
			obtainMutex(thisgraph->animationListsMutex, 1049);
			thisgraph->bbsequence.push_back(make_pair(thistag->blockaddr, thistag->insCount));
			thisgraph->mutationSequence.push_back(thistag->blockID);
			dropMutex(thisgraph->animationListsMutex);
		}

		if (repeats == 1)
		{
			thisgraph->totalInstructions += thistag->insCount;
			thisgraph->loopStateList.push_back(make_pair(0, 0xbad));
		}
		else
		{
			thisgraph->totalInstructions += thistag->insCount*loopCount;
			thisgraph->loopStateList.push_back(make_pair(thisgraph->loopCounter, loopCount));
		}
		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag->jumpModifier == MOD_UNINSTRUMENTED) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//find caller,external vertids if old + add node to graph if new
		NODEPAIR resultPair;
		if (run_external(thistag->blockaddr, repeats, &resultPair))
		{
			obtainMutex(thisgraph->animationListsMutex, 1050);
			thisgraph->externCallSequence[resultPair.first].push_back(resultPair);
			dropMutex(thisgraph->animationListsMutex);
		}

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
	const int numModules = piddata->modBounds.size();
	for (int modNo = 0; modNo < numModules; ++modNo)
	{
		pair<MEM_ADDRESS, MEM_ADDRESS> *moduleBounds = &piddata->modBounds.at(modNo);
		if (address >= moduleBounds->first && address <= moduleBounds->second)
		{
			if (piddata->activeMods.at(modNo) == MOD_INSTRUMENTED)
				return MOD_INSTRUMENTED;
			else 
				return MOD_UNINSTRUMENTED;
		}
	}
	return MOD_UNKNOWN;
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
	++thisgraph->loopCounter;

	vector<TAG>::iterator tagIt;
	//put the verts/edges on the graph
	for (tagIt = loopCache.begin(); tagIt != loopCache.end(); ++tagIt)
		handle_tag(&*tagIt, loopCount);

	loopCache.clear();
	loopCount = 0;
	loopState = NO_LOOP;
}

//build graph for a thread as the trace data arrives from the reader thread
void thread_trace_handler::main_loop()
{
	alive = true;
	ALLEGRO_TIMER *secondtimer = al_create_timer(1);
	ALLEGRO_EVENT_QUEUE *bench_timer_queue = al_create_event_queue();
	al_register_event_source(bench_timer_queue, al_get_timer_event_source(secondtimer));
	al_start_timer(secondtimer);
	unsigned long itemsDone = 0;

	char* msgbuf;
	unsigned long bytesRead;
	while (!die)
	{
		if (!al_is_event_queue_empty(bench_timer_queue))
		{
			al_flush_event_queue(bench_timer_queue);
			thisgraph->setBacklogOut(itemsDone);
			itemsDone = 0;
		}

		thisgraph->traceBufferSize = reader->get_message(&msgbuf, &bytesRead);
		if (!bytesRead) {
			Sleep(5);
			continue;
		}

		if (bytesRead == -1) //thread pipe closed
		{
			if (!loopCache.empty())
			{
				loopState = BUILDING_LOOP;
				dump_loop();
			}
			
			timelinebuilder->notify_tid_end(PID, TID);
			thisgraph->active = false;
			thisgraph->terminated = true;
			thisgraph->emptyArgQueue();
			thisgraph->needVBOReload_preview = true;
			alive = false;
			return;
		}

		++itemsDone;
		char *next_token = msgbuf;
		while (!die)
		{
			if (next_token >= msgbuf + bytesRead) break;
			char *entry = strtok_s(next_token, "@", &next_token);
			if (!entry) break;

			if (entry[0] == TRACE_TAG_MARKER)
			{
				TAG thistag;
				thistag.blockaddr = stol(strtok_s(entry + 1, ",", &entry), 0, 16);
				MEM_ADDRESS nextBlock = stol(strtok_s(entry, ",", &entry), 0, 16);
				UINT64 id_count = stoll(strtok_s(entry, ",", &entry), 0, 16);
				thistag.insCount = id_count & 0xffffffff;
				thistag.blockID = id_count >> 32;

				thistag.jumpModifier = MOD_INSTRUMENTED;
				if (loopState == BUILDING_LOOP)
					loopCache.push_back(thistag);
				else
					handle_tag(&thistag);

				//fallen through/failed conditional jump
				if (nextBlock == 0) continue;

				int modType = find_containing_module(nextBlock);
				if (modType == MOD_INSTRUMENTED) continue;

				//modType could be known unknown here
				//in case of unknown, this waits until we know. hopefully rare.
				int attempts = 1;
				while (!die)
				{
					//this is most likely to be called and looping is rare - usually
					if (get_extern_at_address(nextBlock, &thistag.foundExtern, attempts))
					{
						modType = MOD_UNINSTRUMENTED;
						break;
					}
					if (find_internal_at_address(nextBlock, attempts))
					{
						modType = MOD_INSTRUMENTED;
						break;
					}

					if (attempts++ >= 10)
					{
						cerr << "[rgat] (tid:"<<TID<<" pid:"<<PID<<")Warning: Failing to find address " << 
							std::hex << nextBlock <<" in instrumented or external code. Block tag(addr: " <<
							thistag.blockaddr <<" insQty: " << thistag.insCount << "id: " <<
							thistag.blockID << " modtype: " << modType << endl;
						Sleep(60);
					}
				} 

				if (modType == MOD_INSTRUMENTED) continue;
				
				thistag.blockaddr = nextBlock;
				thistag.jumpModifier = MOD_UNINSTRUMENTED;
				thistag.insCount = 0;

				if (loopState == BUILDING_LOOP)
					loopCache.push_back(thistag);
				else
					handle_tag(&thistag);

				continue;
			}

			if (entry[0] == LOOP_MARKER)
			{	
				if (entry[1] == LOOP_START_MARKER)
				{
					loopState = BUILDING_LOOP;
					string repeats_s = string(strtok_s(entry+2, ",", &entry));
					if (!caught_stol(repeats_s, &loopCount, 10))
						cerr << "[rgat]ERROR: Loop start STOL " << repeats_s << endl;
					continue;
				}

				else if (entry[1] == LOOP_END_MARKER) 
				{
					dump_loop();
					continue;
				}

				cerr << "[rgat] ERROR: Fell through bad loop tag?" << entry << endl;
				assert(0);
			}

			string enter_s = string(entry);
			if (enter_s.substr(0, 3) == "ARG")
			{
				handle_arg(entry, bytesRead);
				continue;
			}

			if (enter_s.substr(0, 3) == "EXC")
			{
				MEM_ADDRESS e_ip;
				string e_ip_s = string(strtok_s(entry + 4, ",", &entry));
				if (!caught_stol(e_ip_s, &e_ip, 16)) {
					
					assert(0);
				}

				unsigned long e_code;
				string e_code_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stol(e_code_s, &e_code, 16)) {
					cerr << "[rgat]ERROR: Exception handling STOL: " << e_code_s << endl;
					assert(0);
				}

				//TODO: place on graph. i'm thinking a yellow highlight line.
				cout << "[rgat]Exception detected in PID: " << PID << " TID: " << TID
					<< "[code " << std::hex << e_code << "] at address " << e_ip <<endl;
				continue;
			}

			cerr << "[rgat]ERROR: Trace handler TID " << TID << " unhandled line " << 
				msgbuf << " ("<<bytesRead<<" bytes)"<<endl;
			if (next_token >= msgbuf + bytesRead) break;
		}
	}

	thisgraph->terminationFlag = true;
	thisgraph->active = false;
	alive = false;
}

