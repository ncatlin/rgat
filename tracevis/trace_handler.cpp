#include "stdafx.h"
#include "trace_handler.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "traceStructs.h"
#include "b64.h"

bool thread_trace_handler::find_internal_at_address(long address, int attempts) {
	while (!piddata->disassembly.count(address))
	{
		Sleep(1);
		if (!attempts--) return false;
		printf("Sleeping until EXTERN %lx...\n", address);
	}
	return true;
}

bool thread_trace_handler::get_extern_at_address(long address, BB_DATA **BB, int attempts = 1) {
	obtainMutex(piddata->externDictMutex, 0, 1000);
	map<unsigned long, BB_DATA*>::iterator externIt = piddata->externdict.find(address);
	while (externIt == piddata->externdict.end())
	{
		if (!attempts--) { 
			dropMutex(piddata->externDictMutex, 0); 
			return false; 
		}
		dropMutex(piddata->externDictMutex, 0);
		Sleep(1);
		obtainMutex(piddata->externDictMutex, 0, 1000);
		externIt = piddata->externdict.find(address);
	}

	if(BB)
		*BB = externIt->second;
	dropMutex(piddata->externDictMutex, 0);
	return true;
}

void thread_trace_handler::insert_edge(edge_data e, NODEPAIR edgePair)
{
	thisgraph->add_edge(e, edgePair);
	if (e.weight > thisgraph->maxWeight)
		thisgraph->maxWeight = e.weight;
}

//checks if current thread has executed this instruction
bool thread_trace_handler::is_old_instruction(INS_DATA *instruction, unsigned int *vertIdx)
{
	obtainMutex(piddata->disassemblyMutex, 0, 100);
	unordered_map<int,int>::iterator vertIdIt = instruction->threadvertIdx.find(TID);
	dropMutex(piddata->disassemblyMutex, 0);
	if (vertIdIt != instruction->threadvertIdx.end())
	{
		*vertIdx = vertIdIt->second;
		return true;
	}
	else 
		return false;
}

void thread_trace_handler::update_conditional_state(unsigned long nextAddress)
{
	if (lastVertID)
	{
		node_data *lastNode = thisgraph->get_node(lastVertID);
		int lastNodeCondStatus = lastNode->conditional;
		if (lastNodeCondStatus & CONDPENDING)
		{
			bool alreadyTaken = lastNodeCondStatus & CONDTAKEN;
			bool alreadyFailed = lastNodeCondStatus & CONDFELLTHROUGH;

			if (!alreadyFailed && (nextAddress == lastNode->ins->condDropAddress))
			{
				lastNodeCondStatus |= CONDFELLTHROUGH;
				alreadyFailed = true;
			}

			if (!alreadyTaken && (nextAddress == lastNode->ins->condTakenAddress))
			{
				lastNodeCondStatus |= CONDTAKEN;
				alreadyTaken = true;
			}

			if (alreadyTaken && alreadyFailed)
				lastNodeCondStatus = CONDCOMPLETE;
			lastNode->conditional = lastNodeCondStatus;
		}
	}

}

void thread_trace_handler::handle_new_instruction(INS_DATA *instruction, int mutation, int bb_inslist_index)
{

	node_data thisnode;
	thisnode.ins = instruction;
	if (instruction->conditional) thisnode.conditional = CONDPENDING;

	targVertID = thisgraph->get_num_nodes();
	int a = 0, b = 0;
	int bMod = 0;

	//first instruction in bb,
	if (bb_inslist_index == 0 && lastRIPType == FIRST_IN_THREAD)
	{
			a = 0;
			b = 0;
	}

	if (lastRIPType != FIRST_IN_THREAD)
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
	thisnode.vcoord.bMod = bMod + (mutation*3);//helps spread out clashing mutations
	thisnode.index = targVertID;
	thisnode.ins = instruction;
	thisnode.address = instruction->address;
	thisnode.mutation = mutation;

	updateStats(a, b, bMod);
	usedCoords[a][b] = true;

	thisgraph->insert_node(targVertID, thisnode);

	obtainMutex(piddata->disassemblyMutex, 0, 100);
	instruction->threadvertIdx[TID] = targVertID;
	dropMutex(piddata->disassemblyMutex, 0);
}


void thread_trace_handler::increaseWeight(edge_data *edge, long executions)
{
	edge->weight += executions;
	if (edge->weight > thisgraph->maxWeight)
		thisgraph->maxWeight = edge->weight;
}

void thread_trace_handler::handle_existing_instruction(INS_DATA *instruction)
{
	obtainMutex(piddata->disassemblyMutex, 0, 100);
	targVertID = instruction->threadvertIdx.at(TID);
	dropMutex(piddata->disassemblyMutex, 0);
}

int thread_trace_handler::runBB(TAG *tag, int startIndex, int repeats = 1)
{
	unsigned int bb_inslist_index = 0;
	int firstMutation = -1;
	int mutation = -1;
	int numInstructions = tag->insCount;
	unsigned long startAddress = tag->blockaddr;
	unsigned long targetAddress = startAddress;

	for (int instructionIndex = 0; instructionIndex < numInstructions; instructionIndex++)
	{
		//conspicuous lack of mutation handling here
		//we could check this by looking at the mutation state of all members of the block
		INS_DATA *instruction = getLastDisassembly(targetAddress,tag->blockID, piddata->disassemblyMutex, &piddata->disassembly, &mutation);
		if (firstMutation == -1) firstMutation = mutation;

		//todo: ditch this?
		if (lastRIPType != FIRST_IN_THREAD)
		{
			if (!thisgraph->node_exists(lastVertID))
			{
				printf("\t\tFatal error last vert not found\n");
				assert(0);
			}
		}

		unsigned int existingVertID;
		//target vert already on this threads graph?
		bool alreadyExecuted = is_old_instruction(instruction, &existingVertID);
		if (alreadyExecuted)
			targVertID = existingVertID; 
		else 
			handle_new_instruction(instruction, mutation, bb_inslist_index);

		if (bb_inslist_index == startIndex && loopState == LOOP_START)
		{
			firstLoopVert = targVertID;
			loopState = LOOP_PROGRESS;
		}

		long nextAddress = instruction->address + instruction->numbytes;
		//again, 2 lookups here
		NODEPAIR edgeIDPair = make_pair(lastVertID, targVertID);
		edge_data *edged;
		if (thisgraph->edge_exists(edgeIDPair, &edged))
			increaseWeight(edged, repeats);

		else if (lastRIPType != FIRST_IN_THREAD)
		{
			edge_data newEdge;
			newEdge.weight = repeats; //todo: skip on first+last edge?
			
			if (lastRIPType == RETURN)
				newEdge.edgeClass = IRET;
			else if (!alreadyExecuted)
			{
				if (lastRIPType == CALL)
					newEdge.edgeClass = ICALL;
				else
					newEdge.edgeClass = INEW;
			}
			else
				newEdge.edgeClass = IOLD;

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
		targetAddress = nextAddress;
	}

	return firstMutation;
}

void thread_trace_handler::updateStats(int a, int b, int bMod) {
	if (abs(a) > thisgraph->maxA) thisgraph->maxA = abs(a);
	if (abs(b) > thisgraph->maxB) thisgraph->maxB = abs(b);
	if (bMod > thisgraph->bigBMod) thisgraph->bigBMod = bMod;
}

//takes position of a node as pointers
//performs an action (call,jump,etc), places new position in pointers
void thread_trace_handler::positionVert(int *pa, int *pb, int *pbMod, long address)
{
	int a = *pa;
	int b = *pb;
	int bMod = *pbMod;
	int clash = 0;

	switch (lastRIPType)
	{
	case AFTERRETURN:
		a = min(a - 20, -(thisgraph->maxA + 2));
		b += 7 * BMULT;
		break;

	case NONFLOW:
		{
			//is it a conditional jump being taken? -> fall through to jump
			//TODO: this tends to be a source of messy edge overlap
			node_data *lastNode = thisgraph->get_node(lastVertID);
			if (!lastNode->conditional || address != lastNode->ins->condTakenAddress)
			{
				bMod += 1 * BMULT;
				break;
			}
		}
	case JUMP:
		{
			a += JUMPA;
			b += JUMPB * BMULT;

			while (usedCoords[a][b])
			{
				a += JUMPA_CLASH;
				if (clash++ > 30)
					printf("\tWARNING: DENSE GRAPH CLASHES (JUMP)\n");
			}
			break;
		}
	case CALL:
		{
			b += CALLB * BMULT;

			while (usedCoords[a][b] == true)
			{
				a += CALLA_CLASH;
				b += CALLB_CLASH * BMULT;

				if (clash++ > 15)
					printf("\tWARNING: DENSE GRAPH CLASH (CALL)\n");
			}

			if (clash) a += CALLA_CLASH;
			break;
		}

	case RETURN:
		//still mulling over how to handle returns
		afterReturn = true;

		//previous externs handled same as previous returns
	case EXTERNAL:
		{
			int result = -1;
			vector<pair<long, int>>::iterator it;
			for (it = callStack.begin(); it != callStack.end(); ++it)
				if (it->first == address)
				{
					result = it->second;
					break;
				}

			if (result != -1)
			{
				VCOORD *caller = &thisgraph->get_node(result)->vcoord;
				a = caller->a + RETURNA_OFFSET;
				b = caller->b + RETURNB_OFFSET;
				bMod = caller->bMod;
				
				//may not have returned to the last item in the callstack
				//delete everything inbetween
				callStack.resize(it-callStack.begin());
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
				if (clash++ > 50)
					printf("\tWARNING: Dense graph clashes (RET)\n");
			}
			break;
		}
	default:
		if (lastRIPType != FIRST_IN_THREAD)
			printf("ERROR: Unknown Last RIP Type\n");
		break;
	}
	*pa = a;
	*pb = b;
	*pbMod = bMod;
	return;
}

void __stdcall thread_trace_handler::ThreadEntry(void* pUserData) {
	return ((thread_trace_handler*)pUserData)->TID_thread();
}

void thread_trace_handler::handle_arg(char * entry, size_t entrySize) {
	unsigned long funcpc, returnpc;
	string argidx_s = string(strtok_s(entry + 4, ",", &entry));
	int argpos;
	if (!caught_stoi(argidx_s, &argpos, 10)) {
		printf("handle_arg 3 STOL ERROR: %s\n", argidx_s.c_str());
		return;
	}

	string funcpc_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stol(funcpc_s, &funcpc, 16)) {
		printf("handle_arg 4 STOL ERROR: %s\n", funcpc_s.c_str());
		return;
	}

	string retaddr_s = string(strtok_s(entry, ",", &entry));
	if (!caught_stol(retaddr_s, &returnpc, 16)) {
		printf("handle_arg 5 STOL ERROR: %s\n", retaddr_s.c_str());
		return;
	}

	if (!pendingFunc) {
		pendingFunc = funcpc;
		pendingRet = returnpc;
		//node_data *targExtern = thisgraph->get_node(targVertID);
		printf("x");
	}

	string moreargs_s = string(strtok_s(entry, ",", &entry));
	bool callDone = moreargs_s.at(0) == 'E' ? true : false;

	char b64Marker = strtok_s(entry, ",", &entry)[0];

	//todo: b64 decode
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
		map <unsigned long, vector<ARGLIST>> *newmap = new map <unsigned long, vector<ARGLIST>>;
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

int thread_trace_handler::run_external(unsigned long targaddr, unsigned long repeats, NODEPAIR *resultPair)
{
	//if parent calls multiple children, spread them out around caller
	//todo: can crash here if lastvid not in vd - only happned while pause debugging tho
	node_data *lastNode = thisgraph->get_node(lastVertID);
	assert(lastNode->ins->numbytes);

	//start by examining our caller
	
	int callerModule = lastNode->nodeMod;
	//if caller is external, not interested in this //todo: no longer happens
	if (piddata->activeMods[callerModule] == MOD_UNINSTRUMENTED) return -1;
	BB_DATA *thisbb = 0;
	do {
		get_extern_at_address(targaddr, &thisbb);
	} while (!thisbb);

	//see if caller already called this
	//if so, get the destination so we can just increase edge weight
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
			printf("runing extern, setting node:%d for address:%lx\n", targVertID, targNode->address);

			*resultPair = std::make_pair(vecit->first, vecit->second);
			increaseWeight(thisgraph->get_edge(*resultPair), repeats);
			targNode->calls += repeats;

			return 1;
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

	newTargNode.vcoord.a = lastnodec.a + 2 * parentExterns + 5;
	newTargNode.vcoord.b = lastnodec.b + parentExterns + 5;
	newTargNode.vcoord.bMod = lastnodec.bMod;
	newTargNode.external = true;
	newTargNode.address = targaddr;
	newTargNode.index = targVertID;
	newTargNode.parentIdx = lastVertID;

	//BB_DATA *thisnode_bbdata = 0;
	//get_extern_at_address(targaddr, &thisnode_bbdata);
	//unsigned long returnAddress = lastNode->ins->address + lastNode->ins->numbytes;

	thisgraph->insert_node(targVertID, newTargNode); //this invalidates lastnode
	lastNode = &newTargNode;

	obtainMutex(thisgraph->funcQueueMutex, "Push Externlist", 1200);
	thisgraph->externList.push_back(targVertID);
	dropMutex(thisgraph->funcQueueMutex, "Push Externlist");
	*resultPair = std::make_pair(lastVertID, targVertID);

	edge_data newEdge;
	newEdge.weight = repeats;
	newEdge.edgeClass = ILIB;
	insert_edge(newEdge, *resultPair);
	lastRIPType = EXTERNAL;
	return 1;
}

void thread_trace_handler::process_new_args()
{
	map<unsigned long, map <unsigned long, vector<ARGLIST>>>::iterator pcaIt = thisgraph->pendingcallargs.begin();
	while (pcaIt != thisgraph->pendingcallargs.end())
	{
		unsigned long funcad = pcaIt->first;
		obtainMutex(piddata->externDictMutex, 0, 1000);
		map<unsigned long, BB_DATA*>::iterator externIt;
		externIt = piddata->externdict.find(funcad);
		if (externIt == piddata->externdict.end() ||
			!externIt->second->thread_callers.count(TID)) {
			dropMutex(piddata->externDictMutex, 0);
			++pcaIt; 
			continue; 
		}

		EDGELIST callvs = externIt->second->thread_callers.at(TID);
		dropMutex(piddata->externDictMutex, 0);

		EDGELIST::iterator callvsIt = callvs.begin();
		while (callvsIt != callvs.end()) //run through each function with a new arg
		{
			node_data *parentn = thisgraph->get_node(callvsIt->first);
			//this breaks if call not used!
			unsigned long callerAddress = parentn->ins->address;

			if (get_extern_at_address(callerAddress, 0, 1))
				printf("\nEXTERN CALLED BY EXTERN, DELETE!\n");

			node_data *targn = thisgraph->get_node(callvsIt->second);

			map <unsigned long, vector<ARGLIST>>::iterator callersIt = pcaIt->second.begin();
			while (callersIt != pcaIt->second.end())//run through each caller to this function
			{
				if (callersIt->first != callerAddress) 
				{ printf("extern ret %lx not arg ret %lx\n", callersIt->first , callerAddress); callersIt++; continue; }

				vector<ARGLIST> callsvector = callersIt->second;
				vector<ARGLIST>::iterator callsIt = callsvector.begin();

				obtainMutex(thisgraph->funcQueueMutex, "FuncQueue Push Live", INFINITE);
				while (callsIt != callsvector.end())//run through each call made by caller
				{

					EXTERNCALLDATA ex;
					ex.edgeIdx = make_pair(parentn->index, targn->index);
					ex.nodeIdx = targn->index;
					ex.callerAddr = parentn->ins->address;
					ex.externPath = piddata->modpaths[piddata->externdict.at(funcad)->modnum];
					ex.fdata = *callsIt;

					assert(parentn->index != targn->index);
					thisgraph->funcQueue.push(ex);
					
					if (targn->funcargs.size() < MAX_ARG_STORAGE)
						targn->funcargs.push_back(*callsIt);
					callsIt = callsvector.erase(callsIt);
				}
				dropMutex(thisgraph->funcQueueMutex, "FuncQueue Push Live");
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
	printf("handling tag %lx, jmpmod:%d", thistag->blockaddr, thistag->jumpModifier);
	if (thistag->jumpModifier == 2)
		printf(" - sym: %s\n", piddata->modsyms[piddata->externdict[thistag->blockaddr]->modnum][thistag->blockaddr].c_str());
	else printf("\n");
#endif

	update_conditional_state(thistag->blockaddr);

	if (thistag->jumpModifier == INTERNAL_CODE)
	{

		int mutation = runBB(thistag, 0, repeats);

		if (!basicMode)
		{
			obtainMutex(thisgraph->animationListsMutex);
			thisgraph->bbsequence.push_back(make_pair(thistag->blockaddr, thistag->insCount));

			//could probably break this by mutating code in a running loop
			thisgraph->mutationSequence.push_back(mutation);
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

	else if (thistag->jumpModifier == EXTERNAL_CODE) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//find caller,external vertids if old + add node to graph if new
		NODEPAIR resultPair;
		int result = run_external(thistag->blockaddr, repeats, &resultPair);

		if (result)
		{
			obtainMutex(thisgraph->animationListsMutex, "Extern run", 1000);
			thisgraph->externCallSequence[resultPair.first].push_back(resultPair);
			dropMutex(thisgraph->animationListsMutex, "Extern run");
		}

		process_new_args();
		thisgraph->set_active_node(resultPair.second);
	}
	else
	{
		printf("handle_tag dead code assert");
		assert(0);
	}
}

//returns the module starting before and ending after the provided address
//if that's none of them, assume its a new code area in calling module
//TODO: this assumption is bad; any self modifying dll may cause problems
int thread_trace_handler::find_containing_module(unsigned long address)
{
	const int numModules = piddata->modBounds.size();
	for (int modNo = 0; modNo < numModules; ++modNo)
	{
		pair<unsigned long, unsigned long> *bounds = &piddata->modBounds.at(modNo);
		if (address >= bounds->first &&	address <= bounds->second)
		{
			if (piddata->activeMods.at(modNo) == MOD_ACTIVE) return MOD_ACTIVE;
			else return MOD_UNINSTRUMENTED;
		}
	}
	return MOD_UNKNOWN;
}

//updates graph entry for each tag in the trace loop cache
void thread_trace_handler::dump_loop()
{
	vector<TAG>::iterator tagIt;

	loopState = LOOP_START;

	if (loopCache.empty())
	{
		loopState = NO_LOOP;
		return;
	}

	++thisgraph->loopCounter;
	//put the verts/edges on the graph
	for (tagIt = loopCache.begin(); tagIt != loopCache.end(); ++tagIt)
		handle_tag(&*tagIt, loopCount);

	loopCache.clear();
	loopCount = 0;
	loopState = NO_LOOP;
}

//build graph for a thread as the trace data arrives from the reader thread
void thread_trace_handler::TID_thread()
{
	thisgraph = (thread_graph_data *)piddata->graphs[TID];
	thisgraph->tid = TID;
	thisgraph->pid = PID;

	char* msgbuf;
	unsigned long bytesRead;
	bool threadRunning = true;
	while (threadRunning)
	{
		thisgraph->traceBufferSize = reader->get_message(&msgbuf, &bytesRead);
		if (bytesRead == 0) {
			Sleep(1);
			continue;
		}

		if (bytesRead == -1)
		{
			dump_loop();
			timelinebuilder->notify_tid_end(PID, TID);
			thisgraph->active = false;
			thisgraph->terminated = true;
			thisgraph->emptyArgQueue();
			thisgraph->needVBOReload_preview = true;
			return;
		}

		char *next_token = msgbuf;
		while (true)
		{
			if (die) break;

			if (next_token >= msgbuf + bytesRead) break;
			char *entry = strtok_s(next_token, "@", &next_token);
			if (!entry) break;

			if (entry[0] == TRACE_TAG_MARKER)
			{
				TAG thistag;

				thistag.blockaddr = stol(strtok_s(entry + 1, ",", &entry), 0, 16);
				unsigned long nextBlock = stol(strtok_s(entry, ",", &entry), 0, 16);
				unsigned long id_count = stoll(strtok_s(entry, ",", &entry), 0, 16);
				thistag.insCount = id_count & 0xffff;
				thistag.blockID = id_count >> 16;

				thistag.jumpModifier = INTERNAL_CODE;
				if (loopState == LOOP_START)
					loopCache.push_back(thistag);
				else
					handle_tag(&thistag);

				//fallen through/failed conditional jump
				if (nextBlock == 0) continue;

				int modType = find_containing_module(nextBlock);
				if (modType == MOD_ACTIVE) continue;

				bool external;
				if (modType == MOD_UNINSTRUMENTED)
					external = true;
				else
					external = false;

				//see if next block is external
				//this is our alternative to instrumenting *everything*
				//rarely called (hopefully)
				int attempts = 1;
				while (true)
				{
					if (get_extern_at_address(nextBlock, &thistag.foundExtern, attempts))
					{
						external = true;
						break;
					}
					if (find_internal_at_address(nextBlock, attempts)) break;
					++attempts;
				} 
				continue;
				if (!external) continue;
				
				thistag.blockaddr = nextBlock;
				thistag.jumpModifier = EXTERNAL_CODE;
				thistag.insCount = 0;

				int modu = thistag.foundExtern->modnum;

				if (loopState == LOOP_START)
					loopCache.push_back(thistag);
				else
					handle_tag(&thistag);

				continue;
			}

			if (entry[0] == LOOP_MARKER)
			{	
				if (entry[1] == LOOP_START_MARKER)
				{
					loopState = LOOP_START;
					string repeats_s = string(strtok_s(entry+2, ",", &entry));
					if (!caught_stol(repeats_s, &loopCount, 10))
						printf("1 STOL ERROR: %s\n", repeats_s.c_str());
					continue;
				}

				else if (entry[1] == LOOP_END_MARKER) 
				{
					dump_loop();
					continue;
				}

				printf("ERROR: Fell through bad loop tag? [%s]\n",entry);
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
				unsigned long e_ip;
				string e_ip_s = string(strtok_s(entry + 4, ",", &entry));
				if (!caught_stol(e_ip_s, &e_ip, 16)) {
					printf("handle_arg 4 STOL ERROR: %s\n", e_ip_s.c_str());
					assert(0);
				}

				unsigned long e_code;
				string e_code_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stol(e_code_s, &e_code, 16)) {
					printf("handle_arg 4 STOL ERROR: %s\n", e_code_s.c_str());
					assert(0);
				}

				//TODO: place on graph. i'm thinking a yellow highlight line.
				printf("Target exception [code %lx] at address %lx\n", e_code, e_ip);
				continue;
			}

			printf("<TID THREAD %d> UNHANDLED LINE (%d b): %s\n", TID, bytesRead, msgbuf);
			if (next_token >= msgbuf + bytesRead) break;
		}
	}
	
}

