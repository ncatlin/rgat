#include "stdafx.h"
#include "trace_handler.h"
#include "traceMisc.h"
#include "GUIConstants.h"
#include "traceStructs.h"

void thread_trace_handler::get_extern_at_address(long address, BB_DATA **BB) {

	while (!piddata->externdict.count(address))
	{
		Sleep(100);
		printf("Sleeping until bbdict contains %lx\n", address);
	}

	obtainMutex(piddata->externDictMutex, 0, 1000);
	*BB = piddata->externdict.at(address);
	dropMutex(piddata->externDictMutex, 0);
}

void thread_trace_handler::insert_edge(edge_data e, NODEPAIR edgePair)
{
	thisgraph->add_edge(e, edgePair);
	if (e.weight > thisgraph->maxWeight)
		thisgraph->maxWeight = e.weight;
}

bool thread_trace_handler::is_new_instruction(INS_DATA *instruction)
{
	obtainMutex(piddata->disassemblyMutex, 0, 100);
	bool result = instruction->threadvertIdx.count(TID) == 0;
	dropMutex(piddata->disassemblyMutex, 0);
	return result;
}


void thread_trace_handler::set_conditional_state(unsigned long address, int state)
{
	INS_DATA *instruction = getLastDisassembly(address, piddata->disassemblyMutex, &piddata->disassembly, 0);
	node_data *n = thisgraph->get_node(instruction->threadvertIdx[TID]);
	n->conditional |= state;

}

void thread_trace_handler::handle_new_instruction(INS_DATA *instruction, int mutation, int bb_inslist_index, node_data *lastNode)
{
	node_data thisnode;
	thisnode.ins = instruction;
	if (instruction->conditional) thisnode.conditional = CONDUNUSED;

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
	thisnode.vcoord.bMod = bMod;
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

void thread_trace_handler::handle_existing_instruction(INS_DATA *instruction, node_data *lastNode)
{
	obtainMutex(piddata->disassemblyMutex, 0, 100);
	targVertID = instruction->threadvertIdx.at(TID);
	dropMutex(piddata->disassemblyMutex, 0);
}

void thread_trace_handler::runBB(unsigned long startAddress, int startIndex,int numInstructions, int repeats = 1)
{
	unsigned int bb_inslist_index = 0;
	bool newVert;
	node_data *lastNode = 0;
	unsigned long targetAddress = startAddress;
	for (int instructionIndex = 0; instructionIndex < numInstructions; instructionIndex++)
	{
		//conspicuous lack of mutation handling here
		//we could check this by looking at the mutation state of all members of the block
		int mutation;
		INS_DATA *instruction = getLastDisassembly(targetAddress, piddata->disassemblyMutex, &piddata->disassembly, &mutation);

		long nextAddress = instruction->address + instruction->numbytes;

		if (lastRIPType != FIRST_IN_THREAD)
		{
			if (!thisgraph->node_exists(lastVertID))
			{
				printf("\t\tFatal error last vert not found\n");
				return;
			}
			lastNode = thisgraph->get_node(lastVertID);
		}

		newVert = is_new_instruction(instruction);
		if (newVert)
			handle_new_instruction(instruction, mutation, bb_inslist_index, lastNode);
		else //target vert already on this threads graph
			handle_existing_instruction(instruction, lastNode);

		if (bb_inslist_index == startIndex && loopState == LOOP_START)
		{
			firstLoopVert = targVertID;
			loopState = LOOP_PROGRESS;
		}

		NODEPAIR edgeIDPair = make_pair(lastVertID, targVertID);
		if (thisgraph->edge_exists(edgeIDPair))
			increaseWeight(thisgraph->get_edge(edgeIDPair), repeats);

		else if (lastRIPType != FIRST_IN_THREAD)
		{
			edge_data newEdge;
			newEdge.weight = repeats; //todo: skip on first+last edge?
			
			if (lastRIPType == RETURN)
				newEdge.edgeClass = IRET;
			else if (newVert) 
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
		bMod += 1 * BMULT;
		break;

	case JUMP:
		{
			a += JUMPA;
			b += JUMPB * BMULT;

			while (usedCoords[a][b] == true)
			{
				a += JUMPA_CLASH;
				if (clash++ > 15)
					printf("\tWARNING: JUMP MAXED\n");
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
					printf("\tWARNING: CALL MAXED\n");
			}

			if (clash) a += CALLA_CLASH;
			break;
		}
	case RETURN:
		afterReturn = true;
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
	}

	string moreargs_s = string(strtok_s(entry, ",", &entry));
	bool callDone = moreargs_s.at(0) == 'E' ? true : false;

	//todo: b64 decode
	string contents;
	if (entry < entry+entrySize)
		contents = string(entry).substr(0, entrySize - (size_t)entry);
	else
		contents = string("NULL");

	BB_DATA* targbbptr;
	get_extern_at_address(funcpc, &targbbptr);
	printf("Handling arg %s of function %s module %s\n",
		contents.c_str(),
		piddata->modsyms[targbbptr->modnum][funcpc].c_str(),
		piddata->modpaths[targbbptr->modnum].c_str());

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

	thisgraph->pendingcallargs.at(funcpc).at(returnpc).push_back(thisCallArgs);

	pendingArgs.clear();
	pendingFunc = 0;
	pendingRet = 0;

	process_new_args();
}

int thread_trace_handler::run_external(unsigned long targaddr, unsigned long repeats, NODEPAIR *resultPair)
{
	//if parent calls multiple children, spread them out around caller
	//todo: can crash here if lastvid not in vd - only happned while pause debugging tho

	node_data *lastnode = thisgraph->get_node(lastVertID);
	
	//start by examining our caller
	
	int callerModule = lastnode->nodeMod;
	//if caller is external, not interested in this
	if (piddata->activeMods[callerModule] == MOD_UNINSTRUMENTED) return -1;
	BB_DATA *thisbb = 0;
	get_extern_at_address(targaddr, &thisbb);

	//see if caller already called this
	//if so, get the destination so we can just increase edge weight
	auto x = thisbb->thread_callers.find(TID);
	if (x != thisbb->thread_callers.end())
	{
		EDGELIST::iterator vecit = x->second.begin();
		for (; vecit != x->second.end(); vecit++)
		{
			if (vecit->first != lastVertID) continue;

			//this instruction in this thread has already called it
			targVertID = vecit->second;
			node_data *targNode = thisgraph->get_node(targVertID);

			*resultPair = std::make_pair(vecit->first, vecit->second);
			increaseWeight(thisgraph->get_edge(*resultPair), repeats);
			targNode->calls += repeats;

			return 1;
		}
		//else: thread has already called it, but from a different place
		
	}
	//else: thread hasnt called this function before

	lastnode->childexterns += 1;
	targVertID = thisgraph->get_num_nodes();

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

	BB_DATA *thisnode_bbdata = 0;
	get_extern_at_address(targaddr, &thisnode_bbdata);

	thisgraph->insert_node(targVertID, newTargNode);
	unsigned long returnAddress = lastnode->ins->address + lastnode->ins->numbytes;
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
		if (!piddata->externdict.at(funcad)->thread_callers.count(TID)) { 
			dropMutex(piddata->externDictMutex, 0);
			//TODO: keep track of this. printf("Failed to find call for %lx in externdict\n", funcad);
			pcaIt++; continue; 
		}

		
		EDGELIST callvs = piddata->externdict.at(funcad)->thread_callers.at(TID);
		dropMutex(piddata->externDictMutex, 0);

		EDGELIST::iterator callvsIt = callvs.begin();
		while (callvsIt != callvs.end()) //run through each function with a new arg
		{
			node_data *parentn = thisgraph->get_node(callvsIt->first);
			unsigned long returnAddress = parentn->ins->address + parentn->ins->numbytes;
			node_data *targn = thisgraph->get_node(callvsIt->second);

			map <unsigned long, vector<ARGLIST>>::iterator retIt = pcaIt->second.begin();
			while (retIt != pcaIt->second.end())//run through each caller to this function
			{
				if (retIt->first != returnAddress) {retIt++; continue;}

				vector<ARGLIST> callsvector = retIt->second;
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
				retIt->second.clear();

				if (retIt->second.empty())
					retIt = pcaIt->second.erase(retIt);
				else
					retIt++;
			}

			callvsIt++;
		}
		if (pcaIt->second.empty())
			pcaIt = thisgraph->pendingcallargs.erase(pcaIt);
		else
			pcaIt++;
	}
}

void thread_trace_handler::handle_tag(TAG thistag, unsigned long repeats = 1)
{
	/*
	printf("handling tag %lx, jmpmod:%d", thistag.targaddr, thistag.jumpModifier);
	if (thistag.jumpModifier == 2)
		printf(" - sym: %s\n", piddata->modsyms[piddata->externdict[thistag.targaddr]->modnum][thistag.targaddr].c_str());
	else printf("\n");*/
	

	if (thistag.jumpModifier == INTERNAL_CODE)
	{
		int mutation = -1;
		INS_DATA* firstins = getLastDisassembly(thistag.targaddr, piddata->disassemblyMutex, &piddata->disassembly, &mutation);

		if (piddata->activeMods.at(firstins->modnum) == MOD_ACTIVE)
		{
			runBB(thistag.targaddr, 0, thistag.insCount, repeats);
		
			obtainMutex(thisgraph->animationListsMutex);
			thisgraph->bbsequence.push_back(make_pair(thistag.targaddr, thistag.insCount));

			//could probably break this by mutating code in a running loop
			thisgraph->mutationSequence.push_back(mutation); 
			dropMutex(thisgraph->animationListsMutex);

			if (repeats == 1)
			{
				thisgraph->totalInstructions += thistag.insCount;
				thisgraph->loopStateList.push_back(make_pair(0, 0xbad));
			}
			else
			{
				thisgraph->totalInstructions += thistag.insCount*loopCount;
				thisgraph->loopStateList.push_back(make_pair(thisgraph->loopCounter, loopCount));
			}
		}
		thisgraph->set_active_node(lastVertID);
	}

	else if (thistag.jumpModifier == EXTERNAL_CODE) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//caller,external vertids
		NODEPAIR resultPair;
		//add node to graph if new
		int result = run_external(thistag.targaddr, repeats, &resultPair);
		
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
		printf("ERROR: BAD JUMP MODIFIER 0x%x: CORRUPT TRACE?\n", thistag.jumpModifier);
		assert(0);
	}
}

//thread handler to build graph for a thread
void thread_trace_handler::TID_thread()
{
	thisgraph = (thread_graph_data *)piddata->graphs[TID];
	thisgraph->tid = TID;
	thisgraph->pid = PID;

	wstring pipename(L"\\\\.\\pipe\\rioThread");
	pipename.append(std::to_wstring(TID));
	wcout << "Opening tidpipe '" << pipename << "'" << endl;
	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		255, 64, 56 * 1024, 300, NULL);

	if ((int)hPipe == -1)
	{
		thisgraph->active = false;
		printf("Error: TIDTHREAD Handle:%d - error:%d\n", (int)hPipe, GetLastError());
		return;
	}

	ConnectNamedPipe(hPipe, NULL);
	char buf[TAGCACHESIZE] = { 0 };
	int PIDcount = 0;

	bool threadRunning = true;
	while (threadRunning)
	{
		DWORD bytesRead = 0;
		ReadFile(hPipe, buf, TAGCACHESIZE, &bytesRead, NULL);
		if (bytesRead == TAGCACHESIZE) {
			printf("\t\tERROR: THREAD READ CACHE EXCEEDED! [%s]\n",buf);
			threadRunning = false;
			break;
		}
		buf[bytesRead] = 0;
		buf[TAGCACHESIZE-1] = 0;

		if (!bytesRead)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				printf("thread %d pipe read ERROR: %d. [Closing handler]\n", TID, err);

			timelinebuilder->notify_tid_end(PID, TID);
			thisgraph->active = false;
			thisgraph->terminated = true;
			thisgraph->emptyArgQueue();
			return;
		}

		char *next_token = buf;
		while (true)
		{
			//todo: check if buf is sensible - suspicious repeats?
			if (next_token >= buf + bytesRead) break;
			char *entry = strtok_s(next_token, "@", &next_token);
			if (!entry) {
				printf("No trace data?");
				continue;
			}

			if (entry[0] == 'j')
			{
				TAG thistag;
				string jtarg = string(strtok_s(entry + 1, ",", &entry));
				if (!caught_stol(jtarg, &thistag.targaddr, 16)) {
					printf("1 STOL ERROR: %s\n", jtarg.c_str());
					continue;
				}

				string jmod_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stoi(jmod_s, &thistag.jumpModifier, 10)) {
					printf("1 STOL ERROR: %s\n", jmod_s.c_str());
					continue;
				}
		
				string jcount_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stoi(jcount_s, &thistag.insCount, 10)) {
					printf("1 STOL ERROR: %s\n", jcount_s.c_str());
					continue;
				}

				if (loopState == LOOP_START) {
					loopCache.push_back(thistag);
					continue;
				}

				handle_tag(thistag);
				continue;
			}

			//mark a conditional jump as taken
			if (entry[0] == 't' && entry[1] == 'j')
			{
				unsigned long conditionalAddr;
				string jtarg(entry+3);
				if (!caught_stol(jtarg, &conditionalAddr, 16)) {
					printf("tj STOL ERROR: %s\n", jtarg.c_str());
				}
				set_conditional_state(conditionalAddr, CONDTAKEN);
				continue;
			}

			//mark a conditional jump as not taken
			if (entry[0] == 'n' && entry[1] == 'j')
			{
				unsigned long conditionalAddr;
				string jtarg(entry + 3);
				if (!caught_stol(jtarg, &conditionalAddr, 16)) {
					printf("tj STOL ERROR: %s\n", jtarg.c_str());
				}
				set_conditional_state(conditionalAddr, CONDNOTTAKEN);
				continue;
			}

			//repeats/loop
			if (entry[0] == 'R')
			{	//loop start
				if (entry[1] == 'S')
				{
					loopState = LOOP_START;
					string repeats_s = string(strtok_s(entry+2, ",", &entry));
					if (!caught_stol(repeats_s, &loopCount, 10)) {
						printf("1 STOL ERROR: %s\n", repeats_s.c_str());
					}
					continue;
				}
				//loop end
				else if (entry[1] == 'E') 
				{
					vector<TAG>::iterator tagIt;
					
					loopState = LOOP_START;

					if (loopCache.empty())
					{
						loopState = NO_LOOP;
						continue;
					}

					thisgraph->loopCounter++;
					//put the verts/edges on the graph
					for (tagIt = loopCache.begin(); tagIt != loopCache.end(); tagIt++)
						handle_tag(*tagIt, loopCount);

					loopCache.clear();
					loopState = NO_LOOP;
					continue;
				}
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
					return;
				}

				unsigned long e_code;
				string e_code_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stol(e_code_s, &e_code, 16)) {
					printf("handle_arg 4 STOL ERROR: %s\n", e_code_s.c_str());
					return;
				}

				printf("Target exception [code %lx] at address %lx\n", e_code, e_ip);
				continue;
			}

			if (enter_s.substr(0, 3) == "BLK")
			{
				unsigned long funcpc;
				string funcpc_s = string(strtok_s(entry+4, ",", &entry));
				if (!caught_stol(funcpc_s, &funcpc, 16)) {
					printf("handle_arg 4 STOL ERROR: %s\n", funcpc_s.c_str());
					return;
				}

				unsigned long retpc;
				string retpc_s = string(strtok_s(entry, ",", &entry));
				if (!caught_stol(retpc_s, &retpc, 16)) {
					printf("handle_arg 4 STOL ERROR: %s\n", retpc_s.c_str());
					return;
				}

				//TODO? BB_DATA* extfunc = piddata->externdict.at(funcpc);
				//thisgraph->set_active_node(extfunc->thread_callers[TID])
				continue;
			}

			printf("<TID THREAD %d> UNHANDLED LINE (%d b): %s\n", TID, bytesRead, buf);
			if (next_token >= buf + bytesRead) break;
		}
	}
}

