#include "stdafx.h"
#include "trace_handler.h"
#include "traceMisc.h"
#include "GUIConstants.h"


int thread_trace_handler::get_extern_at_address(long address, BB_DATA **BB) {

	//if (thisgraph->mutationMap.count(address)) {
	//	return thisgraph->mutationMap[address].back();
	//}

	BB_DATA* targbbptr = piddata->externdict[address];
	while (!targbbptr)
	{
		Sleep(100);
		printf("Sleeping until bbdict contains %lx\n", address);
		targbbptr = piddata->externdict[address];
	}


	BB_DATA *tempBB = targbbptr;
	*BB = tempBB;
	return 0;

}
void thread_trace_handler::insert_edge(edge_data e, pair<int,int> edgePair) 
{
	if (!obtainMutex(thisgraph->edMutex, "Insert Edge")) return;
	edgeDict->insert(make_pair(edgePair, e));
	auto x = edgeList->insert(edgeList->end(), edgePair);
	if (e.weight > thisgraph->maxWeight)
		thisgraph->maxWeight = e.weight;

	dropMutex(thisgraph->edMutex, "Insert Edge");
}

void thread_trace_handler::insert_vert(int targVertID, node_data thisNode)
{
	if (!obtainMutex(thisgraph->edMutex, "Insert Vert")) return;
	if (thisNode.index == 0)
		printf("INSERTED IDX VERT!\n");
	thisgraph->add_vert(make_pair(targVertID, thisNode));
	dropMutex(thisgraph->edMutex, "Insert Vert");
}

bool thread_trace_handler::new_instruction(INS_DATA *instruction)
{
	return (instruction->threadvertIdx.count(TID) == 0);
}

void thread_trace_handler::handle_new_instruction(INS_DATA *instruction, int bb_inslist_index, node_data *lastNode)
{
	node_data thisnode;
	thisnode.ins = instruction;
	if (instruction->conditional) thisnode.conditional = CONDUNUSED;

	targVertID = thisgraph->get_num_verts();
	int a, b, bMod = 0;

	//first instruction in bb,
	if (bb_inslist_index == 0)
	{
		if (lastRIPType == FIRST_IN_THREAD)
		{
			a = 0;
			b = 0;
		}
		else
		{
			//should now know if any previous conditional jump was taken
			//todo: why would last vertid not be in vertdict?
			int lastCondition = lastNode->conditional;
			if (conditionalTaken && thisgraph->get_num_verts() >= lastVertID)
			{
				long lastPC = lastNode->ins->address;
				if (conditionalTaken == lastPC)
				{
					lastRIPType = JUMP;
					if (lastCondition != NOTCONDITIONAL && (lastCondition & CONDTAKEN) == 0)
						lastNode->conditional |= CONDTAKEN;
				}
				else
					printf("\tWARNING: Condition taken notified but not for last instruction? Trace may be faulty!\n");
				conditionalTaken = 0;
			}
			else if (lastRIPType == NONFLOW)
			{
				bMod = lastNode->vcoord.bMod;
				if (lastCondition != NOTCONDITIONAL && (lastCondition & CONDNOTTAKEN) == 0)
					lastNode->conditional |= CONDNOTTAKEN;
			}
		}
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

	updateStats(a, b, bMod);
	usedCoords[a][b] = true;
	if (thisnode.index == 0)printf("iv1\n");
	insert_vert(targVertID, thisnode);

	instruction->threadvertIdx[TID] = targVertID;
}


void thread_trace_handler::increaseWeight(edge_data *edge, long executions)
{
	edge->weight += executions;
	if (edge->weight > thisgraph->maxWeight)
		thisgraph->maxWeight = edge->weight;
}

void thread_trace_handler::handle_existing_instruction(INS_DATA *instruction, node_data *lastNode)
{
	int lastCondition = lastNode->conditional;
	long lastInstruction = thisgraph->get_vert(lastVertID)->ins->address;
	if (conditionalTaken == lastInstruction)
	{
		if (lastCondition != NOTCONDITIONAL && (lastCondition & CONDNOTTAKEN) == 0)
			lastNode->conditional |= CONDNOTTAKEN;
	}
	else
		if (lastCondition != NOTCONDITIONAL && (lastCondition & CONDTAKEN) == 0)
			lastNode->conditional |= CONDTAKEN;

	targVertID = instruction->threadvertIdx[TID];
}

void thread_trace_handler::runBB(unsigned long startAddress, int startIndex,int numInstructions, int repeats = 1)
{
	unsigned int bb_inslist_index = 0;
	bool newVert;
	node_data *lastNode = 0;
	unsigned long targetAddress = startAddress;
	for (int instructionIndex = 0; instructionIndex < numInstructions; instructionIndex++)
	{
		INS_DATA *instruction = piddata->disassembly[targetAddress];
		long nextAddress = instruction->address + instruction->numbytes;

		if (lastRIPType != FIRST_IN_THREAD)
		{
			if (!thisgraph->vert_exists(lastVertID))
			{
				printf("\t\tFatal error last vert not found\n");
				return;
			}
			lastNode = thisgraph->get_vert(lastVertID);
			
		}
		newVert = new_instruction(instruction);
		if (newVert)
			handle_new_instruction(instruction, bb_inslist_index, lastNode);
		else //target vert already on this threads graph
			handle_existing_instruction(instruction, lastNode);
		//tmpThreadSave << std::hex << instruction->address << ":" << instruction->ins_text << "\n";
		
		if (bb_inslist_index == startIndex)
		{
			thisgraph->sequenceEdges.push_back(make_pair(lastVertID, targVertID));
			if (loopState == LOOP_START)
			{
				firstLoopVert = targVertID;
				loopState = LOOP_PROGRESS;
			}
		}
		pair<int, int> edgeIDPair = make_pair(lastVertID, targVertID);
		if (edgeDict->count(edgeIDPair))
		{
			increaseWeight(&edgeDict->at(edgeIDPair), repeats);
		}
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
	case NOJUMP:
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
				VCOORD *caller = &thisgraph->get_vert(result)->vcoord;
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

	pendingArgs.push_back(make_pair(argpos, contents));
	if (!callDone) return;

	BB_DATA* targbbptr = piddata->externdict[funcpc];
	while (!targbbptr)
	{
		Sleep(100);
		printf("Sleeping until basic_block_handler handles %lx\n", funcpc);
	}

	//func been called in thread already? if not, have to place args in holding buffer
	printf("Handling arg %s of function %s module %s\n",
		contents.c_str(),
		piddata->modsyms[targbbptr->modnum][pendingFunc].c_str(),
		piddata->modpaths[targbbptr->modnum].c_str());

	if (thisgraph->pendingcallargs.count(pendingFunc) == 0)
	{
		map <unsigned long, vector<vector<pair<int, string>>>> *newmap = new map <unsigned long, vector<vector<pair<int, string>>>>;
		thisgraph->pendingcallargs.emplace(pendingFunc, *newmap);
	}
	if (thisgraph->pendingcallargs.at(pendingFunc).count(pendingRet) == 0)
	{
		vector<vector<pair<int, string>>> *newvec = new vector<vector<pair<int, string>>>;
		thisgraph->pendingcallargs.at(pendingFunc).emplace(pendingRet, *newvec);
	}
		
	vector <pair<int, string>>::iterator pendcaIt = pendingArgs.begin();
	vector <pair<int, string>> thisCallArgs;
	for (; pendcaIt != pendingArgs.end(); pendcaIt++)
		thisCallArgs.push_back(*pendcaIt);

	thisgraph->pendingcallargs.at(funcpc).at(returnpc).push_back(thisCallArgs);

	pendingArgs.clear();
	pendingFunc = 0;
	pendingRet = 0;

	process_new_args();
	
	return;
}

int thread_trace_handler::run_external(unsigned long targaddr, unsigned long repeats, std::pair<int, int> *resultPair)
{
	//if parent calls multiple children, spread them out around caller
	//todo: can crash here if lastvid not in vd - only happned while pause debugging tho

	node_data *lastnode = thisgraph->get_vert(lastVertID);
	

	//start by examining our caller
	
	int callerModule = lastnode->nodeMod;
	//if caller is external, not interested in this
	if (piddata->activeMods[callerModule] == MOD_UNINSTRUMENTED) return -1;
	BB_DATA *thisbb = 0;
	//todo, check if this is always 0
	int assertZero = get_extern_at_address(targaddr, &thisbb);

	//see if caller already called this
	//if so, get the destination so we can just increase edge weight
	auto x = thisbb->thread_callers.find(TID);
	if (x != thisbb->thread_callers.end())
	{
		vector<pair<int, int>>::iterator vecit = x->second.begin();
		for (; vecit != x->second.end(); vecit++)
		{
			if (vecit->first != lastVertID) continue;

			//this instruction in this thread has already called it
			targVertID = vecit->second;
			node_data *targNode = thisgraph->get_vert(targVertID);

			*resultPair = std::make_pair(vecit->first, vecit->second);
			increaseWeight(&edgeDict->at(*resultPair), repeats);
			targNode->calls += repeats;

			return 1;
		}
		//else: thread has already called it, but from a different place
		
	}
	//else: thread hasnt called this function before

	lastnode->childexterns += 1;
	targVertID = thisgraph->get_num_verts();

	if (!thisbb->thread_callers.count(TID))
	{
		vector<pair<int, int>> callervec;
		callervec.push_back(make_pair(lastVertID, targVertID));
		thisbb->thread_callers.emplace(TID, callervec);
	}
	else
		thisbb->thread_callers.at(TID).push_back(make_pair(lastVertID, targVertID));
	
	int module = thisbb->modnum;

	//make new external/library call node
	node_data newTargNode;
	newTargNode.nodeMod = module;
	newTargNode.nodeSym = piddata->modsyms[module][targaddr];

	int parentExterns = thisgraph->get_vert(lastVertID)->childexterns;
	VCOORD lastnodec = thisgraph->get_vert(lastVertID)->vcoord;

	newTargNode.vcoord.a = lastnodec.a + 2 * parentExterns + 5;
	newTargNode.vcoord.b = lastnodec.b + parentExterns + 5;
	newTargNode.vcoord.bMod = lastnodec.bMod;
	newTargNode.external = true;
	newTargNode.address = targaddr;
	newTargNode.index = targVertID;
	newTargNode.parentIdx = lastVertID;

	BB_DATA *thisnode_bbdata = 0;
	int bbInsIndex = get_extern_at_address(targaddr, &thisnode_bbdata);

	insert_vert(targVertID, newTargNode);
	unsigned long returnAddress = lastnode->ins->address + lastnode->ins->numbytes;
	thisgraph->externList.push_back(make_pair(targVertID, returnAddress));

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
	//can we please do something about this
	map<unsigned long, map <unsigned long, vector<vector <pair<int, string>>>>>::iterator pcaIt = thisgraph->pendingcallargs.begin();
	while (pcaIt != thisgraph->pendingcallargs.end())
	{
		unsigned long funcad = pcaIt->first;
		if (!piddata->externdict.at(funcad)->thread_callers.count(TID)) { pcaIt++; continue; }

		vector<pair<int, int>> callvs = piddata->externdict.at(funcad)->thread_callers.at(TID);
		vector<pair<int, int>>::iterator callvsIt = callvs.begin();
		while (callvsIt != callvs.end()) //run through each function with a new arg
		{
			node_data *parentn = thisgraph->get_vert(callvsIt->first);
			unsigned long returnAddress = parentn->ins->address + parentn->ins->numbytes;
			node_data *targn = thisgraph->get_vert(callvsIt->second);

			map <unsigned long, vector<vector <pair<int, string>>>>::iterator retIt = pcaIt->second.begin();
			while (retIt != pcaIt->second.end())//run through each caller to this function
			{
				if (retIt->first != returnAddress) {retIt++; continue;}

				vector<vector<pair<int, string>>> callsvector = retIt->second;
				vector<vector<pair<int, string>>>::iterator callsIt = callsvector.begin();

				obtainMutex(thisgraph->funcQueueMutex, "FuncQueue Push Live", INFINITE);
				while (callsIt != callsvector.end())//run through each call made by caller
				{
					EXTERNCALLDATA ex;
					ex.edgeIdx = make_pair(parentn->index, targn->index);
					ex.nodeIdx = targn->index;
					ex.fdata = *callsIt;
					
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
	if (thistag.jumpModifier == INTERNAL_CODE)
	{
		INS_DATA* firstins = piddata->disassembly[thistag.targaddr];
		if (piddata->activeMods[firstins->modnum] == MOD_ACTIVE)
		{
			runBB(thistag.targaddr, 0, thistag.insCount, repeats);
			thisgraph->totalInstructions += thistag.insCount;
			thisgraph->bbsequence.push_back(make_pair(thistag.targaddr, thistag.insCount));
			if (repeats == 1)
				thisgraph->loopStateList.push_back(make_pair(0, 0xbad)); 
			else
				thisgraph->loopStateList.push_back(make_pair(thisgraph->loopCounter, loopCount));
		}
		return;
	}

	else if (thistag.jumpModifier == EXTERNAL_CODE) //call to (uninstrumented) external library
	{
		if (!lastVertID) return;

		//caller,external vertids
		std::pair<int, int> resultPair;
		//add node to graph if new
		int result = run_external(thistag.targaddr, repeats, &resultPair);
		if (result) thisgraph->externCallSequence[resultPair.first].push_back(resultPair);

		process_new_args();
		return;
	}
	else
	{
		printf("ERROR: BAD JUMP MODIFIER\n CORRUPT TRACE\n");
		return;
	}
}

//thread handler to build graph for a thread
void thread_trace_handler::TID_thread()
{
	thisgraph = (thread_graph_data *)piddata->graphs[TID];
	thisgraph->tid = TID;
	thisgraph->pid = PID;
	//vertDict = &thisgraph->vertDict;
	edgeDict = &thisgraph->edgeDict;
	edgeList = &thisgraph->edgeList;

	stringstream filename;
	filename << "C:\\tracing\\" << TID << ".txt";
	//tmpThreadSave.open(filename.str(), std::ofstream::binary);

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
			else
				printf("\t Thread %d - pipe read failure [thread exit? -closing handler]------------\n",TID);
			timelinebuilder->notify_tid_end(PID, TID);
			thisgraph->active = false;
			thisgraph->terminated = true;
			tmpThreadSave.close();
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
				string jtarg(entry+3);
				if (!caught_stol(jtarg, &conditionalTaken, 16)) {
					printf("2 STOL ERROR: %s\n", jtarg.c_str());
				}
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

					unsigned long edgeIdx = thisgraph->sequenceEdges.size();

					//put the verts/edges on the graph
					for (tagIt = loopCache.begin(); tagIt != loopCache.end(); tagIt++)
					{
						handle_tag(*tagIt, loopCount);
						
					}

					loopCache.clear();
					loopState = NO_LOOP;
					thisgraph->loopCounter++;
					continue;
				}
			}

			string enter_s = string(entry);
			if (enter_s.substr(0, 3) == "ARG")
			{
				handle_arg(entry, bytesRead);
				continue;
			}

			printf("<TID THREAD %d> UNHANDLED LINE (%d b): %s\n", TID, bytesRead, buf);
			if (next_token >= buf + bytesRead) break;
		}
	}
}

