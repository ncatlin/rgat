/*
Copyright 2017 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
* /

/*
Pre-graph data built from the trace
The final graphs (sphere, linear, etc are built using this data)
*/

#include "stdafx.h"
#include "proto_graph.h"
#include "thread_trace_reader.h"
#include "GUIConstants.h"


proto_graph::proto_graph(PROCESS_DATA *processdata, unsigned int threadID)
{
	piddata = processdata;
	tid = threadID;
}


proto_graph::~proto_graph()
{
	printf("Proto graph destroyed!\n");
}

//creates a node for a newly executed instruction
unsigned int proto_graph::handle_new_instruction(INS_DATA *instruction, BLOCK_IDENTIFIER blockID, unsigned long repeats)
{

	node_data thisnode;
	thisnode.ins = instruction;

	int targVertID = get_num_nodes();

	thisnode.index = targVertID;
	thisnode.ins = instruction;
	thisnode.conditional = thisnode.ins->conditional;
	thisnode.address = instruction->address;
	thisnode.blockID = blockID;
	thisnode.executionCount = repeats;

	assert(!node_exists(targVertID));
	insert_node(targVertID, thisnode);

	piddata->getDisassemblyWriteLock();
	instruction->threadvertIdx[tid] = targVertID;
	piddata->dropDisassemblyWriteLock();

	return targVertID;
}

void proto_graph::handle_previous_instruction(unsigned int newTargVertID, unsigned long repeats)
{
	safe_get_node(newTargVertID)->executionCount += repeats;
	// = newTargVertID;
}


void proto_graph::add_edge(edge_data e, node_data *source, node_data *target)
{
	NODEPAIR edgePair;
	edgePair.first = source->index;
	edgePair.second = target->index;

	getNodeWriteLock();

	source->outgoingNeighbours.insert(edgePair.second);
	if (source->conditional && (source->conditional != CONDCOMPLETE))
	{
		if (source->ins->condDropAddress == target->address)
			source->conditional |= CONDFELLTHROUGH;
		else if (source->ins->condTakenAddress == target->address)
			source->conditional |= CONDTAKEN;
	}

	target->incomingNeighbours.insert(edgePair.first);
	dropNodeWriteLock();

	getEdgeWriteLock();
	edgeDict.insert(make_pair(edgePair, e));
	edgeList.push_back(edgePair);
	dropEdgeWriteLock();
}

void proto_graph::insert_edge_between_BBs(INSLIST *source, INSLIST *target)
{
	INS_DATA *sourceIns = source->back();
	INS_DATA *targetIns = target->front();

	unsigned int sourceNodeIdx = sourceIns->threadvertIdx.at(tid);
	unsigned int targNodeIdx = targetIns->threadvertIdx.at(tid);

	NODEPAIR edgeNodes = make_pair(sourceNodeIdx, targNodeIdx);

	if (edgeDict.count(edgeNodes)) return;

	node_data *sourceNode = safe_get_node(sourceNodeIdx);
	node_data *targNode = safe_get_node(targNodeIdx);

	edge_data newEdge;

	if (targNode->external)
		newEdge.edgeClass = ILIB;
	else if (sourceNode->ins->itype == OPCALL)
		newEdge.edgeClass = ICALL;
	else if (sourceNode->ins->itype == OPRET)
		newEdge.edgeClass = IRET;
	else
		newEdge.edgeClass = IOLD;

	add_edge(newEdge, sourceNode, targNode);

}



//find the edge represented by pair of nodes 'edge'
//false if not found
//true if found + edge data placed in edged
bool proto_graph::edge_exists(NODEPAIR edge, edge_data **edged)
{

	getEdgeReadLock();
	EDGEMAP::iterator edgeit = edgeDict.find(edge);
	dropEdgeReadLock();

	if (edgeit == edgeDict.end()) 
		return false;

	if (edged)
		*edged = &edgeit->second;
	return true;
}

edge_data *proto_graph::get_edge_create(node_data *source, node_data *target)
{
	NODEPAIR edge;
	edge.first = source->index;
	edge.second = target->index;

	getEdgeReadLock();
	EDGEMAP::iterator edgeDIt = edgeDict.find(edge);
	dropEdgeReadLock();

	if (edgeDIt != edgeDict.end())
		return &edgeDIt->second;

	edge_data edgeData;
	edgeData.edgeClass = INEW; //TODO!
	edgeData.chainedWeight = 0;
	add_edge(edgeData, source, target);

	return &edgeDict.at(edge);
}

inline edge_data *proto_graph::get_edge(NODEPAIR edgePair)
{
	getEdgeReadLock();
	EDGEMAP::iterator edgeIt = edgeDict.find(edgePair);
	dropEdgeReadLock();

	if (edgeIt != edgeDict.end())
		return &edgeIt->second;
	else
		return 0;
}


inline void proto_graph::getEdgeReadLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(edMutex, 10001);
#else
	AcquireSRWLockShared(&edgeLock);
#endif
}

inline void proto_graph::getEdgeWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(edMutex, 10002);
#else
	AcquireSRWLockExclusive(&edgeLock);
#endif
}

inline void proto_graph::dropEdgeReadLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(edMutex);
#else
	ReleaseSRWLockShared(&edgeLock);
#endif
}

inline void proto_graph::dropEdgeWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(edMutex);
#else
	ReleaseSRWLockExclusive(&edgeLock);
#endif
}

inline void proto_graph::getNodeReadLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(nodeLMutex, 10005);
#else
	AcquireSRWLockShared(&nodeLock);
#endif
}

inline void proto_graph::dropNodeReadLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(nodeLMutex);
#else
	ReleaseSRWLockShared(&nodeLock);
#endif
}

inline void proto_graph::getNodeWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(nodeLMutex, 10006);
#else
	AcquireSRWLockExclusive(&nodeLock);
#endif
}

inline void proto_graph::dropNodeWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(nodeLMutex);
#else
	ReleaseSRWLockExclusive(&nodeLock);
#endif
}

//linker error if we make this inline too
edge_data * proto_graph::get_edge(unsigned int edgeindex)
{
	if (edgeindex >= edgeList.size()) return 0;

	getEdgeReadLock();
	EDGEMAP::iterator edgeIt = edgeDict.find(edgeList.at(edgeindex));
	dropEdgeReadLock();

	if (edgeIt != edgeDict.end())
		return &edgeIt->second;
	else
		return 0;

}

inline node_data *proto_graph::safe_get_node(unsigned int index)
{
	getNodeReadLock();
	node_data *n = &nodeList.at(index);
	dropNodeReadLock();
	return n;
}

//for when caller already has read/write lock
node_data *proto_graph::unsafe_get_node(unsigned int index)
{
	return &nodeList.at(index);
}

void proto_graph::set_active_node(unsigned int idx)
{
	if (nodeList.size() <= idx) return;
	getNodeWriteLock();
	latest_active_node_idx = idx;
	//latest_active_node_coord = unsafe_get_node(idx)->vcoord;
	dropNodeWriteLock();
}

void proto_graph::insert_node(NODEINDEX targVertID, node_data node)
{
	if (!nodeList.empty()) assert(targVertID == nodeList.back().index + 1);


	if (node.external)
	{
		obtainMutex(highlightsMutex, 5271);
		externList.push_back(node.index);
		dropMutex(highlightsMutex);
	}
	else if (node.ins->hasSymbol)
	{
		obtainMutex(highlightsMutex, 5272);
		internList.push_back(node.index);
		dropMutex(highlightsMutex);
	}

	getNodeWriteLock();
	nodeList.push_back(node);
	dropNodeWriteLock();
}


//add new extern calls to log
unsigned int proto_graph::fill_extern_log(ALLEGRO_TEXTLOG *textlog, unsigned int logSize)
{
	vector <string>::iterator logIt = loggedCalls.begin();
	advance(logIt, logSize);
	while (logIt != loggedCalls.end())
	{
		al_append_native_text_log(textlog, logIt->c_str());
		logSize++;
		logIt++;
	}
	return logSize;
}

void proto_graph::push_anim_update(ANIMATIONENTRY entry)
{
	obtainMutex(animationListsMutex, 2412);
	animUpdates.push(entry);
	savedAnimationData.push_back(entry);
	dropMutex(animationListsMutex);
}



//returns combined count of read+processing trace buffers
unsigned long proto_graph::get_backlog_total()
{
	if (!this->trace_reader) return 0;

	thread_trace_reader *reader = (thread_trace_reader *)trace_reader;
	pair <unsigned long, unsigned long> sizePair;
	reader->getBufsState(&sizePair);
	return sizePair.first + sizePair.second;
}

bool proto_graph::serialise(ofstream *file)
{
	*file << "TID" << tid << "{";

	*file << "N{";
	vector<node_data>::iterator vertit = nodeList.begin();
	for (; vertit != nodeList.end(); ++vertit)
		vertit->serialise(file);
	*file << "}N,";

	*file << "D{";
	EDGELIST::iterator edgeLIt = edgeList.begin();
	for (; edgeLIt != edgeList.end(); ++edgeLIt)
	{
		edge_data *e = get_edge(*edgeLIt);
		assert(e);
		e->serialise(file, edgeLIt->first, edgeLIt->second);
	}
	*file << "}D,";

	*file << "X{";
	set<unsigned int>::iterator exceptit = exceptionSet.begin();
	for (; exceptit != exceptionSet.end(); ++exceptit)
		*file << *exceptit << ",";
	*file << "}X,";

	//S for stats
	*file << "S{"
		//<< maxA << ","
		//<< maxB << ","
		<< baseModule << ","
		<< totalInstructions
		<< "}S,";

	*file << "A{";
	obtainMutex(animationListsMutex, 1030);
	for (unsigned long i = 0; i < savedAnimationData.size(); ++i)
	{
		ANIMATIONENTRY entry = savedAnimationData.at(i);

		*file << (unsigned int)entry.entryType << ","
			<< entry.blockAddr << "," << entry.blockID << ","
			<< entry.count << ","
			<< entry.targetAddr << "," << entry.targetID << ","
			<< entry.callCount << ",";
	}
	dropMutex(animationListsMutex);
	*file << "}A,";

	*file << "}";
	return true;
}

bool proto_graph::unserialise(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	//if (!loadNodes(file, disassembly)) { cerr << "[rgat]ERROR:Node load failed" << endl;  return false; }
	//if (!loadEdgeDict(file)) { cerr << "[rgat]ERROR:EdgeD load failed" << endl; return false; }
	if (!loadExceptions(file)) { cerr << "[rgat]ERROR:Exceptions load failed" << endl;  return false; }
	//if (!loadStats(file)) { cerr << "[rgat]ERROR:Stats load failed" << endl;  return false; }
	if (!loadAnimationData(file)) { cerr << "[rgat]ERROR:Animation load failed" << endl;  return false; }
	return true;
}

bool proto_graph::loadStats(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'S') return false;

	string value_s;
	//getline(*file, value_s, ',');
	//if (!caught_stoi(value_s, &maxA, 10)) return false;
	//getline(*file, value_s, ',');
	//if (!caught_stoi(value_s, &maxB, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, (int *)&baseModule, 10)) return false;
	getline(*file, value_s, '}');
	if (!caught_stoul(value_s, (unsigned long*)&totalInstructions, 10)) return false;

	getline(*file, endtag, ',');
	if (endtag.c_str()[0] != 'S') return false;
	return true;
}

bool proto_graph::loadAnimationData(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'A') return false;

	string type_s, sourceAddr_s, sourceID_s, targAddr_s, targID_s, count_s;
	ANIMATIONENTRY entry;
	while (true)
	{
		getline(*file, type_s, ',');
		if (type_s == "}A")
			return true;

		int entryTypeI;
		if (!caught_stoi(type_s, &entryTypeI, 10))
			break;
		entry.entryType = entryTypeI;

		getline(*file, sourceAddr_s, ',');
		if (!caught_stoul(sourceAddr_s, &entry.blockAddr, 10))
			break;
		getline(*file, sourceID_s, ',');
		if (!caught_stoul(sourceID_s, &entry.blockID, 10))
			break;

		getline(*file, count_s, ',');
		if (!caught_stoul(count_s, &entry.count, 10))
			break;

		getline(*file, targAddr_s, ',');
		if (!caught_stoul(targAddr_s, &entry.targetAddr, 10))
			break;
		getline(*file, targID_s, ',');
		if (!caught_stoul(targID_s, &entry.targetID, 10))
			break;

		getline(*file, targID_s, ',');
		if (!caught_stoul(targID_s, &entry.callCount, 10))
			break;
		savedAnimationData.push_back(entry);
	}
	return false;
}

bool proto_graph::loadExceptions(ifstream *file)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'X') return false;

	unsigned int index;
	string index_s;

	while (true) {
		getline(*file, index_s, ',');
		if (!caught_stoi(index_s, (int *)&index, 10))
		{
			if (index_s == string("}X")) return true;
			return false;
		}
		exceptionSet.insert(exceptionSet.end(), index);
	}
}


bool proto_graph::loadEdgeDict(ifstream *file)
{
	string index_s, source_s, target_s, edgeclass_s;
	int source, target;
	while (true)
	{
		edge_data *edge = new edge_data;

		getline(*file, source_s, ',');
		if (!caught_stoi(source_s, (int *)&source, 10))
		{
			if (source_s == string("}D"))
				return true;
			else
				return false;
		}
		getline(*file, target_s, ',');
		if (!caught_stoi(target_s, (int *)&target, 10)) return false;
		getline(*file, edgeclass_s, '@');
		edge->edgeClass = edgeclass_s.c_str()[0];
		NODEPAIR stpair = make_pair(source, target);
		add_edge(*edge, safe_get_node(source), safe_get_node(target));
	}
	return false;
}

//return symbol text if it exists, otherwise return module path+address
string proto_graph::get_node_sym(NODEINDEX idx, PROCESS_DATA* piddata)
{
	node_data *n = safe_get_node(idx);
	string sym;

	if (piddata->get_sym(n->nodeMod, n->address, &sym))
		return sym;

	string modPath;
	if (!piddata->get_modpath(n->nodeMod, &modPath))
		cerr << "[rgat]WARNING: mod " << n->nodeMod << " expected but not found" << endl;

	stringstream nosym;
	nosym << basename(modPath) << ":0x" << std::hex << n->address;
	return nosym.str();
}

void proto_graph::assign_modpath(PROCESS_DATA *pidinfo)
{
	baseModule = safe_get_node(0)->nodeMod;
	if (baseModule >= (int)pidinfo->modpaths.size()) return;
	string longmodPath;
	pidinfo->get_modpath(baseModule, &longmodPath);

	if (longmodPath.size() > MAX_DIFF_PATH_LENGTH)
		modulePath = ".." + longmodPath.substr(longmodPath.size() - MAX_DIFF_PATH_LENGTH, longmodPath.size());
	else
		modulePath = longmodPath;
}


void proto_graph::start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd)
{
	getEdgeReadLock();
	*edgeIt = edgeList.begin();
	*edgeEnd = edgeList.end();
}

void proto_graph::stop_edgeL_iteration()
{
	dropEdgeReadLock();
}

void proto_graph::start_edgeD_iteration(EDGEMAP::iterator *edgeIt,
	EDGEMAP::iterator *edgeEnd)
{
	getEdgeReadLock();
	*edgeIt = edgeDict.begin();
	*edgeEnd = edgeDict.end();
}

void proto_graph::stop_edgeD_iteration()
{
	dropEdgeReadLock();
}

