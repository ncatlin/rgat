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
#include "serialise.h"

using namespace rapidjson;

proto_graph::proto_graph(PROCESS_DATA *processdata, unsigned int threadID)
{
	piddata = processdata;
	tid = threadID;
}


proto_graph::~proto_graph()
{
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

	lastNode = targVertID;
	return targVertID;
}

void proto_graph::handle_previous_instruction(unsigned int newTargVertID, unsigned long repeats)
{
	safe_get_node(newTargVertID)->executionCount += repeats;
	lastNode = newTargVertID;
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
		newEdge.edgeClass = eEdgeLib;
	else if (sourceNode->ins->itype == OPCALL)
		newEdge.edgeClass = eEdgeCall;
	else if (sourceNode->ins->itype == OPRET)
		newEdge.edgeClass = eEdgeReturn;
	else
		newEdge.edgeClass = eEdgeOld;

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
	edgeData.edgeClass = eEdgeNew;
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
	dropNodeWriteLock();
}

void proto_graph::insert_node(NODEINDEX targVertID, node_data node)
{
	if (!nodeList.empty())
		assert(targVertID == nodeList.back().index + 1);

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

bool proto_graph::serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer)
{
	

	writer.StartObject();

	writer.Key("ThreadID");
	writer.Int64(tid);

	writer.Key("Nodes");
	writer.StartArray();
	vector<node_data>::iterator vertit = nodeList.begin();
	for (; vertit != nodeList.end(); ++vertit)
		vertit->serialise(writer);
	writer.EndArray();

	writer.Key("Edges");
	writer.StartArray();
	EDGELIST::iterator edgeLIt = edgeList.begin();
	for (; edgeLIt != edgeList.end(); ++edgeLIt)
	{
		edge_data *e = get_edge(*edgeLIt);
		assert(e);
		e->serialise(writer, edgeLIt->first, edgeLIt->second);
	}
	writer.EndArray();

	writer.Key("Exceptions");
	writer.StartArray();
	set<unsigned int>::iterator exceptit = exceptionSet.begin();
	for (; exceptit != exceptionSet.end(); ++exceptit)
		writer.Uint(*exceptit);
	writer.EndArray();

	writer.Key("Module");
	writer.Uint(baseModule);

	writer.Key("TotalInstructions");
	writer.Uint64(totalInstructions);

	writer.Key("ReplayData");
	writer.StartArray();
	obtainMutex(animationListsMutex, 1030);
	for (unsigned long i = 0; i < savedAnimationData.size(); ++i)
	{
		writer.StartArray();
		ANIMATIONENTRY entry = savedAnimationData.at(i);

		writer.Uint((unsigned int)entry.entryType);
		writer.Uint64(entry.blockAddr);
		writer.Uint64(entry.blockID);
		writer.Uint64(entry.count);
		writer.Uint64(entry.targetAddr);
		writer.Uint64(entry.targetID);
		writer.Uint64(entry.callCount);

		writer.EndArray();
	}
	dropMutex(animationListsMutex);
	writer.EndArray();

	writer.EndObject(); //end thread object
	return true;
}

bool proto_graph::unserialise(const Value& graphData, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	Value::ConstMemberIterator graphDataIt = graphData.FindMember("Nodes");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find nodes data" << endl;
		return false;
	}
	if (!loadNodes(graphDataIt->value, disassembly)) { cerr << "[rgat]ERROR: Failed to load nodes" << endl;  return false; }

	graphDataIt = graphData.FindMember("Edges");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find nodes data" << endl;
		return false;
	}
	if (!loadEdgeDict(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load edge dict" << endl; return false; }

	graphDataIt = graphData.FindMember("Exceptions");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find exceptions data" << endl;
		return false;
	}
	if (!loadExceptions(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load exceptions set" << endl;  return false; }

	graphDataIt = graphData.FindMember("ReplayData");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find replay data" << endl;
		return false;
	}
	if (!loadAnimationData(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load replay data" << endl;  return false; }

	if (!loadStats(graphData)) { cerr << "[rgat]ERROR:Stats load failed" << endl;  return false; }


	return true;
}

bool proto_graph::loadNodes(const Value& nodesArray, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	Value::ConstValueIterator nodesIt = nodesArray.Begin();
	for (; nodesIt != nodesArray.End(); nodesIt++)
	{
		node_data *n = new node_data;//can't this be done at start?
		if (!n->unserialise(*nodesIt, disassembly))
		{
			cerr << "Failed to unserialise node" << endl;
			delete n;
			return false;
		}

		insert_node(n->index, *n);
		delete n;
	}
}

bool proto_graph::loadStats(const Value& graphData)
{
	 
	Value::ConstMemberIterator statsIt = graphData.FindMember("Module");
	if (statsIt == graphData.MemberEnd()) return false;
	baseModule = statsIt->value.GetUint();

	statsIt = graphData.FindMember("TotalInstructions");
	if (statsIt == graphData.MemberEnd()) return false;
	totalInstructions = statsIt->value.GetUint64();

	return true;
}

bool proto_graph::loadAnimationData(const Value& replayArray)
{
	Value::ConstValueIterator entryIt = replayArray.Begin();
	for (; entryIt != replayArray.End(); entryIt++)
	{
		const Value& replayEntry = *entryIt;

		ANIMATIONENTRY entry; //could probably do this directly on the heap
		entry.entryType = replayEntry[0].GetUint();
		entry.blockAddr = replayEntry[1].GetUint64();
		entry.blockID = replayEntry[2].GetUint64();
		entry.count = replayEntry[3].GetUint64();
		entry.targetAddr = replayEntry[4].GetUint64();
		entry.targetID = replayEntry[5].GetUint64();
		entry.callCount = replayEntry[6].GetUint64();

		savedAnimationData.push_back(entry);
	}
	
	return true;
}

bool proto_graph::loadExceptions(const Value& exceptionsArrays)
{
	Value::ConstValueIterator exceptIt = exceptionsArrays.Begin();

	for (; exceptIt != exceptionsArrays.End(); exceptIt++)
		exceptionSet.insert(exceptionSet.end(), exceptIt->GetUint());

	return true;
}


bool proto_graph::loadEdgeDict(const Value& edgeArray)
{
	Value::ConstValueIterator edgeIt = edgeArray.Begin();

	for (; edgeIt != edgeArray.End(); edgeIt++)
	{
		const Value& edgeData = *edgeIt;

		unsigned int source = edgeData[0].GetUint();
		unsigned int target = edgeData[1].GetUint();
		unsigned int edgeClass = edgeData[2].GetUint();

		edge_data *edge = new edge_data;
		edge->edgeClass = (eEdgeNodeType)edgeClass;

		NODEPAIR stpair = make_pair(source, target);
		add_edge(*edge, safe_get_node(source), safe_get_node(target));
	}
	return true;
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

