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

proto_graph::proto_graph(traceRecord *tracerecPtr, unsigned int threadID)
{
	constructedTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	runRecord = (traceRecord *)tracerecPtr;
	piddata = runRecord->get_piddata();
	tid = threadID;
}


proto_graph::~proto_graph()
{
}

//creates a node for a newly executed instruction
unsigned int proto_graph::handle_new_instruction(INS_DATA &instruction, BLOCK_IDENTIFIER blockID, unsigned long repeats)
{

	node_data thisnode;
	thisnode.ins = &instruction;

	NODEINDEX targVertID = (NODEINDEX)get_num_nodes();

	thisnode.index = targVertID;
	thisnode.ins = &instruction;
	thisnode.conditional = thisnode.ins->conditional;
	thisnode.address = instruction.address;
	thisnode.blockID = blockID;
	thisnode.executionCount = repeats;
	thisnode.globalModID = instruction.globalmodnum;

	assert(!node_exists(targVertID));
	insert_node(targVertID, thisnode);

	piddata->getDisassemblyWriteLock();
	instruction.threadvertIdx.insert(make_pair(tid,targVertID));
	piddata->dropDisassemblyWriteLock();

	lastNode = targVertID; //obsolete
	return targVertID;
}

void proto_graph::handle_previous_instruction(NODEINDEX newTargVertID, unsigned long repeats)
{
	safe_get_node(newTargVertID)->executionCount += repeats;
	lastNode = newTargVertID;
}


void proto_graph::add_edge(edge_data e, node_data &source, node_data &target)
{

	NODEPAIR edgePair;
	edgePair.first = source.index;
	edgePair.second = target.index;

	getNodeWriteLock();

	source.outgoingNeighbours.insert(edgePair.second);
	if (source.conditional && (source.conditional != CONDCOMPLETE))
	{
		if (source.ins->condDropAddress == target.address)
			source.conditional |= CONDFELLTHROUGH;
		else if (source.ins->branchAddress == target.address)
			source.conditional |= CONDTAKEN;
	}

	target.incomingNeighbours.insert(edgePair.first);
	dropNodeWriteLock();

	getEdgeWriteLock();
	edgeDict.insert(make_pair(edgePair, e));
	edgeList.push_back(edgePair);
	dropEdgeWriteLock();
}

void proto_graph::insert_edge_between_BBs(INSLIST &source, INSLIST &target)
{
	INS_DATA *sourceIns = source.back();
	INS_DATA *targetIns = target.front();

	unsigned int sourceNodeIdx = sourceIns->threadvertIdx.at(tid);
	unsigned int targNodeIdx = targetIns->threadvertIdx.at(tid);

	NODEPAIR edgeNodes = make_pair(sourceNodeIdx, targNodeIdx);

	if (edgeDict.count(edgeNodes)) return;

	node_data *sourceNode = safe_get_node(sourceNodeIdx);
	node_data *targNode = safe_get_node(targNodeIdx);

	edge_data newEdge;

	if (targNode->external)
		newEdge.edgeClass = eEdgeNodeType::eEdgeLib;
	else if (sourceNode->ins->itype == eNodeType::eInsCall)
		newEdge.edgeClass = eEdgeNodeType::eEdgeCall;
	else if (sourceNode->ins->itype == eNodeType::eInsReturn)
		newEdge.edgeClass = eEdgeNodeType::eEdgeReturn;
	else
		newEdge.edgeClass = eEdgeNodeType::eEdgeOld;

	add_edge(newEdge, *sourceNode, *targNode);

}



/*find the edge represented by pair of nodes 'edge'
	return false if not found
	return true if found + edge data placed in **edged

this is probably the highest usage CPU function in the application (2% ish of total CPU usage)
see if there is a better container for edgeDict than unordered map
*/
bool proto_graph::edge_exists(NODEPAIR edge, edge_data **edged)
{
	getEdgeReadLock();
	EDGEMAP::iterator edgeit = edgeDict.find(edge);
	dropEdgeReadLock();

	if (edgeit == edgeDict.end()) 
		return false;
	else
	{
		if (edged)
			*edged = &edgeit->second;
		return true;
	}
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
	edgeData.edgeClass = eEdgeNodeType::eEdgeNew;
	edgeData.chainedWeight = 0;
	add_edge(edgeData, *source, *target);

	return &edgeDict.at(edge);
}

//linker error if we make this inline too
edge_data * proto_graph::get_edge(NODEINDEX edgeindex)
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

edge_data *proto_graph::get_edge(NODEPAIR edgePair)
{
	getEdgeReadLock();
	EDGEMAP::iterator edgeIt = edgeDict.find(edgePair);
	dropEdgeReadLock();

	if (edgeIt != edgeDict.end())
		return &edgeIt->second;
	else
		return 0;
}

//assumes caller has edge lock
inline edge_data *proto_graph::unsafe_get_edge(NODEPAIR edgePair)
{
	EDGEMAP::iterator edgeIt = edgeDict.find(edgePair);

	if (edgeIt != edgeDict.end())
		return &edgeIt->second;
	else
		return 0;
}




inline void proto_graph::getEdgeWriteLock()
{
	AcquireSRWLockExclusive(&edgeLock);
}



inline void proto_graph::dropEdgeWriteLock()
{
	ReleaseSRWLockExclusive(&edgeLock);
}

void proto_graph::getNodeReadLock()
{
	AcquireSRWLockShared(&nodeLock);
}


inline void proto_graph::getNodeWriteLock()
{
	AcquireSRWLockExclusive(&nodeLock);
}

inline void proto_graph::dropNodeWriteLock()
{
	ReleaseSRWLockExclusive(&nodeLock);
}



inline node_data *proto_graph::safe_get_node(NODEINDEX index)
{
	if (index >= nodeList.size()) 
		return NULL;

	getNodeReadLock();
	node_data *n = &nodeList.at(index);
	dropNodeReadLock();
	return n;
}

//for when caller already has read/write lock
node_data *proto_graph::unsafe_get_node(NODEINDEX index)
{
	return &nodeList.at(index);
}

void proto_graph::set_active_node(NODEINDEX idx)
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
		highlightsLock.lock();
		externalNodeList.push_back(node.index);
		highlightsLock.unlock();
	}
	else if (node.ins->hasSymbol)
	{
		highlightsLock.lock();
		internalNodeList.push_back(node.index);
		highlightsLock.unlock();
	}

	getNodeWriteLock();
	nodeList.push_back(node);
	dropNodeWriteLock();
}

void proto_graph::push_anim_update(ANIMATIONENTRY entry)
{
	AcquireSRWLockExclusive(&animationListsSRWLOCK);
	savedAnimationData.push_back(entry);
	ReleaseSRWLockExclusive(&animationListsSRWLOCK);
}

//returns combined count of read+processing trace buffers
unsigned long proto_graph::get_backlog_total()
{
	if (!this->trace_reader) return 0;

	thread_trace_reader *reader = (thread_trace_reader *)trace_reader;
	pair <size_t, size_t> sizePair;
	reader->getBufsState(sizePair);
	return sizePair.first + sizePair.second;
}

bool proto_graph::serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer)
{
	writer.StartObject();

	writer.Key("ThreadID");
	writer.Int64(tid);

	writer.Key("Nodes");
	writer.StartArray();
	getNodeReadLock();
	vector<node_data>::iterator vertit = nodeList.begin();
	for (; vertit != nodeList.end(); ++vertit)
		vertit->serialise(writer, this);
	dropNodeReadLock();
	writer.EndArray();

	writer.Key("Edges");
	writer.StartArray();
	getEdgeReadLock();
	EDGELIST::iterator edgeLIt = edgeList.begin();
	for (; edgeLIt != edgeList.end(); ++edgeLIt)
	{
		edge_data *e = unsafe_get_edge(*edgeLIt);
		assert(e);
		e->serialise(writer, edgeLIt->first, edgeLIt->second);
	}
	dropEdgeReadLock();
	writer.EndArray();

	writer.Key("Exceptions");
	writer.StartArray();
	highlightsLock.lock();
	set<NODEINDEX>::iterator exceptit = exceptionSet.begin();
	for (; exceptit != exceptionSet.end(); ++exceptit)
		writer.Uint64(*exceptit);
	highlightsLock.unlock();
	writer.EndArray();

	writer.Key("Module");
	writer.Uint(exeModuleID);

	externCallsLock.lock();
	writer.Key("ExternCalls");
	writer.StartArray();
	ARGIDXDATA argData;
	EXTERNCALLDATA externcall;
	foreach(externcall, externCallRecords)
	{
		writer.StartArray();
			writer.Uint64(externcall.edgeIdx.first);
			writer.Uint64(externcall.edgeIdx.second);
			writer.StartArray();
				foreach(argData, externcall.argList)
				{
					writer.StartArray();
					writer.Uint(argData.first);
					writer.String(argData.second.c_str());
					writer.EndArray();
				} 
			writer.EndArray();
		writer.EndArray();
	}
	writer.EndArray();
	externCallsLock.unlock();

	writer.Key("TotalInstructions");
	writer.Uint64(totalInstructions);

	writer.Key("ReplayData");
	writer.StartArray();
	AcquireSRWLockShared(&animationListsSRWLOCK);
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
	ReleaseSRWLockShared(&animationListsSRWLOCK);
	writer.EndArray();

	writer.EndObject(); //end thread object
	return true;
}

bool proto_graph::deserialise(const Value& graphData, map <MEM_ADDRESS, INSLIST> &disassembly)
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
		cerr << "[rgat] Error: Failed to find edge data" << endl;
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

	graphDataIt = graphData.FindMember("ExternCalls");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find extern calls data" << endl;
		return false;
	}
	if (!loadCallData(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load extern call data" << endl;  return false; }


	graphDataIt = graphData.FindMember("ReplayData");
	if (graphDataIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find replay data" << endl;
		return false;
	}
	if (!loadAnimationData(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load trace replay data" << endl;  return false; }

	if (!loadStats(graphData)) { cerr << "[rgat]ERROR: Failed to load graph stats" << endl;  return false; }


	return true;
}

bool proto_graph::loadNodes(const Value& nodesArray, map <MEM_ADDRESS, INSLIST> &disassembly)
{
	Value::ConstValueIterator nodesIt = nodesArray.Begin();
	for (; nodesIt != nodesArray.End(); nodesIt++)
	{
		node_data *n = new node_data;//can't this be done at start?
		if (!n->deserialise(*nodesIt, disassembly))
		{
			cerr << "Failed to unserialise node" << endl;
			delete n;
			return false;
		}

		insert_node(n->index, *n);
		delete n;
	}

	return true;
}

bool proto_graph::loadCallData(const Value& callArray)
{
	Value::ConstValueIterator callIt = callArray.Begin();
	for (; callIt != callArray.End(); callIt++)
	{
		const Value& callEntry = *callIt;

		if (callEntry.Capacity() != 3) 
			return false;
		if (callEntry[0].GetType() != rapidjson::Type::kNumberType) 
			return false;
		if (callEntry[1].GetType() != rapidjson::Type::kNumberType) 
			return false;
		if (callEntry[2].GetType() != rapidjson::Type::kArrayType)
			return false;

		NODEPAIR edge = make_pair(callEntry[0].GetUint(), callEntry[1].GetUint());
		ARGLIST args;

		Value::ConstValueIterator argPairArrayIt = callEntry[2].Begin();
		for (; argPairArrayIt != callEntry[2].End(); argPairArrayIt++)
		{
			const Value& argArrayItem = *argPairArrayIt;

			if (argArrayItem.GetType() != rapidjson::Type::kArrayType || argArrayItem.Capacity() != 2) 
				return false;
			const Value& argIndex = argArrayItem[0];
			const Value& argString = argArrayItem[1];

			ARGIDXDATA argData;
			argData.first = argIndex.GetUint();
			argData.second = argString.GetString();
			args.push_back(argData);
		}

		externCallRecords.push_back({ edge, args });
	}
	return true;
}

bool proto_graph::loadStats(const Value& graphData)
{
	 
	/*
	
			const Value& functionCalls = nodeData[8];
		Value::ConstValueIterator funcCallsIt = functionCalls.Begin();
		for (; funcCallsIt != functionCalls.End(); funcCallsIt++)
		{
			ARGLIST callArgs;
			const Value& callArgumentsArray = *funcCallsIt;
			Value::ConstValueIterator argsIt = callArgumentsArray.Begin();
			for (; argsIt != callArgumentsArray.End(); argsIt++)
			{
				const Value& callArgumentsEntry = *argsIt;

				int argIndex = callArgumentsEntry[0].GetUint();
				string b64Arg = callArgumentsEntry[1].GetString();
				string plainArgString = base64_decode(b64Arg);

				callArgs.push_back(make_pair(argIndex, plainArgString));
			}
			funcargs.push_back(callArgs);
		}
	*/


	Value::ConstMemberIterator statsIt = graphData.FindMember("Module");
	if (statsIt == graphData.MemberEnd()) return false;
	exeModuleID = statsIt->value.GetUint();
	moduleBase = runRecord->get_piddata()->modBounds.at(exeModuleID)->first;

	statsIt = graphData.FindMember("TotalInstructions");
	if (statsIt == graphData.MemberEnd()) return false;
	totalInstructions = statsIt->value.GetUint64();

	return true;
}

bool proto_graph::loadAnimationData(const Value& traceArray)
{
	Value::ConstValueIterator entryIt = traceArray.Begin();
	for (; entryIt != traceArray.End(); entryIt++)
	{
		const Value& traceEntry = *entryIt;

		ANIMATIONENTRY entry;
		entry.entryType = (eTraceUpdateType)traceEntry[0].GetUint();
		entry.blockAddr = traceEntry[1].GetUint64();
		entry.blockID = traceEntry[2].GetUint64();
		entry.count = traceEntry[3].GetUint64();
		entry.targetAddr = traceEntry[4].GetUint64();
		entry.targetID = traceEntry[5].GetUint64();
		entry.callCount = traceEntry[6].GetUint64();

		savedAnimationData.push_back(entry);
	}
	
	return true;
}

bool proto_graph::loadExceptions(const Value& exceptionsArrays)
{
	Value::ConstValueIterator exceptIt = exceptionsArrays.Begin();

	for (; exceptIt != exceptionsArrays.End(); exceptIt++)
		exceptionSet.insert(exceptionSet.end(), exceptIt->GetUint64());

	return true;
}


bool proto_graph::loadEdgeDict(const Value& edgeArray)
{
	Value::ConstValueIterator edgeIt = edgeArray.Begin();

	for (; edgeIt != edgeArray.End(); edgeIt++)
	{
		const Value& edgeData = *edgeIt;

		NODEINDEX source = edgeData[0].GetUint64();
		NODEINDEX target = edgeData[1].GetUint64();
		unsigned int edgeClass = edgeData[2].GetUint();

		edge_data *edge = new edge_data;
		edge->edgeClass = (eEdgeNodeType)edgeClass;

		NODEPAIR stpair = make_pair(source, target);
		add_edge(*edge, *safe_get_node(source), *safe_get_node(target));
	}
	return true;
}

//return symbol text if it exists, otherwise return module path+offset
string proto_graph::get_node_sym(NODEINDEX idx)
{
	node_data *n = safe_get_node(idx);
	string sym;

	MEM_ADDRESS offset = n->address - get_piddata()->modBounds.at(n->globalModID)->first;
	if (piddata->get_sym(n->globalModID, offset, sym))
		return sym;

	boost::filesystem::path modPath;
	if (!piddata->get_modpath(n->globalModID, &modPath))
		cerr << "[rgat]WARNING: mod " << n->globalModID << " expected but not found" << endl;

	stringstream nosym;
	nosym << modPath.filename() << "+0x" << std::hex << offset;
	return nosym.str();
}

void proto_graph::assign_modpath()
{
	exeModuleID = safe_get_node(0)->globalModID;
	if (exeModuleID >= (int)piddata->modpaths.size()) return;

	boost::filesystem::path longmodPath;
	piddata->get_modpath(exeModuleID, &longmodPath);
	moduleBase = runRecord->get_piddata()->modBounds.at(exeModuleID)->first;
	

	if (longmodPath.size() > MAX_DIFF_PATH_LENGTH)
		modulePath = ".." + longmodPath.string().substr(longmodPath.size() - MAX_DIFF_PATH_LENGTH, longmodPath.size());
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


vector<NODEINDEX> proto_graph::copyExternalNodeList()
{
	highlightsLock.lock();
	vector<NODEINDEX> externListCopy(externalNodeList);
	highlightsLock.unlock();
	return externListCopy;
}

vector<NODEINDEX> proto_graph::copyInternalNodeList()
{
	highlightsLock.lock();
	vector<NODEINDEX> internalNodeListCopy(internalNodeList);
	highlightsLock.unlock();
	return internalNodeListCopy;
}
