/*
Copyright 2016-2017 Nia Catlin

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
Header for pre-graph data built from the trace
The final graphs (cylinder, tree, etc are built using this data)
*/
#pragma once
#include "stdafx.h"
#include <traceStructs.h>
#include <traceMisc.h>
#include "node_data.h"
#include "locks.h"
#include "traceRecord.h"

#include <rapidjson\document.h>
#include <rapidjson\filewritestream.h>
#include <rapidjson\writer.h>
#include <rapidjson\filereadstream.h>
#include <rapidjson\reader.h>
#include <boost\lockfree\spsc_queue.hpp>

#define ANIMATION_ENDED -1
#define ANIMATION_WIDTH 8

enum eTraceUpdateType { eAnimExecTag, eAnimLoop, eAnimLoopLast, eAnimUnchained, eAnimUnchainedResults, eAnimUnchainedDone, eAnimExecException};

struct ANIMATIONENTRY {
	eTraceUpdateType entryType;
	MEM_ADDRESS blockAddr;
	BLOCK_IDENTIFIER blockID;
	unsigned long count;
	MEM_ADDRESS targetAddr;
	BLOCK_IDENTIFIER targetID;
	unsigned long callCount;
};


class proto_graph
{
private:
	PID_TID tid = 0;

	int nlockholder = 0;

	void *trace_reader = NULL;
	PROCESS_DATA* piddata = NULL;
	traceRecord* runRecord = NULL;
	HANDLE disassemblyMutex;

	SRWLOCK nodeLock = SRWLOCK_INIT;
	SRWLOCK edgeLock = SRWLOCK_INIT;


	//used to keep a blocking extern highlighted - may not be useful with new method TODO
	unsigned int latest_active_node_idx = 0;
	time_t constructedTime;

	bool loadNodes(const rapidjson::Value& nodesArray, map <MEM_ADDRESS, INSLIST> &disassembly);
	bool loadExceptions(const rapidjson::Value& exceptionsArray);
	bool loadStats(const rapidjson::Value& graphData);
	bool loadAnimationData(const rapidjson::Value& replayArray);
	bool loadCallData(const rapidjson::Value& graphData);



protected:
	

public:
	proto_graph(traceRecord *runrecord, unsigned int threadID);
	~proto_graph();

	void insert_edge_between_BBs(INSLIST &source, INSLIST &target);
	void insert_node(NODEINDEX targVertID, node_data node);
	bool edge_exists(NODEPAIR edge, edge_data **edged);
	void add_edge(edge_data e, node_data &source, node_data &target);

	EDGEMAP edgeDict; //node id pairs to edge data
	EDGELIST edgeList; //order of edge execution
	
	//i feel like this misses the point, idea is to iterate safely
	EDGELIST *edgeLptr() { return &edgeList; }

	vector<node_data> nodeList; //node id to node data

	bool node_exists(NODEINDEX idx) { return (nodeList.size() > idx); }
	size_t get_num_nodes() { return nodeList.size(); }
	size_t get_num_edges() { return edgeDict.size(); }

	void acquireNodeReadLock() { getNodeReadLock(); }
	void releaseNodeReadLock() { dropNodeReadLock(); }

	unsigned int handle_new_instruction(INS_DATA &instruction, BLOCK_IDENTIFIER blockID, unsigned long repeats);
	void handle_previous_instruction(NODEINDEX targVertID, unsigned long repeats);

	traceRecord* get_traceRecord() { return runRecord; }
	PROCESS_DATA* get_piddata() { return piddata; }
	PID_TID get_TID() { return tid; }

	void set_active_node(NODEINDEX idx);

	string get_node_sym(NODEINDEX idx);

	size_t getAnimDataSize() { return savedAnimationData.size(); }
	vector <ANIMATIONENTRY> * getSavedAnimData() { return &savedAnimationData; }

	//list of all external nodes
	vector<NODEINDEX> externalNodeList;
	vector<NODEINDEX> copyExternalNodeList();

	//list of all internal nodes with symbols
	vector<NODEINDEX> internalNodeList;
	vector<NODEINDEX> copyInternalNodeList();

	//these are called a lot. make sure as efficient as possible
	edge_data *get_edge(NODEPAIR edge);
	inline edge_data * unsafe_get_edge(NODEPAIR edgePair);

	edge_data * get_edge(NODEINDEX edgeindex);

	edge_data *get_edge_create(node_data *source, node_data *target);

	node_data *unsafe_get_node(NODEINDEX index);
	node_data *safe_get_node(NODEINDEX index);

	bool loadEdgeDict(const rapidjson::Value& edgeArray);
	
	rgatlocks::UntestableLock highlightsLock; //todo comment this or rename
	SRWLOCK animationListsSRWLOCK = SRWLOCK_INIT;

	rgatlocks::UntestableLock externCallsLock;

	/*
	the below was for a scrapped extern call log implementation but this should be how animationdata is done instead?

	//trace reader quickly fills this queue with extern calls at runtime
	boost::lockfree::spsc_queue<NODEINDEX, boost::lockfree::capacity<20000>> externNodeRuntimeQueue;
	//the trace processor moves data from the queue to this storage in slower time
	vector<NODEINDEX> externNodeLog;
	*/

	void push_anim_update(ANIMATIONENTRY);
	//animation data received from target
	vector <ANIMATIONENTRY> savedAnimationData;



	//todo rename
	set<NODEINDEX> exceptionSet;

	void assign_modpath();

	//updated with backlog input/processing each second for display
	//dunno if ulong reads are atomic, not vital for this application
	//adding accessor functions for future threadsafe acesss though
	pair<unsigned long, unsigned long> backlogInOut = make_pair(0, 0);

	void setBacklogIn(unsigned long in) { backlogInOut.first = in; }
	void setBacklogOut(unsigned long out) { backlogInOut.second = out; }
	unsigned long getBacklogIn() { return backlogInOut.first; }
	unsigned long getBacklogOut() { return backlogInOut.second; }
	unsigned long get_backlog_total();

	bool terminationFlag = false;

	void *getReader() { return trace_reader; }
	void setReader(void *newReader) { trace_reader = newReader; }
	bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	bool deserialise(const rapidjson::Value& graphData, map <MEM_ADDRESS, INSLIST> &disassembly);

	double getConstructedTime() { return constructedTime; }
	NODEPAIR instructions_to_nodepair(INS_DATA *sourceIns, INS_DATA *targIns);

	vector<EXTERNCALLDATA> externCallRecords;
	unsigned long totalInstructions = 0;
	int exeModuleID = -1;
	MEM_ADDRESS moduleBase = 0;
	boost::filesystem::path modulePath;
	map <ADDRESS_OFFSET, NODEINDEX> internalPlaceholderFuncNames;

	NODEINDEX lastNode = 0;
	//used by heatmap solver
	NODEINDEX finalNodeID = 0;

	vector <string> loggedCalls;

	bool terminated = false;
	bool updated = true;
	
	void set_terminated() {
		terminated = true;
		updated = true; //aka needvboreloadpreview
	}


	inline void getEdgeReadLock()	{ AcquireSRWLockShared(&edgeLock);	}
	inline void dropEdgeReadLock()	{ ReleaseSRWLockShared(&edgeLock);  }

	inline void dropEdgeWriteLock();
	inline void getEdgeWriteLock();

	void getNodeReadLock();
	inline void dropNodeReadLock(){ ReleaseSRWLockShared(&nodeLock); }

	inline void getNodeWriteLock();
	inline void dropNodeWriteLock();

	void start_edgeD_iteration(EDGEMAP::iterator *edgeit, EDGEMAP::iterator *edgeEnd);
	void stop_edgeD_iteration();

	void start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd);
	void stop_edgeL_iteration();

	bool active = true;
};

