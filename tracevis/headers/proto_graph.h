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
Header for pre-graph data built from the trace
The final graphs (sphere, linear, etc are built using this data)
*/
#pragma once
#include "stdafx.h"
#include <traceStructs.h>
#include <traceMisc.h>
#include "node_data.h"

#include <rapidjson\document.h>
#include <rapidjson\filewritestream.h>
#include <rapidjson\writer.h>
#include <rapidjson\filereadstream.h>
#include <rapidjson\reader.h>

#define ANIMATION_ENDED -1
#define ANIMATION_WIDTH 8

#define ANIM_EXEC_TAG 0
#define ANIM_LOOP 1
#define ANIM_LOOP_LAST 2
#define ANIM_UNCHAINED 3
#define ANIM_UNCHAINED_RESULTS 4
#define ANIM_UNCHAINED_DONE 5
#define ANIM_EXEC_EXCEPTION 6

struct ANIMATIONENTRY {
	char entryType;
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

	void *trace_reader;
	PROCESS_DATA* piddata;
	HANDLE disassemblyMutex;

#ifdef XP_COMPATIBLE
	HANDLE nodeLMutex = CreateMutex(NULL, FALSE, NULL);
	HANDLE edMutex = CreateMutex(NULL, FALSE, NULL);
#else
	SRWLOCK nodeLock = SRWLOCK_INIT;
	SRWLOCK edgeLock = SRWLOCK_INIT;
#endif

	//used to keep a blocking extern highlighted - may not be useful with new method TODO
	unsigned int latest_active_node_idx = 0;

	bool loadNodes(const rapidjson::Value& nodesArray, map <MEM_ADDRESS, INSLIST> *disassembly);
	bool loadExceptions(const rapidjson::Value& exceptionsArray);
	bool loadStats(const rapidjson::Value& graphData);
	bool loadAnimationData(const rapidjson::Value& replayArray);

protected:
	

public:
	proto_graph(PROCESS_DATA *processdata, unsigned int threadID);
	~proto_graph();

	void insert_edge_between_BBs(INSLIST *source, INSLIST *target);
	void insert_node(NODEINDEX targVertID, node_data node);
	bool edge_exists(NODEPAIR edge, edge_data **edged);
	void add_edge(edge_data e, node_data *source, node_data *target);

	EDGEMAP edgeDict; //node id pairs to edge data
	EDGELIST edgeList; //order of edge execution
	
	//i feel like this misses the point, idea is to iterate safely
	EDGELIST *edgeLptr() { return &edgeList; }

	vector<node_data> nodeList; //node id to node data

	bool node_exists(unsigned int idx) { if (nodeList.size() > idx) return true; return false; }
	unsigned int get_num_nodes() { return nodeList.size(); }
	unsigned int get_num_edges() { return edgeDict.size(); }

	void acquireNodeReadLock() { getNodeReadLock(); }
	void releaseNodeReadLock() { dropNodeReadLock(); }

	unsigned int handle_new_instruction(INS_DATA *instruction, BLOCK_IDENTIFIER blockID, unsigned long repeats);
	void handle_previous_instruction(unsigned int targVertID, unsigned long repeats);

	PROCESS_DATA* get_piddata() { return piddata; }
	PID_TID get_TID() { return tid; }

	void set_active_node(unsigned int idx);

	string get_node_sym(NODEINDEX idx, PROCESS_DATA* piddata);

	unsigned long getAnimDataSize() { return savedAnimationData.size(); }
	vector <ANIMATIONENTRY> * getSavedAnimData() { return &savedAnimationData; }

	//list of all external nodes
	vector<unsigned int> externList;
	//list of all internal nodes with symbols
	vector<unsigned int> internList;

	//these are called a lot. make sure as efficient as possible
	inline edge_data *get_edge(NODEPAIR edge);
	edge_data * get_edge(unsigned int edgeindex);
	edge_data *get_edge_create(node_data *source, node_data *target);

	node_data *unsafe_get_node(unsigned int index);
	node_data *safe_get_node(unsigned int index);

	bool loadEdgeDict(const rapidjson::Value& edgeArray);
	
	HANDLE highlightsMutex = CreateMutex(NULL, FALSE, NULL); //todo comment this or rename
	HANDLE animationListsMutex = CreateMutex(NULL, FALSE, NULL);
	HANDLE externGuardMutex = CreateMutex(NULL, FALSE, NULL);

	void push_anim_update(ANIMATIONENTRY);
	//animation data as it is received from drgat
	queue <ANIMATIONENTRY> animUpdates;
	//animation data saved here for replays
	vector <ANIMATIONENTRY> savedAnimationData;

	//todo rename
	set<unsigned int> exceptionSet;

	void assign_modpath(PROCESS_DATA *);

	//updated with backlog input/processing each second for display
	//dunno if ulong reads are atomic, not vital for this application
	//adding accessor functions for future threadsafe acesss though
	pair<unsigned long, unsigned long> backlogInOut = make_pair(0, 0);

	void setBacklogIn(unsigned long in) { backlogInOut.first = in; }
	void setBacklogOut(unsigned long out) { backlogInOut.second = out; }
	unsigned long getBacklogIn() { return backlogInOut.first; }
	unsigned long getBacklogOut() { return backlogInOut.second; }
	unsigned long get_backlog_total();

	unsigned int fill_extern_log(ALLEGRO_TEXTLOG *textlog, unsigned int logSize);

	bool terminationFlag = false;

	unsigned long traceBufferSize = 0;
	void *getReader() { return trace_reader; }
	void setReader(void *newReader) { trace_reader = newReader; }
	bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	bool unserialise(const rapidjson::Value& graphData, map <MEM_ADDRESS, INSLIST> *disassembly);

	unsigned long totalInstructions = 0;
	int baseModule = -1;
	string modulePath;

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

	inline void getEdgeReadLock();
	inline void getEdgeWriteLock();
	inline void dropEdgeReadLock();
	inline void dropEdgeWriteLock();

	inline void getNodeReadLock();
	inline void dropNodeReadLock();
	inline void getNodeWriteLock();
	inline void dropNodeWriteLock();

	void start_edgeD_iteration(EDGEMAP::iterator *edgeit, EDGEMAP::iterator *edgeEnd);
	void stop_edgeD_iteration();

	void start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd);
	void stop_edgeL_iteration();

	bool active = true;

};

