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

#pragma once
#include "traceStructs.h"
#include "node_data.h"
#include "edge_data.h"
#include "thread_graph_data.h"
#include "thread_trace_reader.h"
#include "GUIStructs.h"
#include "timeline.h"

struct TAG {
	unsigned long blockaddr;
	unsigned int insCount;
	int jumpModifier;
	unsigned int blockID;
	BB_DATA* foundExtern;

};
struct FAILEDARGS {
	int caller;
	int externid;
	unsigned long targaddr;
};

class thread_trace_handler
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	int TID;
	thread_graph_data *watchedGraph;
	PROCESS_DATA *piddata;
	timeline *timelinebuilder;
	thread_trace_reader *reader;
	bool die = false;
	bool basicMode = false;
	
private:
	//important state variables!
	unsigned int lastVertID = 0; //the vert that led to this instruction
	unsigned int targVertID = 0; //new vert we are creating

	char lastRIPType = FIRST_IN_THREAD;
	vector<pair<long, int>> callStack;

	thread_graph_data *thisgraph;
	//keep track of which a,b coords are occupied
	map<int, map<int, bool>> usedCoords;

	void handle_arg(char * entry, size_t entrySize);
	void process_new_args();
	bool run_external(unsigned long targaddr, unsigned long repeats, NODEPAIR *resultPair);

	void TID_thread();
	int runBB(TAG *tag, int startIndex, int repeats);
	void positionVert(int *pa, int *pb, int *pbMod, long address);
	void updateStats(int a, int b, unsigned int bMod);
	void insert_edge(edge_data e, NODEPAIR edgepair);
	bool is_old_instruction(INS_DATA *instruction, unsigned int *vertIdx);
	void handle_new_instruction(INS_DATA *instruction,int mutation, int bb_inslist_index);
	void handle_existing_instruction(INS_DATA *instruction);
	bool get_extern_at_address(long address, BB_DATA ** BB, int attempts);
	bool find_internal_at_address(long address, int attempts);
	void increaseWeight(edge_data *edge, long executions);
	void handle_tag(TAG *thistag, unsigned long repeats);
	void update_conditional_state(unsigned long nextAddress);
	int find_containing_module(unsigned long address);
	void dump_loop();

	unsigned long pendingFunc = 0;
	unsigned long pendingRet = 0;
	ARGLIST pendingArgs;
	vector<FAILEDARGS> repeatArgAttempts;

#define NO_LOOP 0
#define LOOP_CACHE_BUILD 1
#define LOOP_START 2
#define LOOP_PROGRESS 3
	bool afterReturn = false;
	unsigned long loopCount = 0;
	unsigned int firstLoopVert = 0;
	int loopState = NO_LOOP;
	//tag address, mod type
	vector<TAG> loopCache;
	NODEPAIR repeatStart;
	NODEPAIR repeatEnd;
	
};