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
#include "proto_graph.h"
#include "thread_trace_reader.h"
#include "timeline.h"
#include "base_thread.h"

#define NO_LOOP 0
#define BUILDING_LOOP 1
#define LOOP_PROGRESS 2

struct TAG {
	//come from trace
	MEM_ADDRESS blockaddr;
	BLOCK_IDENTIFIER blockID;
	unsigned long insCount;
	//used internally
	int jumpModifier;
	BB_DATA* foundExtern = 0;
};
struct FAILEDARGS {
	int caller;
	int externid;
	MEM_ADDRESS targaddr;
};

struct BLOCKREPEAT {
	MEM_ADDRESS blockaddr;
	BLOCK_IDENTIFIER blockID;
	unsigned int insCount = 0;
	vector<pair<MEM_ADDRESS, BLOCK_IDENTIFIER>> targBlocks;
	unsigned long totalExecs;
	INSLIST *blockInslist = 0;
};

struct PENDING_REPEAT {
	MEM_ADDRESS blockaddr;
	BLOCK_IDENTIFIER blocID;
	vector <pair<MEM_ADDRESS, unsigned long>> pendingTargs;
};


class trace_graph_builder : public base_thread
{
public:
	trace_graph_builder(traceRecord* runRecordptr, proto_graph *graph, thread_trace_reader *readerThread)
		:base_thread()
	{
		runRecord = runRecordptr;
		binary = (binaryTarget *)runRecord->get_binaryPtr();
		piddata = binary->get_piddata();
		thisgraph = graph;
		reader = readerThread;
		TID = graph->get_TID();
		basicMode = binary->launchopts.basic;
		set_max_arg_storage(clientState->config.maxArgStorage);
		saveFlag = &clientState->savingFlag;
	}

	PROCESS_DATA *piddata;
	timeline *timelinebuilder;
	bool basicMode = false;
	void set_max_arg_storage(unsigned int maxargs) { arg_storage_capacity = maxargs; }
	bool *saveFlag;

private:
	void main_loop();

	thread_trace_reader *reader;

	void handle_arg(char * entry, size_t entrySize);
	void process_new_args();
	bool lookup_extern_func_calls(MEM_ADDRESS called_function_address, EDGELIST &callEdges);
	bool run_external(MEM_ADDRESS targaddr, unsigned long repeats, NODEPAIR *resultPair);

	void runBB(TAG *tag, int repeats);
	void run_faulting_BB(TAG *tag);
	void BB_addNewEdge(bool alreadyExecuted, int instructionIndex, unsigned long repeats);

	void process_trace_tag(char *entry);
	void process_loop_marker(char *entry);
	void satisfy_pending_edges();
	void add_unchained_update(char *entry);
	void add_satisfy_update(char *entry);
	void add_exception_update(char *entry);
	void add_exec_count_update(char *entry);
	void add_unlinking_update(char *entry);

	bool set_target_instruction(INS_DATA *instruction);

	bool find_internal_at_address(MEM_ADDRESS address, int attempts);

	INSLIST *find_block_disassembly(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID);

	void handle_tag(TAG *thistag, unsigned long repeats);
	void handle_exception_tag(TAG *thistag);

	int find_containing_module(MEM_ADDRESS address, int &modnum);
	void dump_loop();
	bool assign_blockrepeats();

	PID_TID TID;
	//important state variables!
	NODEINDEX lastVertID = 0; //the vert that led to new instruction
	NODEINDEX targVertID = 0; //new vert we are creating

	eEdgeNodeType lastNodeType = eFIRST_IN_THREAD;

	proto_graph *thisgraph;


	vector <BLOCKREPEAT> blockRepeatQueue;
	DWORD64 lastRepeatUpdate = GetTickCount64();
	bool repeatsUpdateDue() { return (GetTickCount64() > lastRepeatUpdate + 800); }

	MEM_ADDRESS pendingCalledFunc = 0;
	MEM_ADDRESS pendingFuncCaller = 0;

	ARGLIST pendingArgs;
	//   function 	      caller		
	map<MEM_ADDRESS, map <MEM_ADDRESS, vector<ARGLIST>>> pendingcallargs;
	vector<FAILEDARGS> repeatArgAttempts;

	vector<PENDING_REPEAT> pendingTargCounts;
	struct NEW_EDGE_BLOCKDATA {
		MEM_ADDRESS sourceAddr;
		BLOCK_IDENTIFIER sourceID;
		MEM_ADDRESS targAddr;
		BLOCK_IDENTIFIER targID;
	};
	vector<NEW_EDGE_BLOCKDATA> pendingEdges;

	
	unsigned long loopIterations = 0;
	unsigned int firstLoopVert = 0;
	int loopState = NO_LOOP;
	//tag address, mod type
	vector<TAG> loopCache;
	NODEPAIR repeatStart;
	NODEPAIR repeatEnd;

	//number of times an external function has been called. used to map arguments to calls
	map <pair<MEM_ADDRESS, BLOCK_IDENTIFIER>, unsigned long> externFuncCallCounter;
	unsigned int arg_storage_capacity = 100;

	binaryTarget *binary;
	traceRecord* runRecord;
};