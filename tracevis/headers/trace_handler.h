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
	int insCount;
	int jumpModifier;
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
	
private:
	//important state variables!
	unsigned int lastVertID = 0; //the vert that led to this instruction
	unsigned int targVertID = 0; //new vert we are creating

	char lastRIPType = FIRST_IN_THREAD;
	bool afterReturn = false;
	vector<pair<long, int>> callStack;

	thread_graph_data *thisgraph;
	//keep track of which a,b coords are occupied
	map<int, map<int, bool>> usedCoords;

	void handle_arg(char * entry, size_t entrySize);
	void process_new_args();
	int run_external(unsigned long targaddr, unsigned long repeats, NODEPAIR *resultPair);

	void TID_thread();
	int runBB(unsigned long startAddress, int startIndex, int insCount, int repeats);
	void positionVert(int *pa, int *pb, int *pbMod, long address);
	void updateStats(int a, int b, int bMod);
	void insert_edge(edge_data e, NODEPAIR edgepair);
	bool is_old_instruction(INS_DATA *instruction, unsigned int *vertIdx);
	void handle_new_instruction(INS_DATA *instruction,int mutation, int bb_inslist_index);
	void handle_existing_instruction(INS_DATA *instruction);
	bool get_extern_at_address(long address, BB_DATA ** BB);
	bool find_internal_at_address(long address);
	void increaseWeight(edge_data *edge, long executions);
	void handle_tag(TAG thistag, unsigned long repeats);
	void update_conditional_state(unsigned long nextAddress);
	int find_containing_module(unsigned long address);

	unsigned long pendingFunc = 0;
	unsigned long pendingRet = 0;
	ARGLIST pendingArgs;
	vector<FAILEDARGS> repeatArgAttempts;

#define NO_LOOP 0
#define LOOP_CACHE_BUILD 1
#define LOOP_START 2
#define LOOP_PROGRESS 3

	unsigned long loopCount = 0;
	unsigned int firstLoopVert = 0;
	int loopState = NO_LOOP;
	//tag address, mod type
	vector<TAG> loopCache;
	NODEPAIR repeatStart;
	NODEPAIR repeatEnd;
	
};