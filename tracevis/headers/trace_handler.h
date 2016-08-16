#pragma once
#include "traceStructs.h"
#include "node_data.h"
#include "edge_data.h"
#include "thread_graph_data.h"
#include "GUIStructs.h"

struct TAG {
	unsigned long targaddr;
	int insCount;
	int jumpModifier;
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
	PID_DATA *piddata;
	

protected:

	//important state variables!
	unsigned int lastVertID = 0; //the vert that led to this instruction
	unsigned int targVertID = 0; //new vert we are creating
	char lastRIPType = FIRST_IN_THREAD;
	unsigned long conditionalTaken = 0;
	bool afterReturn = false;

	thread_graph_data *thisgraph;

	//important lists!
	//map<unsigned int, node_data> *vertDict; //vert id to vert data
	map<std::pair<unsigned int, unsigned int>, edge_data> *edgeDict; //vert id pairs to edge data
	vector<pair<unsigned int, unsigned int>> *edgeList;//order of edge execution
	void handle_arg(char * entry, size_t entrySize);
	map<int, long> vertBBDict; //basicblock address of each vert //delme?? todo
	void transferBufferedArgs(BB_DATA *parentbb, unsigned long targaddr, node_data *targetNode);
	//bool insert_pending_args_into_node(unsigned long targaddress, int callerid, int externid);
	int run_external(unsigned long targaddr, unsigned long repeats, std::pair<int, int> *resultPair);

	vector<pair<long, int>> callStack;

	//keep track of which a,b coords are occupied
	map<int, map<int,bool>> usedCoords;
	


private:
	ofstream tmpThreadSave;

	void TID_thread();
	void runBB(unsigned long startAddress, int startIndex, int insCount, int repeats);
	void positionVert(int *pa, int *pb, int *pbMod, long address);
	void updateStats(int a, int b, int bMod);
	void insert_edge(edge_data e, pair<int, int> edgepair);
	void insert_vert(int targVertID, node_data thisNode);
	bool new_instruction(INS_DATA *instruction);
	void handle_new_instruction(INS_DATA *instruction, int bb_inslist_index, node_data *lastNode);
	void handle_existing_instruction(INS_DATA *instruction, node_data *lastNode);
	int get_extern_at_address(long address, BB_DATA ** BB);
	void increaseWeight(edge_data *edge, long executions);
	void handle_tag(TAG thistag, unsigned long repeats);

	unsigned long pendingFunc = 0;
	unsigned long pendingRet = 0;
	vector<pair<int, string>> pendingArgs;
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
	pair<unsigned int, unsigned int> repeatStart;
	pair<unsigned int, unsigned int> repeatEnd;
	
};

//void TID_thread(thread_start_data *startData);