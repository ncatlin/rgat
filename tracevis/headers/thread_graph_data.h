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
Monsterous class that handles the bulk of graph management 
*/

#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "traceMisc.h"
#include "OSspecific.h"

//max length to display in diff summary
#define MAX_DIFF_PATH_LENGTH 50
#define ANIMATION_ENDED -1
#define ANIMATION_WIDTH 8

struct EXTERNCALLDATA {
	NODEPAIR edgeIdx;
	unsigned int nodeIdx;
	ARGLIST argList;
	MEM_ADDRESS callerAddr = 0;
	string externPath;
	bool drawFloating = false;
};

#define ANIM_EXEC_TAG 0
#define ANIM_LOOP 1
#define ANIM_LOOP_LAST 2
#define ANIM_UNCHAINED 3
#define ANIM_UNCHAINED_RESULTS 4
#define ANIM_UNCHAINED_DONE 5
#define ANIM_EXEC_EXCEPTION 6

#define KEEP_BRIGHT -1

struct ANIMATIONENTRY {
	char entryType;
	MEM_ADDRESS blockAddr;
	BLOCK_IDENTIFIER blockID;
	unsigned long count;
	MEM_ADDRESS targetAddr;
	BLOCK_IDENTIFIER targetID;
};

struct VERTREMAINING {
	unsigned int vertIdx;
	unsigned int timeRemaining;
};

class thread_graph_data
{
	GRAPH_DISPLAY_DATA *mainnodesdata = 0;
	GRAPH_DISPLAY_DATA *mainlinedata = 0;

	EDGEMAP edgeDict; //node id pairs to edge data
	EDGELIST edgeList; //order of edge execution

	unsigned int lastAnimatedBB = 0;
	unsigned int firstAnimatedBB = 0;
	vector<node_data> nodeList; //node id to node data

	
	PROCESS_DATA* piddata;
	int baseMod = -1;
	HANDLE disassemblyMutex;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <unsigned int, bool> activeNodeMap;


#ifdef XP_COMPATIBLE
	HANDLE nodeLMutex = CreateMutex(NULL, FALSE, NULL);
	HANDLE edMutex = CreateMutex(NULL, FALSE, NULL);
#else
	SRWLOCK nodeLock = SRWLOCK_INIT;
	SRWLOCK edgeLock = SRWLOCK_INIT;
#endif

	inline void getEdgeReadLock();
	inline void getEdgeWriteLock();
	inline void dropEdgeReadLock();
	inline void dropEdgeWriteLock();

	inline void getNodeReadLock();
	inline void dropNodeReadLock();
	inline void getNodeWriteLock();
	inline void dropNodeWriteLock();

	//bool advance_sequence(bool);
	//bool decrease_sequence();

	bool loadEdgeDict(ifstream *file);
	bool loadExterns(ifstream *file);
	bool loadExceptions(ifstream *file);
	bool loadNodes(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly);
	bool loadStats(ifstream *file);
	bool loadAnimationData(ifstream *file);

	//which BB we are pointing to in the sequence list
	unsigned long animationIndex = 0;
	//which instruction we are pointing to in the BB
	unsigned long blockInstruction = 0;
	bool newanim = true;
	unsigned int last_anim_start = 0;
	unsigned int last_anim_stop = 0;

	void *trace_reader;
	
	//updated with backlog input/processing each second for display
	//dunno if ulong reads are atomic, not vital for this application
	//adding accessor functions for future threadsafe acesss though
	pair<unsigned long, unsigned long> backlogInOut = make_pair(0, 0);
	
	bool fill_block_vertlist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *vertlist);

	void process_live_animation_updates();
	int process_replay_animation_updates(int stepSize);
	void brighten_new_active();
	void maintain_active();
	void darken_fading(float fadeRate);
	void remove_unchained_from_animation();
	unsigned long calculate_wait_frames(unsigned int stepSize, unsigned long executions);

	map <NODEINDEX, int> newAnimNodeTimes;
	map <unsigned int, int> activeAnimNodeTimes;
	set <unsigned int> fadingAnimNodes;

	map <NODEPAIR, int> newAnimEdgeTimes;
	map <NODEPAIR, int> activeAnimEdgeTimes;
	set <NODEPAIR> fadingAnimEdges;

	map <NODEINDEX, int> newExternTimes;
	map <NODEINDEX, EXTTEXT> activeExternTimes;

	//animation data as it is received from drgat
	queue <ANIMATIONENTRY> animUpdates;
	//animation data saved here for replays
	vector <ANIMATIONENTRY> savedAnimationData;
	vector <ANIMATIONENTRY> currentUnchainedBlocks;

	NODEINDEX lastAnimatedNode = 0;
	unsigned long animLoopCounter = 0;
	unsigned int unchainedWaitFrames = 0;
	unsigned int maxWaitFrames = 0;

public:
	thread_graph_data(PROCESS_DATA* processdata, unsigned int threadID);
	~thread_graph_data();

	void display_active(bool showNodes, bool showEdges);
	void display_static(bool showNodes, bool showEdges);

	void draw_externTexts(ALLEGRO_FONT *font, bool nearOnly, int left, int right, int height, PROJECTDATA *pd);

	void acquireNodeReadLock() { getNodeReadLock(); }
	void releaseNodeReadLock() { dropNodeReadLock(); }

	int render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour = 0, bool preview = false);
	
	bool edge_exists(NODEPAIR edge, edge_data **edged);
	void add_edge(edge_data e, node_data *source, node_data *target);
	void insert_node(NODEINDEX targVertID, node_data node); 
	void extend_faded_edges();
	void assign_modpath(PROCESS_DATA *);
	GRAPH_DISPLAY_DATA *get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA *get_mainnodes() { return mainnodesdata; }
	GRAPH_DISPLAY_DATA *get_previewnodes() { return previewnodes; }
	GRAPH_DISPLAY_DATA *get_activelines() { return animlinedata; }
	GRAPH_DISPLAY_DATA *get_activenodes() { return animnodesdata; }
	void render_new_edges(bool doResize, map<int, ALLEGRO_COLOR> *lineColoursArr);
	void redraw_anim_edges();
	void set_max_wait_frames(unsigned int frames) { maxWaitFrames = frames; }

	void push_anim_update(ANIMATIONENTRY);

	unsigned int fill_extern_log(ALLEGRO_TEXTLOG *textlog, unsigned int logSize);

	bool serialise(ofstream *file);
	bool unserialise(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly);

	//these are called a lot. make sure as efficient as possible
	inline edge_data *get_edge(NODEPAIR edge);
	edge_data * get_edge(unsigned int edgeindex);
	edge_data *get_edge_create(node_data *source, node_data *target);

	inline node_data *unsafe_get_node(unsigned int index);
	node_data *safe_get_node(unsigned int index);

	void insert_edge_between_BBs(INSLIST *source, INSLIST *target);

	bool node_exists(unsigned int idx) { if (nodeList.size() > idx) return true; return false; }
	unsigned int get_num_nodes() { return nodeList.size();}
	unsigned int get_num_edges() { return edgeDict.size();}

	void start_edgeD_iteration(EDGEMAP::iterator *edgeit, EDGEMAP::iterator *edgeEnd);
	void stop_edgeD_iteration();

	void start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd);
	void stop_edgeL_iteration();

	//i feel like this misses the point, idea is to iterate safely
	EDGELIST *edgeLptr() { return &edgeList; } 

	void render_animation(float fadeRate);
	void render_live_animation(float fadeRate);
	int render_replay_animation(int stepSize, float fadeRate);


	INS_DATA* get_last_instruction(unsigned long sequenceId);
	string get_node_sym(unsigned int idx, PROCESS_DATA* piddata);

	void reset_mainlines();
	//unsigned int derive_anim_node();
	//void performStep(int stepSize, bool skipLoop);
	//unsigned int updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop);
	VCOORD *get_active_node_coord();
	void set_active_node(unsigned int idx);
	void reset_animation();
	
	void set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);
	void set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha);
	void emptyArgQueue();
	vector <string> loggedCalls;

	VCOORD latest_active_node_coord;
	//used to keep a blocking extern highlighted - may not be useful with new method TODO
	unsigned int latest_active_node_idx = 0;
	//used by heatmap solver
	unsigned int finalNodeID = 0;

	PID_TID tid = 0;
	PID_TID pid = 0;
	bool active = true;
	bool terminated = false;

	ALLEGRO_BITMAP *previewBMP = NULL;
	//sym/arg strings that are to be made floating
	std::queue<EXTERNCALLDATA> floatingExternsQueue;

	HANDLE animationListsMutex = CreateMutex(NULL, FALSE, NULL);

	//list of external calls used for listing possible highlights
	HANDLE highlightsMutex = CreateMutex(NULL, FALSE, NULL);
	vector<unsigned int> externList; 
	set<unsigned int> exceptionSet;
	string modPath;

	HANDLE funcQueueMutex = CreateMutex(NULL, FALSE, NULL);
	//number of times each extern called, used for tracking which arg to display
	map <unsigned int, unsigned long> callCounter;

	//keep track of graph dimensions
	int maxA = 0;
	int maxB = 0;
	long zoomLevel = 0;

	unsigned long vertResizeIndex = 0;

	MULTIPLIERS *m_scalefactors = NULL;
	MULTIPLIERS *p_scalefactors = NULL;


	bool needVBOReload_main = true;
	GLuint graphVBOs[4] = { 0,0,0,0 };

	HANDLE graphwritingMutex = CreateMutex(NULL, FALSE, NULL);
	
	bool isGraphBusy();
	void setGraphBusy(bool set);

	bool VBOsGenned = false;
	//node+edge col+pos
	bool needVBOReload_preview = true;
	bool previewNeedsResize = false;
	GLuint previewVBOs[4] = { 0,0,0,0 };
	GRAPH_DISPLAY_DATA *previewnodes = 0;
	GRAPH_DISPLAY_DATA *previewlines = 0;

	bool needVBOReload_heatmap = true;
	//lowest/highest numbers of edge iterations
	pair<unsigned long,unsigned long> heatExtremes;
	GLuint heatmapEdgeVBO[1] = { 0 };
	GRAPH_DISPLAY_DATA *heatmaplines = 0;

	bool needVBOReload_conditional = true;
	//number of taken, not taken conditionals
	pair<unsigned long, unsigned long> condCounts;
	GLuint conditionalVBOs[2] = { 0 };
	GRAPH_DISPLAY_DATA *conditionallines = 0;
	GRAPH_DISPLAY_DATA *conditionalnodes = 0;


	//position out of all the instructions instrumented
	unsigned long animInstructionIndex = 0;
	unsigned long totalInstructions = 0;

	bool needVBOReload_active = true;
	//two sets of VBOs for graph so we can display one
	//while the other is being written
	int lastVBO = 2;
	GLuint activeVBOs[4] = { 0,0,0,0 };

	//active areas + inactive areas
	GRAPH_DISPLAY_DATA *animnodesdata = 0;
	GRAPH_DISPLAY_DATA *animlinedata = 0;

	void display_highlight_lines(vector<node_data *> *nodeList, ALLEGRO_COLOR *colour, int lengthModifier);

	unsigned long traceBufferSize = 0;
	void *getReader() { return trace_reader;}
	void setReader(void *newReader) { trace_reader = newReader;}

	void setBacklogIn(unsigned long in) { backlogInOut.first = in; }
	void setBacklogOut(unsigned long out) { backlogInOut.second = out; }
	unsigned long getBacklogIn() { return backlogInOut.first; }
	unsigned long getBacklogOut() { return backlogInOut.second; }
	unsigned long get_backlog_total();
	bool terminationFlag = false;
};

