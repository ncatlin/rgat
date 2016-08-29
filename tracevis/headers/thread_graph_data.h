#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "traceMisc.h"

//max length to display in diff summary
#define MAX_DIFF_PATH_LENGTH 50
#define ANIMATION_ENDED -1
#define ANIMATION_WIDTH 8
#define MINIMUM_FADE_ALPHA 0.2


struct EXTERNCALLDATA {
	NODEPAIR edgeIdx;
	unsigned int nodeIdx;
	ARGLIST fdata;
	unsigned long callerAddr = 0;
	string externPath;
};

class thread_graph_data
{
private:
	GRAPH_DISPLAY_DATA *mainnodesdata = 0;
	GRAPH_DISPLAY_DATA *mainlinedata = 0;

	unsigned int lastAnimatedBB = 0;
	unsigned int firstAnimatedBB = 0;
	int baseMod = -1;
	HANDLE disassemblyMutex;

	map<unsigned int, node_data> nodeDict; //node id to node data
	map <unsigned long, vector<INS_DATA*>> *disassembly;

	EDGELIST activeEdgeList;
	vector <unsigned int> activeNodeList;
	map<NODEPAIR, edge_data> edgeDict; //node id pairs to edge data
	EDGELIST edgeList; //order of edge execution

	HANDLE edMutex = CreateMutex(NULL, FALSE, NULL);
	HANDLE nodeDMutex = CreateMutex(NULL, FALSE, NULL);

	bool advance_sequence(bool);
	bool decrease_sequence();

	bool loadEdgeDict(ifstream *file);
	bool loadExterns(ifstream *file);
	bool loadNodes(ifstream *file, map <unsigned long, vector<INS_DATA *>> *disassembly);
	bool loadStats(ifstream *file);
	bool loadAnimationData(ifstream *file);
	bool loadCallSequence(ifstream *file);

	//which BB we are pointing to in the sequence list
	unsigned long sequenceIndex = 0;
	//which instruction we are pointing to in the BB
	unsigned long blockInstruction = 0;
	bool newanim = true;
	unsigned int last_anim_start = 0;
	unsigned int last_anim_stop = 0;

public:
	thread_graph_data(map <unsigned long, vector<INS_DATA*>> *disassembly, HANDLE disasMutex);
	~thread_graph_data();

	void display_active(bool showNodes, bool showEdges);
	void display_static(bool showNodes, bool showEdges);

	int render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour = 0, bool preview = false);
	edge_data *get_edge(NODEPAIR edge);
	bool edge_exists(NODEPAIR edge);
	void add_edge(edge_data e, NODEPAIR edge);
	void insert_node(int targVertID, node_data node); 
	void extend_faded_edges();
	void assign_modpath(PROCESS_DATA *);
	GRAPH_DISPLAY_DATA *get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA *get_mainnodes() { return mainnodesdata; }
	GRAPH_DISPLAY_DATA *get_activelines() { return animlinedata; }
	GRAPH_DISPLAY_DATA *get_activenodes() { return animnodesdata; }
	void render_new_edges(bool doResize, map<int, ALLEGRO_COLOR> *lineColoursArr);

	bool serialise(ofstream *file);
	bool unserialise(ifstream *file, map <unsigned long, vector<INS_DATA *>> *disassembly);

	node_data *get_node(unsigned int index)
	{
		obtainMutex(nodeDMutex,0, 500); 
		node_data *n = &nodeDict.at(index); 
		dropMutex(nodeDMutex); return n;
	}

	bool node_exists(unsigned int idx) { if (nodeDict.count(idx)) return true; return false; }
	unsigned int get_num_nodes() { return nodeDict.size();}
	unsigned int get_num_edges() { return edgeDict.size();}

	void start_edgeD_iteration(map<NODEPAIR, edge_data>::iterator *edgeit,
		map<NODEPAIR, edge_data>::iterator *edgeEnd);
	void stop_edgeD_iteration();

	void start_edgeL_iteration(EDGELIST::iterator *edgeIt, EDGELIST::iterator *edgeEnd);
	void stop_edgeL_iteration();

	map<unsigned int, node_data>::iterator get_nodeStart() { return nodeDict.begin(); }
	map<unsigned int, node_data>::iterator get_nodeEnd() { return nodeDict.end(); }
	unsigned long get_sequenceLen() { return bbsequence.size(); }
	void animate_latest();

	INS_DATA* get_last_instruction(unsigned long sequenceId);
	string get_node_sym(unsigned int idx, PROCESS_DATA* piddata);
	void highlight_externs(unsigned long targetSequence);

	void reset_mainlines();
	node_data *derive_anim_node();
	void performStep(int stepSize, bool skipLoop);
	unsigned int updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop);
	node_data * get_active_node();
	void set_active_node(int idx) {	latest_active_node = &nodeDict[idx];}
	void update_animation_render();
	void reset_animation();
	void darken_animation(float alphaDelta);

	void brighten_BBs();
	void set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);
	void set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha);
	void emptyArgQueue();
	vector <string> loggedCalls;

	node_data * latest_active_node = 0;

	unsigned int tid = 0;
	unsigned int pid = 0;
	bool active = true;
	bool terminated = false;

	ALLEGRO_BITMAP *previewBMP = NULL;
	std::queue<EXTERNCALLDATA> funcQueue;

	HANDLE animationListsMutex = CreateMutex(NULL, FALSE, NULL);
	map<unsigned int, EDGELIST> externCallSequence;

	vector<int> externList; //list of external calls
	string modPath;


	HANDLE funcQueueMutex = CreateMutex(NULL, FALSE, NULL);
	map <unsigned int, unsigned int> callCounter;
	//ugh
	//   funcaddress	      caller		
	map<unsigned long, map <unsigned long, vector<ARGLIST>>> pendingcallargs;

	//keep track of graph dimensions
	int maxA = 0;
	int maxB = 0;
	int bigBMod = 0;
	long zoomLevel = 0;

	unsigned long maxWeight = 0;

	MULTIPLIERS *m_scalefactors = NULL;
	MULTIPLIERS *p_scalefactors = NULL;

	//node+edge col+pos
	bool needVBOReload_main = false;
	GLuint graphVBOs[4] = { 0,0,0,0 };
	

	//node+edge col+pos
	bool needVBOReload_preview = false;
	GLuint previewVBOs[4] = { 0,0,0,0 };
	GRAPH_DISPLAY_DATA *previewnodes = 0;
	GRAPH_DISPLAY_DATA *previewlines = 0;

	bool finalHeatmap = false;
	bool needVBOReload_heatmap = false;
	GLuint heatmapEdgeVBO[1] = { 0 };
	GRAPH_DISPLAY_DATA *heatmaplines = 0;

	bool needVBOReload_conditional = false;
	GLuint conditionalVBOs[2] = { 0 };
	GRAPH_DISPLAY_DATA *conditionallines = 0;
	GRAPH_DISPLAY_DATA *conditionalnodes = 0;

	vector <pair<unsigned long,int>> bbsequence; //block address, number of instructions
	vector <int> mutationSequence;

	//<which loop this is, how many iterations>
	vector <pair<unsigned int, unsigned long>> loopStateList;

	vector<unsigned int> animLoopProgress;
	unsigned long animLoopStartIdx = 0;
	unsigned long animLoopIndex = 0;
	//total number of individual loops
	unsigned int loopCounter = 0;

	//position out of all the instructions instrumented
	unsigned long animInstructionIndex = 0;
	unsigned long totalInstructions = 0;

	unsigned int loopsPlayed = 0;
	unsigned long loopIteration = 0;
	unsigned long targetIterations = 0;

	bool needVBOReload_active = false;
	GLuint activeVBOs[4] = { 0,0,0,0 };

	//active areas + inactive areas
	GRAPH_DISPLAY_DATA *animnodesdata = 0;
	GRAPH_DISPLAY_DATA *animlinedata = 0;

	void highlightNodes(vector<node_data *> *nodeList, ALLEGRO_COLOR *colour, int lengthModifier);
};

