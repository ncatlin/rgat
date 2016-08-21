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
	pair<unsigned int, unsigned int> edgeIdx;
	unsigned int nodeIdx;
	vector<pair<int, string>> fdata;
	unsigned long callerAddr = 0;
	string externPath;
};
class thread_graph_data
{
private:
	GRAPH_DISPLAY_DATA *mainvertsdata = 0;
	GRAPH_DISPLAY_DATA *mainlinedata = 0;
	map<unsigned int, node_data> vertDict; //node id to node data
	map <unsigned long, vector<INS_DATA*>> *disassembly;
	unsigned int lastAnimatedBB = 0;
	unsigned int firstAnimatedBB = 0;
	vector<pair<unsigned int, unsigned int>> activeEdgeList;
	vector <unsigned int> activeNodeList;
	bool advance_sequence(bool);
	bool decrease_sequence();
	HANDLE disassemblyMutex;

public:
	thread_graph_data(map <unsigned long, vector<INS_DATA*>> *disassembly, HANDLE disasMutex);
	~thread_graph_data();

	void display_active(bool showNodes, bool showEdges);
	void display_static(bool showNodes, bool showEdges);

	int render_edge(pair<int, int> ePair, GRAPH_DISPLAY_DATA *edgedata, vector<ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour = 0, bool preview = false);
	void extend_faded_edges();
	void assign_modpath(PID_DATA *);
	GRAPH_DISPLAY_DATA *get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA *get_mainverts() { return mainvertsdata; }
	GRAPH_DISPLAY_DATA *get_activelines() { return animlinedata; }
	GRAPH_DISPLAY_DATA *get_activeverts() { return animvertsdata; }

	HANDLE vertDMutex = CreateMutex(NULL, FALSE, NULL);
	node_data *get_vert(unsigned int index)
	{
		obtainMutex(vertDMutex,0, 500); node_data *n = &vertDict.at(index); dropMutex(vertDMutex); return n;
	}
	void add_vert(pair<unsigned int, node_data> newnodepair) 
	{
		obtainMutex(vertDMutex, 0, 500); vertDict.insert(newnodepair); dropMutex(vertDMutex);
	}

	bool vert_exists(unsigned int idx) { if (vertDict.count(idx)) return true; return false; }
	unsigned int get_num_verts() { return vertDict.size();}
	map<unsigned int, node_data>::iterator get_vertStart() { return vertDict.begin(); }
	map<unsigned int, node_data>::iterator get_vertEnd() { return vertDict.end(); }
	unsigned long get_sequenceLen() { return bbsequence.size(); }
	void animate_latest();
	void set_block_alpha(unsigned long firstInstruction, unsigned int quantity,
		GLfloat *nodecols, GLfloat *edgecols,  float alpha);

	INS_DATA* get_last_instruction(unsigned long sequenceId);
	string get_node_sym(unsigned int idx) { return vertDict[idx].nodeSym; }
	void highlight_externs(unsigned long targetSequence);
	

	void reset_mainlines();
	node_data *derive_anim_node();
	void performStep(int stepSize, bool skipLoop);
	unsigned int updateAnimation(unsigned int updateSize, bool animationMode, bool skipLoop);
	node_data * get_active_node();
	void set_active_node(int idx) {	latest_active_node = &vertDict[idx];}
	void update_animation_render();
	void clear_final_BBs();
	void reset_animation();
	void darken_animation(float alphaDelta);

	void brighten_BBs();
	void set_edge_alpha(pair<unsigned int, unsigned int> eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);
	void set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha);
	void emptyArgQueue();
	vector <string> loggedCalls;

	map <unsigned long, vector <BB_DATA *>> mutationMap;

	node_data * latest_active_node = 0;

	bool serialise(ofstream *file);

	unsigned int tid = 0;
	unsigned int pid = 0;
	bool active = true;
	bool terminated = false;

	ALLEGRO_BITMAP *previewBMP = NULL;
	std::queue<EXTERNCALLDATA> funcQueue;

	HANDLE callSeqMutex = CreateMutex(NULL, FALSE, NULL);
	map<unsigned int, vector<std::pair<int, int>>> externCallSequence;

	HANDLE edMutex = CreateMutex(NULL, FALSE, NULL);
	map<std::pair<unsigned int, unsigned int>, edge_data> edgeDict; //node id pairs to edge data
	vector<pair<unsigned int, unsigned int>> edgeList; //order of edge execution
	vector<pair<int, long>> externList; //list of external calls
	string modPath;
	int baseMod = -1;


	HANDLE funcQueueMutex = CreateMutex(NULL, FALSE, NULL);
	map <unsigned int, unsigned int> callCounter;
	//ugh
	//   funcaddress	      caller					 argid  arg
	map<unsigned long, map <unsigned long, vector<vector <pair<int, string>>>>> pendingcallargs;

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
	GRAPH_DISPLAY_DATA *previewverts = 0;
	GRAPH_DISPLAY_DATA *previewlines = 0;

	bool finalHeatmap = false;
	bool needVBOReload_heatmap = false;
	GLuint heatmapEdgeVBO[1] = { 0 };
	GRAPH_DISPLAY_DATA *heatmaplines = 0;

	bool needVBOReload_conditional = false;
	GLuint conditionalVBOs[2] = { 0 };
	GRAPH_DISPLAY_DATA *conditionallines = 0;
	GRAPH_DISPLAY_DATA *conditionalverts = 0;

	vector <pair<unsigned long,int>> bbsequence;
	vector <pair<unsigned int, unsigned int>> sequenceEdges;
	//loop end/loop iterations pair
	vector <pair<unsigned int, unsigned long>> loopStateList;
	vector<unsigned int> animLoopProgress;
	unsigned long animLoopStartIdx= 0;
	unsigned long animLoopIndex = 0;
	//number of individual loops
	unsigned int loopCounter = 0;

	//which BB we are pointing to in the sequence list
	unsigned long sequenceIndex = 0;
	//which instruction we are pointing to in the BB
	unsigned long blockInstruction = 0;

	bool newanim = true;
	unsigned int last_anim_start = 0;
	unsigned int last_anim_stop = 0;
	//position out of all the instructions instrumented
	unsigned long animInstructionIndex = 0;
	unsigned long totalInstructions = 0;

	unsigned int loopsPlayed = 0;
	unsigned long loopIteration = 0;
	unsigned long targetIterations = 0;

	bool needVBOReload_active = false;
	GLuint activeVBOs[4] = { 0,0,0,0 };

	//active areas + inactive areas
	GRAPH_DISPLAY_DATA *animvertsdata = 0;
	GRAPH_DISPLAY_DATA *animlinedata = 0;
};

