#pragma once
#include <stdafx.h>
#include "proto_graph.h"
#include "opengl_operations.h"
#include "GUIConstants.h"

#define KEEP_BRIGHT -1

struct VERTREMAINING {
	unsigned int vertIdx;
	unsigned int timeRemaining;
};

struct HIGHLIGHT_DATA {
	int highlightState = 0;
	string highlight_s;
	MEM_ADDRESS highlightAddr;
	int highlightModule = 0;
	vector<node_data *> highlightNodes;
};

struct PLOT_TRACK {
	unsigned int lastVertID;
	unsigned int lastVertType;
};

class plotted_graph
{
public:
	plotted_graph(PROCESS_DATA *processdata, unsigned int threadID, proto_graph *protoGraph);
	~plotted_graph();

	proto_graph * get_protoGraph() { return internalProtoGraph; }

	bool needVBOReload_preview = true;
	bool previewNeedsResize = false;
	GLuint previewVBOs[4] = { 0,0,0,0 };
	GRAPH_DISPLAY_DATA *previewnodes = 0;
	GRAPH_DISPLAY_DATA *previewlines = 0;

	bool needVBOReload_heatmap = true;
	//lowest/highest numbers of edge iterations
	pair<unsigned long, unsigned long> heatExtremes;
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

	long long userSelectedAnimPosition = -1;

	bool needVBOReload_active = true;
	//two sets of VBOs for graph so we can display one
	//while the other is being written
	int lastVBO = 2;
	GLuint activeVBOs[4] = { 0,0,0,0 };

	//active areas + inactive areas
	GRAPH_DISPLAY_DATA *animnodesdata = 0;
	GRAPH_DISPLAY_DATA *animlinedata = 0;

	ALLEGRO_BITMAP *previewBMP = NULL;

	bool VBOsGenned = false;
	GLuint graphVBOs[4] = { 0,0,0,0 };
	void gen_graph_VBOs();

	float getAnimationPercent() { return (float)((float)animationIndex / (float)internalProtoGraph->savedAnimationData.size()); }
	void set_max_wait_frames(unsigned int frames) { maxWaitFrames = frames; }

	void display_highlight_lines(vector<node_data *> *nodeList, ALLEGRO_COLOR *colour, int lengthModifier);
	void rescale_nodes(bool isPreview);
	int draw_new_nodes(GRAPH_DISPLAY_DATA *vertsdata, map<int, ALLEGRO_COLOR> *nodeColours);

	MULTIPLIERS *main_scalefactors = NULL;
	MULTIPLIERS *preview_scalefactors = NULL;

	unsigned long vertResizeIndex = 0;


	void display_active(bool showNodes, bool showEdges);
	void display_static(bool showNodes, bool showEdges);
	virtual void draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd) {};
	virtual void show_symbol_labels(VISSTATE *clientState, PROJECTDATA *pd) {};
	int draw_new_preview_edges(VISSTATE* clientState);
	virtual void render_static_graph(VISSTATE *clientState) {};
	void updateMainRender(VISSTATE *clientState);
	virtual void plot_wireframe(VISSTATE *clientState) {};
	virtual void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes) {};
	virtual void performMainGraphDrawing(VISSTATE *clientState, map <PID_TID, vector<EXTTEXT>> *externFloatingText) {};
	int render_preview_graph(VISSTATE *clientState);

	bool isGraphBusy();
	void setGraphBusy(bool set);

	void reset_animation();
	int render_replay_animation(int stepSize, float fadeRate);

	GRAPH_DISPLAY_DATA *get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA *get_mainnodes() { return mainnodesdata; }

	void render_live_animation(float fadeRate);
	long zoomLevel = 0;

	HIGHLIGHT_DATA highlightData;
	bool needVBOReload_main = true;
	virtual bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate) { return false;	};

protected:
	virtual void positionVert(void *positionStruct, MEM_ADDRESS address) {};
	
	virtual void display_graph(VISSTATE *clientState, PROJECTDATA *pd) {};

	

	PID_TID  tid, pid;
	proto_graph *internalProtoGraph;

	

	//keep track of which a,b coords are occupied
	std::map<pair<int, int>, bool> usedCoords;	

	void display_big_conditional(VISSTATE *clientState);
	void display_big_heatmap(VISSTATE *clientState);

	//get on-screen xyz coords of node
	virtual FCOORD nodeCoordB(MULTIPLIERS *dimensions, float diamModifier, unsigned int index) { cerr << "Warning: Virtual func called\n" << endl; FCOORD x; return x; };
	virtual void drawHighlight(unsigned int nodeIndex, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier) { cerr << "Warning: Virtual func called\n" << endl; };
	virtual int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		MULTIPLIERS *dimensions, map<int, ALLEGRO_COLOR> *nodeColours) {
		cerr << "Warning: Virtual func called\n" << endl; return 0;
	};
	virtual void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd) { cerr << "Warning: Virtual func called\n" << endl; };
	virtual void draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata) { cerr << "Warning: Virtual func called\n" << endl; };

	PLOT_TRACK lastPreviewNode;
	PLOT_TRACK lastMainNode;


	//keep track of graph dimensions
	int maxA = 0;
	int maxB = 0;

	void extend_faded_edges();
	int render_new_edges(bool doResize, map<int, ALLEGRO_COLOR> *lineColoursArr, map<int, ALLEGRO_COLOR> *nodeColours);
	void redraw_anim_edges();

	void reset_mainlines();

	
	map <pair<NODEINDEX, unsigned int>, int> newExternTimes;
	map <NODEINDEX, EXTTEXT> activeExternTimes;

	vector <ANIMATIONENTRY> currentUnchainedBlocks;

	void render_animation(float fadeRate);

	GRAPH_DISPLAY_DATA *get_previewnodes() { return previewnodes; }
	GRAPH_DISPLAY_DATA *get_activelines() { return animlinedata; }
	GRAPH_DISPLAY_DATA *get_activenodes() { return animnodesdata; }

	GRAPH_DISPLAY_DATA *mainnodesdata = 0;
	GRAPH_DISPLAY_DATA *mainlinedata = 0;

	//for keeping track of graph dimensions
	virtual void updateStats(int a, int b, unsigned int bMod);

private:
	HANDLE graphwritingMutex = CreateMutex(NULL, FALSE, NULL);

	void set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);
	void set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha) {};

	//node+edge col+pos
	bool fill_block_vertlist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *vertlist);


	void process_live_animation_updates();
	int process_replay_animation_updates(int stepSize);
	void brighten_new_active();
	void maintain_active();
	void darken_fading(float fadeRate);
	void remove_unchained_from_animation();
	unsigned long calculate_wait_frames(unsigned int stepSize, unsigned long executions);
	void clear_active();
	void removeEntryFromQueue();

	NODEINDEX lastAnimatedNode = 0;
	unsigned long animLoopCounter = 0;
	unsigned int unchainedWaitFrames = 0;
	unsigned int maxWaitFrames = 0;
	unsigned long entriesProcessed = 0;

	//which BB we are pointing to in the sequence list
	unsigned long animationIndex = 0;

	map <NODEINDEX, int> newAnimNodeTimes;
	map <unsigned int, int> activeAnimNodeTimes;
	set <unsigned int> fadingAnimNodes;

	map <NODEPAIR, int> newAnimEdgeTimes;
	map <NODEPAIR, int> activeAnimEdgeTimes;
	set <NODEPAIR> fadingAnimEdges;

	bool animBuildingLoop = false;


};

