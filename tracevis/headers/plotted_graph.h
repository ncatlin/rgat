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
Generic rendered graph, constructs a (graphical) graph from a control flow graph
Requires inheriting to give it a layout (eg: sphere_graph)
*/

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
	unsigned int lastVertID = 0;
	eEdgeNodeType lastVertType = eNodeNonFlow;
};

struct SCREEN_QUERY_PTRS {
	VISSTATE *clientState;
	GRAPH_DISPLAY_DATA *mainverts;
	PROJECTDATA *pd;
	bool show_all_always;
};

class plotted_graph
{
public:
	plotted_graph(proto_graph *protoGraph, vector<ALLEGRO_COLOR> *graphColoursPtr);
	~plotted_graph();

	virtual void initialiseDefaultDimensions() {};
	virtual bool get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo) { cerr << "Warning: Virtual gvnp called"; return false; };
	virtual void render_static_graph(VISSTATE *clientState) {};
	virtual void plot_wireframe(VISSTATE *clientState) {};
	virtual void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes) {};
	virtual void performMainGraphDrawing(VISSTATE *clientState) {};
	virtual void orient_to_user_view(int xshift, int yshift, long zoom) {};
	virtual bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata,
		ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate) {	return false;};
	virtual unsigned int get_graph_size() { return 0; };

	virtual void toggle_autoscale() {};
	virtual bool pending_rescale() { return false; }
	virtual void adjust_A_edgeSep(float delta) {};
	virtual void adjust_B_edgeSep(float delta) {};
	virtual void reset_edgeSep() {};
	virtual void adjust_size(float delta) {};

	virtual void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier) { cerr << "Warning: Virtual drawHighlight called\n" << endl; };
	virtual void drawHighlight(void* graphCoord, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier) { cerr << "Warning: Virtual drawHighlight called\n" << endl; };

	void updateMainRender(VISSTATE *clientState);
	bool setGraphBusy(bool set);
	void reset_animation();
	void gen_graph_VBOs();
	int render_replay_animation(int stepSize, float fadeRate);
	int render_preview_graph(VISSTATE *clientState);
	float getAnimationPercent() { return (float)((float)animationIndex / (float)internalProtoGraph->savedAnimationData.size()); }
	void render_live_animation(float fadeRate);
	void set_last_active_node();
	void draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);
	void show_symbol_labels(VISSTATE *clientState, PROJECTDATA *pd);

	proto_graph * get_protoGraph() { return internalProtoGraph; }
	bool isWireframeSupported() { return wireframeSupported; }
	long get_zoom() { return defaultZoom; };
	pair <long, long> getStartShift() { return defaultViewShift; };
	PID_TID get_pid() { return pid; }
	PID_TID get_tid() { return tid; }
	graphLayouts getLayout() { return layout; }

	GLuint graphVBOs[4] = { 0,0,0,0 };

	GRAPH_DISPLAY_DATA *get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA *get_mainnodes() { return mainnodesdata; }

	GRAPH_DISPLAY_DATA *animnodesdata = 0;
	GRAPH_DISPLAY_DATA *animlinedata = 0;
	GRAPH_DISPLAY_DATA *conditionallines = 0;
	GRAPH_DISPLAY_DATA *conditionalnodes = 0;
	GRAPH_DISPLAY_DATA *previewnodes = 0;
	GRAPH_DISPLAY_DATA *previewlines = 0;

	bool needVBOReload_main = true;
	bool needVBOReload_active = true;
	bool needVBOReload_preview = true;
	bool needVBOReload_heatmap = true;
	bool needVBOReload_conditional = true;

	ALLEGRO_BITMAP *previewBMP = NULL;
	GRAPH_SCALE *main_scalefactors = NULL;
	GRAPH_SCALE *preview_scalefactors = NULL;
	GLuint previewVBOs[4] = { 0,0,0,0 };

	HIGHLIGHT_DATA highlightData;

	GLuint heatmapEdgeVBO[1] = { 0 };
	GRAPH_DISPLAY_DATA *heatmaplines = 0;
	//lowest/highest numbers of edge iterations
	pair<unsigned long, unsigned long> heatExtremes;
	pair<unsigned long, unsigned long> condCounts;

	long zoomLevel = 0;
	unsigned long vertResizeIndex = 0;
	bool VBOsGenned = false;
	long long userSelectedAnimPosition = -1;

	bool increase_thread_references();
	void decrease_thread_references();
	void display_highlight_lines(vector<node_data *> *nodeList, ALLEGRO_COLOR *colour, int lengthModifier);

protected:

#ifdef XP_COMPATIBLE
	HANDLE nodeCoordMutex;
	HANDLE threadReferenceMutex;
#else
	SRWLOCK nodeCoordLock = SRWLOCK_INIT;
	SRWLOCK threadReferenceLock = SRWLOCK_INIT;
#endif

	bool previewNeedsResize = false;

	
	void display_active(bool showNodes, bool showEdges);
	void display_static(bool showNodes, bool showEdges);
	void rescale_nodes(bool isPreview);
	void display_big_conditional(VISSTATE *clientState);
	void display_big_heatmap(VISSTATE *clientState);
	int render_new_edges(bool doResize);
	void redraw_anim_edges();

	void acquire_nodecoord_read();
	void acquire_nodecoord_write();
	void release_nodecoord_read();
	void release_nodecoord_write();

	//for keeping track of graph dimensions
	//this will likely need to be genericised to width/height/depth or something
	virtual void updateStats(int a, int b, int c);
	int maxA = 0, maxB = 0;

	//keep track of which a,b coords are occupied
	std::map<pair<int, int>, bool> usedCoords;
	vector<pair<MEM_ADDRESS, NODEINDEX>> callStack;

	proto_graph *internalProtoGraph;
	PLOT_TRACK lastMainNode;
	NODEINDEX lastAnimatedNode = 0;
	GRAPH_DISPLAY_DATA *mainnodesdata = 0;
	map <NODEINDEX, EXTTEXT> activeExternTimes;
	vector <ANIMATIONENTRY> currentUnchainedBlocks;
	vector <ALLEGRO_COLOR> *graphColours;

	bool wireframeSupported;
	pair <long, long> defaultViewShift;
	long defaultZoom;
	graphLayouts layout;

private:
	virtual void positionVert(void *positionStruct, MEM_ADDRESS address) {};
	virtual void display_graph(VISSTATE *clientState, PROJECTDATA *pd) {};

	virtual FCOORD nodeIndexToXYZ(unsigned int index, GRAPH_SCALE *dimensions, float diamModifier) { cerr << "Warning: Virtual nodeIndexToXYZ called\n" << endl; FCOORD x; return x; };

	virtual int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		GRAPH_SCALE *dimensions) {cerr << "Warning: Virtual add_node called\n" << endl; return 0;	};

	void set_max_wait_frames(unsigned int frames) { maxWaitFrames = frames; }
	bool isGraphBusy();
	int render_new_preview_edges(VISSTATE* clientState);
	void extend_faded_edges();
	void reset_mainlines();
	void render_animation(float fadeRate);
	void set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);
	void set_node_alpha(unsigned int nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha);
	//node+edge col+pos
	bool fill_block_nodelist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *vertlist);
	void plotted_graph::brighten_next_block_edge(ANIMATIONENTRY *entry, int brightTime);
	void brighten_node_list(ANIMATIONENTRY *entry, int brightTime, vector <NODEINDEX> *nodeIDList);
	void draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata);
	void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);

	void process_live_animation_updates();
	void process_live_update();
	void end_unchained(ANIMATIONENTRY *entry);
	int process_replay_animation_updates(int stepSize);
	void process_replay_update(int stepSize);

	void brighten_new_active_nodes();
	void brighten_new_active_extern_nodes();
	void brighten_new_active_edges();
	void brighten_new_active();

	void maintain_active();
	void darken_fading(float fadeRate);
	void darken_nodes(float fadeRate);
	void darken_edges(float fadeRate);

	void remove_unchained_from_animation();
	unsigned long calculate_wait_frames(unsigned int stepSize, unsigned long executions);
	void clear_active();
	void removeEntryFromQueue();

	GRAPH_DISPLAY_DATA *mainlinedata = 0;

	//position out of all the instructions instrumented
	unsigned long animInstructionIndex = 0;

	//two sets of VBOs for graph so we can display one
	//while the other is being written
	int lastVBO = 2;
	GLuint activeVBOs[4] = { 0,0,0,0 };
	GLuint conditionalVBOs[2] = { 0 };
	PID_TID pid, tid;
	PLOT_TRACK lastPreviewNode;
	map <pair<NODEINDEX, unsigned int>, int> newExternTimes;
	HANDLE graphwritingMutex = CreateMutex(NULL, FALSE, NULL);

	unsigned long animLoopCounter = 0;
	unsigned int unchainedWaitFrames = 0;
	unsigned int maxWaitFrames = 0;

	//which BB we are pointing to in the sequence list
	unsigned long animationIndex = 0;

	//have tried vector<pair<nodeindex,int>> but it's slower
	map <NODEINDEX, int> newAnimNodeTimes;
	map <unsigned int, int> activeAnimNodeTimes;
	set <unsigned int> fadingAnimNodes;

	map <NODEPAIR, int> newAnimEdgeTimes;
	map <NODEPAIR, int> activeAnimEdgeTimes;
	set <NODEPAIR> fadingAnimEdges;

	bool animBuildingLoop = false;
	bool dying = false;
	int threadReferences = 0;
};

