/*
Copyright 2016-2017 Nia Catlin

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
Requires inheriting to give it a layout (eg: cylinder_graph)
*/

#pragma once
#include <stdafx.h>
#include <QtOpenGL\qglfunctions.h>
#include "proto_graph.h"
#include "GUIConstants.h"
#include "rgatState.h"
#include "graphGLWidget.h"
#include "graphicsMaths.h"
#include "locks.h"

#define KEEP_BRIGHT -1

enum REPLAY_STATE { eStopped, ePlaying, ePaused, eEnded};

struct VERTREMAINING {
	unsigned int vertIdx;
	unsigned int timeRemaining;
};

enum egraphHighlightModes { eNone_HL = -1, eRefreshs_HL = 0, eAddress_HL = 1, eSym_HL = 2, eModule_HL = 3, eExceptions_HL = 4 };
struct HIGHLIGHT_DATA {
	egraphHighlightModes highlightState = eNone_HL;
	string highlight_s;
	MEM_ADDRESS highlightAddr = 0;
	int highlightModule = -1;
	vector<NODEINDEX> highlightNodes;
};


struct PLOT_TRACK {
	NODEINDEX lastVertID = 0;
	eEdgeNodeType lastVertType = eNodeNonFlow;
};

struct SCREEN_QUERY_PTRS {
	GRAPH_DISPLAY_DATA *mainverts;
	PROJECTDATA *pd;
};

struct GENERIC_COORD {
	void *coordPtr;
};

class plotted_graph
{
public:
	plotted_graph(proto_graph *protoGraph, vector<QColor> *graphColoursPtr);
	~plotted_graph();

	virtual void initialiseDefaultDimensions() {};
	virtual void initialiseCustomDimensions(GRAPH_SCALE scale) {};
	virtual void plot_wireframe(graphGLWidget &gltarget) {};
	virtual void maintain_draw_wireframe(graphGLWidget &gltarget) {};

	virtual bool get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo, graphGLWidget &gltarget) {
		cerr << "Warning: Virtual gvnp called" << endl;		return false;
	};
	virtual void render_static_graph() { assert(false); };

	virtual void performMainGraphDrawing(graphGLWidget &gltarget) { cout << "virtual pmgd called" << endl; };
	virtual void performDiffGraphDrawing(graphGLWidget &gltarget, void *divergeNodePosition);

	virtual void orient_to_user_view() {};
	virtual bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata,	QColor *forceColour, bool preview, bool noUpdate) {
		cerr << "bad render_edge" << endl;	return false;	};
	virtual unsigned int get_graph_size() { return 0; };
	virtual void *get_node_coord_ptr(NODEINDEX idx) { return 0; }

	virtual void adjust_A_edgeSep(float delta) {};
	virtual void adjust_B_edgeSep(float delta) {};
	virtual void reset_edgeSep() {};
	virtual void adjust_size(float delta) {};

	virtual void drawHighlight(GENERIC_COORD& graphCoord, GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget)
	{
		cerr << "Warning: Virtual drawHighlight (void *) called\n" << endl;
	};
	virtual void drawHighlight(NODEINDEX nodeIndex,       GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget) 
		{ cerr << "Warning: Virtual drawHighlight (nodeindex) called\n" << endl; };



	virtual void irregularActions() {}
	virtual void previewYScroll() {}
	virtual int prevScrollYPosition() { return -255; }
	virtual float previewZoom() { return -550; }
	virtual pair<void *, float> get_diffgraph_nodes() { return make_pair((void *)0, (float)0.0); }
	virtual void set_diffgraph_nodes(pair<void *, float> diffData) {  }
	virtual void gl_frame_setup(graphGLWidget &gltarget);
	virtual void regenerate_wireframe_if_needed() {};
	//for keeping track of graph dimensions
	virtual void updateStats(float a, float b, float c);

	virtual int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data **node) { return INT_MAX; };

	void updateMainRender();
	int render_preview_graph();
	void changeZoom(double delta);

	void draw_instructions_text(int zdist, PROJECTDATA *pd, graphGLWidget &gltarget);
	void show_external_symbol_labels(PROJECTDATA *pd, graphGLWidget &gltarget);
	void show_internal_symbol_labels(PROJECTDATA *pd, graphGLWidget &gltarget, bool placeHolders);
	void draw_internal_symbol(DCOORD screenCoord, node_data *n, graphGLWidget &gltarget, QPainter *painter, const QFontMetrics *fontMetric);
	void draw_internal_symbol(DCOORD screenCoord, node_data *n, graphGLWidget &gltarget, QPainter *painter, const QFontMetrics *fontMetric, string symbolText);
	void draw_func_args(QPainter *painter, DCOORD screenCoord, node_data *n, graphGLWidget &gltarget, const QFontMetrics *fontMetric);
	void gen_graph_VBOs(graphGLWidget &gltarget);
	void render_replay_animation(float fadeRate);


	void schedule_animation_reset() { animation_needs_reset = true; }
	void reset_animation_if_scheduled();

	float getAnimationPercent() { return (float)((float)animationIndex / (float)internalProtoGraph->savedAnimationData.size()); }
	void render_live_animation(float fadeRate);
	void highlight_last_active_node();
	void set_animation_update_rate(int updatesPerFrame) { animEntriesPerFrame = updatesPerFrame; }

	bool setGraphBusy(bool set, int caller);
	bool trySetGraphBusy();

	void setBeingDeleted() { beingDeleted = true; }
	bool isBeingDeleted() { return beingDeleted; }
	bool isreferenced()  { return threadReferences != 0; }
	bool isAnimated() { return animated; }
	bool needsReleasing() { return freeMe; }
	void setNeedReleasing(bool state) { freeMe = state; }
	void apply_drag(double dx, double dy);
	void setAnimated(bool newState);
	void copy_node_data(GRAPH_DISPLAY_DATA *nodes);
	void scheduleRedraw() { replotScheduled = true; }
	bool needsReplotting() {	return replotScheduled;	}
	float zoomMultiplier() { return zoomFactor(cameraZoomlevel, main_scalefactors->plotSize); }

	PID_TID get_pid() { return pid; }
	PID_TID get_tid() { return tid; }

	graphLayouts getLayout() { return layout; }

	proto_graph * get_protoGraph() { return internalProtoGraph; }
	bool isWireframeSupported() { return wireframeSupported; }
	bool isWireframeActive() { return wireframeActive; }
	void setWireframeActive(bool newState) { wireframeActive = wireframeSupported ? newState : false; }

	GRAPH_DISPLAY_DATA* get_mainlines() { return mainlinedata; }
	GRAPH_DISPLAY_DATA* get_mainnodes() { return mainnodesdata; }

	bool increase_thread_references(int caller);
	void decrease_thread_references(int caller);
	void display_highlight_lines(vector<NODEINDEX> *nodeList, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
	void setHighlightData(vector<NODEINDEX> *nodeList, egraphHighlightModes highlightType);

public:

	static rgatState *clientState;

	GLuint graphVBOs[4] = { 0,0,0,0 };

	GRAPH_DISPLAY_DATA *animnodesdata = NULL;
	GRAPH_DISPLAY_DATA *animlinedata = NULL;
	GRAPH_DISPLAY_DATA *conditionallines = NULL;
	GRAPH_DISPLAY_DATA *conditionalnodes = NULL;
	GRAPH_DISPLAY_DATA *previewnodes = NULL;
	GRAPH_DISPLAY_DATA *previewlines = NULL;

	bool needVBOReload_main = true;
	bool needVBOReload_active = true;
	bool needVBOReload_preview = true;
	bool needVBOReload_heatmap = true;
	bool needVBOReload_conditional = true;

	GRAPH_SCALE *main_scalefactors = NULL;
	GRAPH_SCALE *preview_scalefactors = NULL;
	GLuint previewVBOs[4] = { 0,0,0,0 };

	HIGHLIGHT_DATA highlightData;

	GLuint heatmapEdgeVBO[1] = { 0 };
	GRAPH_DISPLAY_DATA *heatmaplines = 0;
	//lowest/highest numbers of edge iterations
	pair<unsigned long, unsigned long> heatExtremes;
	pair<unsigned long, unsigned long> condCounts;

	unsigned long vertResizeIndex = 0;
	bool VBOsGenned = false;
	long long userSelectedAnimPosition = -1;

	double cameraZoomlevel = -1;
	float view_shift_x = 0, view_shift_y = 0;
	REPLAY_STATE replayState = eStopped;
	size_t updateProcessingIndex = 0;
	float maxA = 0, maxB = 0, maxC = 0;

	int threadReferences = 0;
	bool schedule_performSymbolResolve = false;

	vector <TEXTRECT> labelPositions;
	
protected:
	void display_active(graphGLWidget &gltarget);
	void display_static(graphGLWidget &gltarget);
	void display_big_conditional(graphGLWidget &gltarget);
	void display_big_heatmap(graphGLWidget &gltarget);
	int render_new_edges();
	void redraw_anim_edges();

	void acquire_nodecoord_read();
	void acquire_nodecoord_write();
	void release_nodecoord_read();
	void release_nodecoord_write();

	PLOT_TRACK setLastNode(NODEINDEX nodeIdx);

protected:

	mutable std::shared_mutex nodeCoordLock_;
	mutable std::shared_mutex threadReferenceLock_;

	rgatlocks::UntestableLock callStackLock;

	bool previewNeedsResize = false;
	bool freeMe = false;
	bool replotScheduled = false;

	//keep track of which a,b coords are occupied - may need to be unique to each plot
	std::map<pair<float, float>, bool> usedCoords;
	vector<pair<MEM_ADDRESS, NODEINDEX>> mainCallStack;
	vector<pair<MEM_ADDRESS, NODEINDEX>> previewCallStack;

	proto_graph *internalProtoGraph = NULL;
	PLOT_TRACK lastMainNode;
	NODEINDEX lastAnimatedNode = 0;

	GRAPH_DISPLAY_DATA *mainnodesdata = NULL;
	map <NODEINDEX, EXTTEXT> activeExternTimes;
	vector <ANIMATIONENTRY> currentUnchainedBlocks;
	vector <QColor> *graphColours = NULL;

	bool wireframeSupported = false;
	bool wireframeActive = false;
	pair <long, long> defaultViewShift;
	long defaultZoom;
	graphLayouts layout;

private:
	virtual void positionVert(void *positionStruct, MEM_ADDRESS address) {};
	virtual void display_graph(PROJECTDATA *pd) {};
	virtual FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier) { cerr << "Warning: Virtual nodeIndexToXYZ called\n" << endl; FCOORD x; return x; };

	virtual int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		GRAPH_SCALE *dimensions) {
		cerr << "Warning: Virtual add_node called\n" << endl;
		return 0;
	};

	void set_max_wait_frames(unsigned int frames) { maxWaitFrames = frames; }
	int render_new_preview_edges();
	void extend_faded_edges();
	void reset_mainlines();
	void render_animation(float fadeRate);
	void set_node_alpha(NODEINDEX nIdx, GRAPH_DISPLAY_DATA *nodesdata, float alpha);
	//node+edge col+pos
	bool fill_block_nodelist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, vector <NODEINDEX> *vertlist);
	void brighten_next_block_edge(ANIMATIONENTRY *entry, int brightTime);
	void brighten_node_list(ANIMATIONENTRY *entry, int brightTime, vector <NODEINDEX> *nodeIDList);
	void draw_condition_ins_text(float zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata, graphGLWidget &gltarget);
	void draw_edge_heat_text(int zdist, PROJECTDATA *pd, graphGLWidget &gltarget);
	void set_edge_alpha(NODEPAIR eIdx, GRAPH_DISPLAY_DATA *edgesdata, float alpha);

	void process_live_animation_updates();
	void process_live_update();
	void end_unchained(ANIMATIONENTRY *entry);
	int process_replay_animation_updates(int optionalStepSize);
	void process_replay_update();

	void brighten_new_active_nodes();
	void brighten_new_active_extern_nodes();
	void brighten_new_active_edges();
	void brighten_new_active();

	void maintain_active();
	void darken_fading(float fadeRate);
	void darken_nodes(float fadeRate);
	void darken_edges(float fadeRate);

	void remove_unchained_from_animation();
	unsigned long calculate_wait_frames(unsigned long executions);
	void clear_active();

private:
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
	map <pair<NODEINDEX, unsigned long>, int> newExternTimes;

	//prevent graph from being deleted while being used
	rgatlocks::TestableLock graphBusyLock;

	unsigned int animEntriesPerFrame = 150;
	unsigned long animLoopCounter = 0;
	unsigned int unchainedWaitFrames = 0;
	unsigned int maxWaitFrames = 0;

	//which BB we are pointing to in the sequence list
	unsigned long animationIndex = 0;

	//have tried vector<pair<nodeindex,int>> but it's slower
	map <NODEINDEX, int> newAnimNodeTimes;
	map <NODEINDEX, int> activeAnimNodeTimes;
	set <NODEINDEX> fadingAnimNodes;

	map <NODEPAIR, int> newAnimEdgeTimes;
	map <NODEPAIR, int> activeAnimEdgeTimes;
	set <NODEPAIR> fadingAnimEdges;


	bool animBuildingLoop = false;
	bool dying = false;
	bool beingDeleted = false;
	//int threadReferences = 0;
	bool animated = false;
	bool animation_needs_reset = false;
	bool performSymbolResolve = false;
};

struct constructed_before
{
	inline bool operator() (plotted_graph* graph1, plotted_graph* graph2)
	{
		return (graph1->get_protoGraph()->getConstructedTime() < graph2->get_protoGraph()->getConstructedTime());
	}
};