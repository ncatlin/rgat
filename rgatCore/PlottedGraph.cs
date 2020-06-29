using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
	class GRAPH_SCALE
	{
		public long plotSize = 10000;
		public long basePlotSize = 10000;
		public float userSizeModifier = 1;
		public int maxA = 360;
		public int maxB = 180;
		public int maxC = 1;
		public int pix_per_A, pix_per_B, original_pix_per_A, original_pix_per_B;
		public float stretchA = 1, stretchB = 1;
	};


	abstract class PlottedGraph
    {

		public PlottedGraph(ProtoGraph protoGraph)//, List<QColor> *graphColoursPtr);
        {
			pid = protoGraph.TraceData.PID;
			tid = protoGraph.ThreadID;

			//possibly conditional. diff graphs won't want heatmaps etc
			mainnodesdata = new GraphDisplayData();
			mainlinedata = new GraphDisplayData();

			animlinedata = new GraphDisplayData();
			animnodesdata = new GraphDisplayData();

			previewlines = new GraphDisplayData(true);
			previewnodes = new GraphDisplayData(true);

			conditionallines = new GraphDisplayData();
			conditionalnodes = new GraphDisplayData();
			heatmaplines = new GraphDisplayData();

			blocklines = new GraphDisplayData();

			needVBOReload_conditional = true;
			needVBOReload_heatmap = true;
			needVBOReload_main = true;
			needVBOReload_preview = true;

			
			//main_scalefactors = new GRAPH_SCALE;
			//preview_scalefactors = new GRAPH_SCALE;

			internalProtoGraph = protoGraph;
			/*
			if (internalProtoGraph->active)
				animated = true;
			else
				animated = false;

			graphColours = graphColoursPtr;
			*/
		}

		/*
		virtual void initialiseDefaultDimensions() { };
		virtual void initialiseCustomDimensions(GRAPH_SCALE scale) { };
		virtual void plot_wireframe(graphGLWidget &gltarget) { };
		virtual void maintain_draw_wireframe(graphGLWidget &gltarget) { };

		virtual bool get_visible_node_pos(uint nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget)
		{
			cerr << "Warning: Virtual gvnp called" << endl; return false;
		};
		virtual void render_static_graph() { assert(false); };

		virtual void performMainGraphDrawing(graphGLWidget &gltarget) { cout << "virtual pmgd called" << endl; };
		virtual void performDiffGraphDrawing(graphGLWidget &gltarget, void* divergeNodePosition);

		virtual void orient_to_user_view() { };
		virtual bool render_edge(NODEPAIR ePair, GraphDisplayData* edgedata, QColor* forceColour, bool preview, bool noUpdate)
		{
			cerr << "bad render_edge" << endl; return false;
		};
		virtual uint get_graph_size() { return 0; };
		virtual void* get_node_coord_ptr(uint idx) { return 0; }

		virtual void adjust_A_edgeSep(float delta) { };
		virtual void adjust_B_edgeSep(float delta) { };
		virtual void reset_edgeSep() { };
		virtual void adjust_size(float delta) { };

		virtual void drawHighlight(GENERIC_COORD& graphCoord, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget)
		{
			cerr << "Warning: Virtual drawHighlight (void *) called\n" << endl;
		};
		virtual void drawHighlight(uint uint, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget)
		{ cerr << "Warning: Virtual drawHighlight (uint) called\n" << endl; };



		virtual void irregularActions() { }
		virtual void previewYScroll() { }
		virtual int prevScrollYPosition() { return -255; }
		virtual float previewZoom() { return -550; }
		virtual void pan(int keyPressed) { };
		virtual Tuple<void*, float> get_diffgraph_nodes() { return make_pair((void*)0, (float)0.0); }
		virtual void set_diffgraph_nodes(Tuple<void*, float> diffData) { }
		virtual void gl_frame_setup(graphGLWidget &gltarget);
		virtual void regenerate_wireframe_if_needed() { };
		virtual void setWireframeActive(int mode) { };
		//for keeping track of graph dimensions
		virtual void updateStats(float a, float b, float c);

		virtual int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data** node) { return INT_MAX; };

		void updateMainRender();
		int render_preview_graph();
		void changeZoom(double delta, double deltaModifier);

		void draw_instructions_text(int zdist, PROJECTDATA* pd, graphGLWidget &gltarget);
		void show_external_symbol_labels(PROJECTDATA* pd, graphGLWidget &gltarget);
		void show_internal_symbol_labels(PROJECTDATA* pd, graphGLWidget &gltarget, bool placeHolders);
		void draw_internal_symbol(DCOORD screenCoord, node_data* n, graphGLWidget &gltarget, QPainter* painter, const QFontMetrics* fontMetric);
		void draw_internal_symbol(DCOORD screenCoord, node_data* n, graphGLWidget &gltarget, QPainter* painter, const QFontMetrics* fontMetric, string symbolText);
		void draw_func_args(QPainter* painter, DCOORD screenCoord, node_data* n, graphGLWidget &gltarget, const QFontMetrics* fontMetric);
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
		bool isreferenced() { return threadReferences != 0; }
		bool isAnimated() { return animated; }
		bool needsReleasing() { return freeMe; }
		void setNeedReleasing(bool state) { freeMe = state; }
		void apply_drag(double dx, double dy);
		*/
		public void SetAnimated(bool newState)
        {
			if (IsAnimated)
			{
				animation_needs_reset = true;
			}

			IsAnimated = newState;
		}
		/*
		void copy_node_data(GraphDisplayData* nodes);
		void scheduleRedraw() { replotScheduled = true; }
		bool needsReplotting() { return replotScheduled; }
		float zoomMultiplier() { return zoomFactor(cameraZoomlevel, main_scalefactors->plotSize); }

		graphLayouts getLayout() { return layout; }

		proto_graph* get_protoGraph() { return internalProtoGraph; }
		bool isWireframeSupported() { return wireframeSupported; }
		bool isWireframeActive() { return wireframeActive; }

		GraphDisplayData* get_mainlines() { return mainlinedata; }
		GraphDisplayData* get_mainnodes() { return mainnodesdata; }

		bool increase_thread_references(int caller);
		void decrease_thread_references(int caller);
		void display_highlight_lines(List<uint>* nodeList, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
		void setHighlightData(List<uint>* nodeList, egraphHighlightModes highlightType);
		*/

		static rgatState clientState;

		//GLuint graphVBOs[6] = { 0, 0, 0, 0, 0, 0 };

		GraphDisplayData mainlinedata = null;
		GraphDisplayData animnodesdata = null;
		GraphDisplayData animlinedata = null;
		GraphDisplayData conditionallines = null;
		GraphDisplayData conditionalnodes = null;
		GraphDisplayData previewnodes = null;
		GraphDisplayData previewlines = null;
		GraphDisplayData blocklines = null;

		bool needVBOReload_main = true;
		bool needVBOReload_active = true;
		bool needVBOReload_preview = true;
		bool needVBOReload_heatmap = true;
		bool needVBOReload_conditional = true;

		protected GRAPH_SCALE main_scalefactors = new GRAPH_SCALE();
		protected GRAPH_SCALE preview_scalefactors = new GRAPH_SCALE();
		//GLuint previewVBOs[4] = { 0, 0, 0, 0 };

		//HIGHLIGHT_DATA highlightData;

		//GLuint heatmapEdgeVBO[1] = { 0 };
		GraphDisplayData heatmaplines = null;
		//lowest/highest numbers of edge iterations
		Tuple<ulong, ulong> heatExtremes;
		Tuple<ulong, ulong> condCounts;

		ulong vertResizeIndex = 0;
		bool VBOsGenned = false;
		ulong userSelectedAnimPosition = 0;

		protected double cameraZoomlevel = -1;
		protected float view_shift_x = 0, view_shift_y = 0;
		protected float graph_pan_x = 0, graph_pan_y = 0;

		//REPLAY_STATE replayState = eStopped;
		int updateProcessingIndex = 0;
		float maxA = 0, maxB = 0, maxC = 0;

		int threadReferences = 0;
		bool schedule_performSymbolResolve = false;

		//List<TEXTRECT> labelPositions;
		int wireframeMode; //used to query the current mode

		//protected:
		/*
	void display_active(graphGLWidget &gltarget);
		void display_static(graphGLWidget &gltarget);
		void display_big_conditional(graphGLWidget &gltarget);
		void display_big_heatmap(graphGLWidget &gltarget);
		int render_new_edges();
		int render_new_blocks();
		void redraw_anim_edges();

		void acquire_nodecoord_read();
		void acquire_nodecoord_write();
		void release_nodecoord_read();
		void release_nodecoord_write();
		*/
		//PLOT_TRACK setLastNode(uint nodeIdx);

		//protected:

		//mutable std::shared_mutex nodeCoordLock_;
		//mutable std::shared_mutex threadReferenceLock_;

		//rgatlocks::UntestableLock callStackLock;

		bool previewNeedsResize = false;
		bool freeMe = false;
		bool replotScheduled = false;

		//keep track of which a,b coords are occupied - may need to be unique to each plot
		Dictionary<Tuple<float, float>, bool> usedCoords;
		List<Tuple<ulong, uint>> mainCallStack;
		List<Tuple<ulong, uint>> previewCallStack;

		protected ProtoGraph internalProtoGraph = null;
		//PLOT_TRACK lastMainNode;
		uint lastAnimatedNode = 0;

		GraphDisplayData mainnodesdata = null;
		//Dictionary<uint, EXTTEXT> activeExternTimes;
		//List<ANIMATIONENTRY> currentUnchainedBlocks;
		//List<QColor>* graphColours = null;

		protected bool wireframeSupported = false;
		protected bool wireframeActive = false;
		Tuple<long, long> defaultViewShift;
		long defaultZoom;
		protected graphLayouts layout;

		//private:
		/*
		virtual void positionVert(void* positionStruct, MEM_ADDRESS address) { };
		virtual void display_graph(PROJECTDATA* pd) { };
		virtual FCOORD uintToXYZ(uint index, GRAPH_SCALE* dimensions, float diamModifier) { cerr << "Warning: Virtual uintToXYZ called\n" << endl; FCOORD x; return x; };

		virtual void render_node(node_data* n, PLOT_TRACK* lastNode, GraphDisplayData* vertdata, GraphDisplayData* animvertdata,
			GRAPH_SCALE* dimensions)
		{
			cerr << "Warning: Virtual render_node called\n" << endl;
		};
		virtual void render_block(block_data &b, GRAPH_SCALE* dimensions)
		{
			cerr << "Warning: Virtual render_block called\n" << endl;
		};

		void set_max_wait_frames(uint frames) { maxWaitFrames = frames; }
		int render_new_preview_edges();
		void extend_faded_edges();
		void reset_mainlines();
		void render_animation(float fadeRate);
		void set_node_alpha(uint nIdx, GraphDisplayData* nodesdata, float alpha);
		//node+edge col+pos
		bool fill_block_nodelist(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, List<uint>* vertlist);
		void brighten_next_block_edge(ANIMATIONENTRY* entry, int brightTime);
		void brighten_node_list(ANIMATIONENTRY* entry, int brightTime, List<uint>* nodeIDList);
		void draw_condition_ins_text(float zdist, PROJECTDATA* pd, GraphDisplayData* vertsdata, graphGLWidget &gltarget);
		void draw_edge_heat_text(int zdist, PROJECTDATA* pd, graphGLWidget &gltarget);
		void set_edge_alpha(NODEPAIR eIdx, GraphDisplayData* edgesdata, float alpha);

		void process_live_animation_updates();
		void process_live_update();
		void end_unchained(ANIMATIONENTRY* entry);
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
		ulong calculate_wait_frames(ulong executions);
		void clear_active();
		*/
		//private:
		/*
		ulong renderedBlocksCount = 0;

		//position out of all the instructions instrumented
		ulong animInstructionIndex = 0;

		//two sets of VBOs for graph so we can display one
		//while the other is being written
		int lastVBO = 2;
		GLuint activeVBOs[4] = { 0, 0, 0, 0 };
		GLuint conditionalVBOs[2] = { 0 };
		*/
		public uint pid { get; private set; }
		public uint tid { get; private set; }
		/*
		PLOT_TRACK lastPreviewNode;
		Dictionary<Tuple<uint, ulong>, int> newExternTimes;
		*/
		//prevent graph from being deleted while being used
		//rgatlocks::TestableLock graphBusyLock;

		uint animEntriesPerFrame = 150;
		ulong animLoopCounter = 0;
		uint unchainedWaitFrames = 0;
		uint maxWaitFrames = 0;

		//which BB we are pointing to in the sequence list
		ulong animationIndex = 0;

		//have tried List<Tuple<uint,int>> but it's slower
		Dictionary<uint, int> newAnimNodeTimes;
		Dictionary<uint, int> activeAnimNodeTimes;
		List<uint> fadingAnimNodesSet;

		Dictionary<Tuple<uint,uint>, int> newAnimEdgeTimes;
		Dictionary<Tuple<uint, uint>, int> activeAnimEdgeTimes;
		List<Tuple<uint, uint>> fadingAnimEdgesSet;


		bool animBuildingLoop = false;
		bool dying = false;
		bool beingDeleted = false;
		//int threadReferences = 0;
		public bool IsAnimated { get; private set; } = false;
		bool animation_needs_reset = false;
		bool performSymbolResolve = false;
	}
}
