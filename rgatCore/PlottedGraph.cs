using Microsoft.Extensions.DependencyModel;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using Veldrid;

namespace rgatCore
{
    class GRAPH_SCALE
    {
        public float plotSize = 1000;
        public float basePlotSize = 1000;
        public float userSizeModifier = 1;
        public float pix_per_A, pix_per_B, original_pix_per_A, original_pix_per_B;
        public float stretchA = 1, stretchB = 1;
    };


    abstract class PlottedGraph
    {
        public enum REPLAY_STATE { eStopped, ePlaying, ePaused, eEnded };

        protected struct EXTTEXT
        {
            public int framesRemaining;
            public float yOffset;
            public string displayString;
        };

        public struct TEXTITEM
        {
            public Vector2 screenXY;
            public Color color;
            public string contents;
            public int fontSize;
        }

        protected struct TEXTRECT
        {
            System.Drawing.Rectangle rect;
            uint index;
        };

        public PlottedGraph(ProtoGraph protoGraph, List<WritableRgbaFloat> graphColourslist)
        {
            pid = protoGraph.TraceData.PID;
            tid = protoGraph.ThreadID;

            //possibly conditional. diff graphs won't want heatmaps etc
            mainnodesdata = new GraphDisplayData();
            mainlinedata = new GraphDisplayData();

            previewlines = new GraphDisplayData(true);
            previewnodes = new GraphDisplayData(true);

            conditionallines = new GraphDisplayData();
            conditionalnodes = new GraphDisplayData();
            heatmaplines = new GraphDisplayData();

            //blocklines = new GraphDisplayData();


            //main_scalefactors = new GRAPH_SCALE;
            //preview_scalefactors = new GRAPH_SCALE;

            internalProtoGraph = protoGraph;

            IsAnimated = !internalProtoGraph.Terminated;
            graphColours = graphColourslist;

        }


        public abstract void InitialiseDefaultDimensions();
        public abstract void initialiseCustomDimensions(GRAPH_SCALE scale);
        /*
		virtual void plot_wireframe(graphGLWidget &gltarget) { };
		virtual void maintain_draw_wireframe(graphGLWidget &gltarget) { };

		virtual bool get_visible_node_pos(uint nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget)
		{
			cerr << "Warning: Virtual gvnp called" << endl; return false;
		};
		*/
        public abstract void render_static_graph();
        /*
		virtual void performMainGraphDrawing(graphGLWidget &gltarget) { cout << "virtual pmgd called" << endl; };
		virtual void performDiffGraphDrawing(graphGLWidget &gltarget, void* divergeNodePosition);

		virtual void orient_to_user_view() { };
		*/
        protected abstract bool render_edge(Tuple<uint, uint> nodePair, GraphDisplayData nodedata, GraphDisplayData edgedata, WritableRgbaFloat? forceColour, bool preview, bool noUpdate);
        /*
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


		*/
        /*
		virtual void previewYScroll() { }
		virtual int prevScrollYPosition() { return -255; }
		virtual float previewZoom() { return -550; }
		virtual void pan(int keyPressed) { };
		virtual Tuple<void*, float> get_diffgraph_nodes() { return make_pair((void*)0, (float)0.0); }
		virtual void set_diffgraph_nodes(Tuple<void*, float> diffData) { }
		virtual void gl_frame_setup(graphGLWidget &gltarget);
		virtual void regenerate_wireframe_if_needed() { };
		virtual void setWireframeActive(int mode) { };

		*/

        //for tracking how big the graph gets
        protected void updateStats(float a, float b, float c)
        {
            //the extra work of 2xabs() happens so rarely that its worth avoiding
            //the stack allocations of a variable every call
            if (Math.Abs(a) > maxA) maxA = Math.Abs(a);
            if (Math.Abs(b) > maxB) maxB = Math.Abs(b);
        }


        //virtual int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, NodeData* node) { return INT_MAX; };

        public void ReRender(bool alsoPreview = false)
        {
            mainlinedata = new GraphDisplayData();
            mainnodesdata = new GraphDisplayData();
            wireframelines = new GraphDisplayData();
            conditionallines = new GraphDisplayData();
            conditionalnodes = new GraphDisplayData();

            if (alsoPreview)
            {
                previewlines = new GraphDisplayData();
                previewnodes = new GraphDisplayData();
            }
            NeedReplotting = false;
        }



        public void UpdateMainRender()
        {
            render_static_graph();
        }

        public void render_preview_graph()
        {
            if (previewNeedsResize)
            {
                Console.WriteLine("Unhandled preview resize");
                //assert(false);
                //previewlines->reset();
                //previewNeedsResize = false;
            }

            //lock (renderingLock)
            {
                render_new_edges(true);
            }
        }


        //void changeZoom(double delta, double deltaModifier);

        //iterate through all the nodes, draw instruction text for the ones in view
        //TODO: in animation mode don't show text for inactive nodes
        void DrawInstructionsText(int zdist)//, PROJECTDATA* pd, graphGLWidget &gltarget)
        {

            Vector3 screenCoord;
            string displayText = "?";

            /*
            SCREEN_QUERY_PTRS screenInfo;
            screenInfo.mainverts = get_mainnodes();
            screenInfo.pd = pd;
            */

            //QPainter painter(&gltarget);
            //painter.setPen(clientState->config.mainColours.instructionText);
            //painter.setFont(clientState->instructionFont);

            uint numVerts = internalProtoGraph.get_num_nodes();
            for (uint i = 0; i < numVerts; ++i)
            {
                NodeData n = internalProtoGraph.safe_get_node(i);

                if (n.IsExternal) continue;
                //if (!get_visible_node_pos(i, &screenCoord, &screenInfo, gltarget)) continue;

                bool compactDisplay;

                if (!GlobalConfig.instructionTextVisibility.extraDetail || zdist > GlobalConfig.insTextCompactThreshold)
                {
                    if (n.ins.itype != eNodeType.eInsUndefined || !n.IsConditional() || n.label?.Length > 0)
                        compactDisplay = false;
                    else
                        compactDisplay = true;
                }
                else
                    compactDisplay = false;

                if (compactDisplay && n.ins.itype == eNodeType.eInsUndefined) continue; //dont want to see add,mov,etc from far away

                if (n.ins.itype == eNodeType.eInsCall || n.ins.itype == eNodeType.eInsJump)
                {
                    if (GlobalConfig.instructionTextVisibility.fullPaths && n.ins.branchAddress != 0)
                    {
                        List<uint> outnodes = null;
                        lock (internalProtoGraph.nodeLock)
                        {
                            outnodes = n.OutgoingNeighboursSet;
                        }

                        bool expectedTarget = false;
                        foreach (uint nidx in outnodes)

                        {
                            NodeData possibleTargN = internalProtoGraph.safe_get_node(nidx);
                            if (possibleTargN.address == n.ins.branchAddress)
                            {
                                if (possibleTargN.label?.Length > 0)
                                {
                                    displayText = n.ins.ins_text;
                                }
                                else
                                {
                                    displayText = n.ins.mnemonic + " " + possibleTargN.label;
                                }
                                expectedTarget = true;
                                break;
                            }
                        }
                        if (!expectedTarget)
                            displayText = n.ins.ins_text;

                    }
                    else
                        displayText = n.ins.ins_text;
                }
                else
                    displayText = n.ins.ins_text;


                string string2 = $"{i}";

                if (!compactDisplay && GlobalConfig.instructionTextVisibility.addresses)
                {
                    if (GlobalConfig.instructionTextVisibility.offsets)
                        string2 += $"+0x{(n.ins.address - internalProtoGraph.moduleBase):X}: {displayText}";
                    else
                        string2 += $"+0x{n.ins.address:X}: {displayText}";
                }

                //painter.drawText(screenCoord.x + INS_X_OFF, gltarget.height() - screenCoord.y + INS_Y_OFF, ss.str().c_str());
            }

        }

        /*
		 * 
        void show_external_symbol_labels(PROJECTDATA* pd, graphGLWidget &gltarget);
		void show_internal_symbol_labels(PROJECTDATA* pd, graphGLWidget &gltarget, bool placeHolders);
		void draw_internal_symbol(DCOORD screenCoord, NodeData n, graphGLWidget &gltarget, QPainter* painter, const QFontMetrics* fontMetric);
		void draw_internal_symbol(DCOORD screenCoord, NodeData n, graphGLWidget &gltarget, QPainter* painter, const QFontMetrics* fontMetric, string symbolText);
		void draw_func_args(QPainter* painter, DCOORD screenCoord, NodeData n, graphGLWidget &gltarget, const QFontMetrics* fontMetric);
		void gen_graph_VBOs(graphGLWidget &gltarget);
		*/

        public void render_replay_animation(float fadeRate)
        {
            if (userSelectedAnimPosition != -1)
            {
                //schedule_animation_reset();
                //reset_animation_if_scheduled();

                SetAnimated(true);

                int selectionDiff;
                if (userSelectedAnimPosition < 20 || internalProtoGraph.SavedAnimationData.Count < 20)
                {
                    animationIndex = 0;
                    selectionDiff = userSelectedAnimPosition;
                }
                else
                    animationIndex = userSelectedAnimPosition - 20;

                process_replay_animation_updates(20);
            }
            else
                process_replay_animation_updates();

            render_animation(fadeRate);

            if (userSelectedAnimPosition != -1)
                userSelectedAnimPosition = -1;
        }

        //public void schedule_animation_reset() { animation_needs_reset = true; }
        public void ResetAnimation()
        {
            ResetAllActiveAnimatedAlphas();

            //darken any active drawn nodes
            if (internalProtoGraph.NodeList.Count > 0)
            {
                internalProtoGraph.set_active_node(0);
                darken_fading(1.0f); //this is pointless?
            }

            Debug.Assert(fadingAnimEdgesSet.Count == 0 && FadingAnimNodesSet.Count == 0);

            animInstructionIndex = 0;
            lastAnimatedNode = 0;
            animationIndex = 0;

            //animnodesdata.acquire_col_write();

            newAnimEdgeTimes.Clear();
            newAnimNodeTimes.Clear();

            unchainedWaitFrames = 0;
            currentUnchainedBlocks.Clear();
            animBuildingLoop = false;
            IsAnimated = false;

            replayState = REPLAY_STATE.eStopped;

            Console.WriteLine("Animation Stopped");
            //animnodesdata.release_col_write();
        }

        public float GetAnimationPercent() {
            if (internalProtoGraph.SavedAnimationData.Count == 0) return 0;
            return (float)((float)animationIndex / (float)internalProtoGraph.SavedAnimationData.Count); 
        }
        
        public void render_live_animation(float fadeRate)
        {
            process_live_animation_updates();
            render_animation(fadeRate);
            
        }


        public void highlight_last_active_node()
        {
            if (internalProtoGraph.lastVertID < (uint)mainnodesdata.CountVerts())
                lastAnimatedNode = internalProtoGraph.lastVertID;
        }




        bool setGraphBusy(bool set, int caller)
        {
            if (set)
            {
                //graphBusyLock.lock();
                if (beingDeleted)
                {
                    //graphBusyLock.unlock();
                    return false;
                }
            }
            else
            {
                //graphBusyLock.unlock();
            }
            return true;
        }

        protected bool trySetGraphBusy()
        {
            Console.WriteLine("Todo implement trySetGraphBusy");
            return true;
            //return graphBusyLock.trylock();
        }
        bool isreferenced() { return threadReferences != 0; }
        void setNeedReleasing(bool state) { freeMe = state; }
        void apply_drag(double dx, double dy)
        {
            Console.WriteLine("todo apply drag");
        }


        public bool beingDeleted { private set; get; } = false;

        public void SetAnimated(bool newState)
        {
            if (IsAnimated)
            {
                animation_needs_reset = true;
            }

            IsAnimated = newState;
        }
        //void copy_node_data(GraphDisplayData* nodes);

        public float zoomMultiplier() { return GraphicsMaths.zoomFactor(cameraZoomlevel, main_scalefactors.plotSize); }
        /*

		bool isWireframeSupported() { return wireframeSupported; }
		bool isWireframeActive() { return wireframeActive; }

		GraphDisplayData* get_mainlines() { return mainlinedata; }
		GraphDisplayData* get_mainnodes() { return mainnodesdata; }

		bool increase_thread_references(int caller);
		void decrease_thread_references(int caller);
		void display_highlight_lines(List<uint>* nodeList, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
		void setHighlightData(List<uint>* nodeList, egraphHighlightModes highlightType);
		*/

        public static rgatState clientState;

        //GLuint graphVBOs[6] = { 0, 0, 0, 0, 0, 0 };


        public GraphDisplayData mainnodesdata = null;
        public GraphDisplayData mainlinedata = null;
        public GraphDisplayData conditionallines = null;
        public GraphDisplayData conditionalnodes = null;
        public GraphDisplayData previewnodes = null;
        public GraphDisplayData previewlines = null;
        //public GraphDisplayData blocklines = null;
        public GraphDisplayData wireframelines = null;


        public GRAPH_SCALE main_scalefactors = new GRAPH_SCALE();
        public GRAPH_SCALE preview_scalefactors = new GRAPH_SCALE();
        //GLuint previewVBOs[4] = { 0, 0, 0, 0 };

        //HIGHLIGHT_DATA highlightData;

        //GLuint heatmapEdgeVBO[1] = { 0 };
        GraphDisplayData heatmaplines = null;
        //lowest/highest numbers of edge iterations
        Tuple<ulong, ulong> heatExtremes;
        Tuple<ulong, ulong> condCounts;

        public ulong vertResizeIndex = 0;
        public int userSelectedAnimPosition = 0;

        public double cameraZoomlevel = -1;
        public float view_shift_x = 0, view_shift_y = 0;
        public float graph_pan_x = 0, graph_pan_y = 0;

        public REPLAY_STATE replayState = REPLAY_STATE.eStopped;
        int updateProcessingIndex = 0;
        protected float maxA = 0, maxB = 0, maxC = 0;

        int threadReferences = 0;
        bool schedule_performSymbolResolve = false;

        protected List<TEXTRECT> labelPositions = new List<TEXTRECT>();

        protected readonly Object textLock = new Object();
        protected List<TEXTITEM> texts = new List<TEXTITEM>();


        public abstract List<TEXTITEM> GetOnScreenTexts(GraphicsMaths.SCREENINFO scrn);

        int wireframeMode; //used to query the current mode

        //protected:

        /*
		protected void display_active(graphGLWidget &gltarget)
        {
			//reload buffers if needed and not being written
			if (needVBOReload_active)
			{
				int mainlinevertsQty = mainlinedata.CountVerts;
				if (mainlinevertsQty == 0) return;

				int animnodesverts = animnodesdata.CountVerts;
				int staticnodesverts = mainnodesdata.CountVerts;
				int nodeLoadQty = Math.Min(animnodesverts, staticnodesverts);
				int animlinevertsQty = animlinedata.CountVerts;
				int edgeVertLoadQty = Math.Min(animlinevertsQty, mainlinevertsQty);

				//mainnodesdata.acquire_pos_read();
				//animnodesdata.acquire_col_read();

				gltarget.load_VBO(GL_Constants.VBO_NODE_POS, activeVBOs, POSITION_VERTS_SIZE(nodeLoadQty), mainnodesdata.readonly_pos());
				gltarget.load_VBO(GL_Constants.VBO_NODE_COL, activeVBOs, COLOUR_VERTS_SIZE(nodeLoadQty), animnodesdata.readonly_col());

				animnodesdata.CountLoadedVerts = nodeLoadQty;

				mainnodesdata.release_pos_read();
				animnodesdata.release_col_read();


				List<float> vecPtr = mainlinedata.acquire_pos_read();
				if (vecPtr.Count == 0)
				{
					mainlinedata.release_pos_read();
					return;
				}
				GLfloat* buf = &vecPtr.at(0);
				gltarget.load_VBO(GL_Constants.VBO_LINE_POS, activeVBOs, POSITION_VERTS_SIZE(edgeVertLoadQty), buf);
				mainlinedata.release_pos_read();

				buf = &animlinedata.acquire_col_read().at(0);
				gltarget.load_VBO(GL_Constants.VBO_LINE_COL, activeVBOs, COLOUR_VERTS_SIZE(edgeVertLoadQty), buf);
				animlinedata.release_col_read();

				GLenum result = gltarget.glGetError();
				if (result)	{ Console.WriteLine("error :" + result); 	}
				animlinedata.CountLoadedVerts = edgeVertLoadQty;

				needVBOReload_active = false;
			}


			if (clientState.showNodes && animnodesdata.CountLoadedVerts > 0)
			{
				gltarget.array_render_points(GL_Constants.VBO_NODE_POS, GL_Constants.VBO_NODE_COL, activeVBOs, animnodesdata.CountLoadedVerts);
				int err = glGetError();
				if (err != 0)
					Console.WriteLine("GL error " + err + " in arr_r_pts (display active) loading " + animnodesdata.CountLoadedVerts);
			}

			if (clientState.showEdges && animlinedata.CountLoadedVerts > 0)
			{
				gltarget.array_render_lines(GL_Constants.VBO_LINE_POS, GL_Constants.VBO_LINE_COL, activeVBOs, animlinedata.CountLoadedVerts);
				int err = glGetError();
				if (err != 0) Console.WriteLine("GL error " +err+ " in arr_r_edges (display active)");
			}
		}


		*/

        //protected void display_big_conditional(graphGLWidget &gltarget);
        //protected void display_big_heatmap(graphGLWidget &gltarget);

        public void PlayPauseClicked()
        {
            switch (replayState)
            {
                case REPLAY_STATE.eStopped: //start it from beginning
                    replayState = REPLAY_STATE.ePlaying;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Stopped -> Playing");
                    break;

                case REPLAY_STATE.ePlaying: //pause it
                    replayState = REPLAY_STATE.ePaused;
                    Console.WriteLine("Animation state Playing -> Paused");
                    break;

                case REPLAY_STATE.ePaused: //unpause it
                    replayState = REPLAY_STATE.ePlaying;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Paused -> Playing");
                    break;

            }
        }

        protected void render_new_edges(bool isPreview)
        {
            GraphDisplayData linedata = isPreview ? previewlines : mainlinedata;
            GraphDisplayData nodeData = isPreview ? previewnodes : mainnodesdata;
            GRAPH_SCALE scalefactors = isPreview ? preview_scalefactors : main_scalefactors;

            int edgesDrawn = 0;
            uint startIndex = linedata.CountRenderedEdges;
            int endIndex = internalProtoGraph.edgeList.Count;
            for (uint edgeIdx = startIndex; edgeIdx < endIndex; edgeIdx++)
            {
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (edgeNodes.Item1 >= nodeData.CountVerts())
                {
                    NodeData n1 = internalProtoGraph.safe_get_node(edgeNodes.Item1);
                    render_node(n1, nodeData, scalefactors);
                }

                if (edgeNodes.Item2 >= nodeData.CountVerts())
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeNodes];
                    if (e.edgeClass == eEdgeNodeType.eEdgeException)
                        nodeData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeException;

                    NodeData n2 = internalProtoGraph.safe_get_node(edgeNodes.Item2);
                    render_node(n2, nodeData, scalefactors);

                }

                if (!render_edge(edgeNodes, nodeData, linedata, null, isPreview, false))
                {
                    Console.WriteLine("Error: rendering edge");
                }
                edgesDrawn++;
            }
        }


        //protected int render_new_blocks();
        protected void redraw_anim_edges()
        {
            Console.WriteLine("todo redraw_anim_edges");
            /*
            List<VertexPositionColor> ecol = animlinedata.acquire_vert_write();
            foreach (var edgeIDIt in activeAnimEdgeTimes)
            {
                Tuple<uint, uint> nodePair = edgeIDIt.Key;


                if (internalProtoGraph.edgeDict.TryGetValue(nodePair, out EdgeData e))
                {
                    int numEdgeVerts = e.vertSize;
                    int colArrIndex = e.arraypos + GL_Constants.AOFF;
                    for (int i = 0; i < numEdgeVerts; ++i)
                        ecol[colArrIndex].SetAlpha(1);
                }
            }
            animlinedata.release_vert_write();
            */
        }
        /*
		protected void acquire_nodecoord_read();
		protected void acquire_nodecoord_write();
		protected void release_nodecoord_read();
		protected void release_nodecoord_write();
		*/

        /*
        PLOT_TRACK setLastNode(uint nodeIdx)
        {
            PLOT_TRACK lastnode;

            NodeData n;
            n = internalProtoGraph.safe_get_node(nodeIdx);
            lastnode.lastVertID = nodeIdx;

            if (n.IsExternal)
                lastnode.lastVertType = eEdgeNodeType.eNodeExternal;
            else
            {
                switch (n.ins.itype)
                {
                    case eNodeType.eInsUndefined:
                        {
                            lastnode.lastVertType = n.IsConditional() ?
                                eEdgeNodeType.eNodeJump :
                                eEdgeNodeType.eNodeNonFlow;
                            break;
                        }
                    case eNodeType.eInsJump:
                        {
                            if (n.IsConditional()) Console.WriteLine($"render_node jump because n {n.index} is conditional undef");
                            Console.WriteLine($"setLastNode jump because n {n.index} is jump");
                            lastnode.lastVertType = eEdgeNodeType.eNodeJump;
                            break;
                        }
                    case eNodeType.eInsReturn:
                        {
                            lastnode.lastVertType = eEdgeNodeType.eNodeReturn;
                            break;
                        }
                    case eNodeType.eInsCall:
                        {
                            lastnode.lastVertType = eEdgeNodeType.eNodeCall;

                            //let returns find their caller if they have one
                            ulong nextAddress = n.ins.address + (ulong)n.ins.numbytes;

                            //callStackLock.lock () ;
                            if (mainnodesdata.IsPreview)
                                PreviewCallStack.Add(new Tuple<ulong, uint>(nextAddress, n.index));
                            else
                                MainCallStack.Add(new Tuple<ulong, uint>(nextAddress, n.index));
                            //callStackLock.unlock();

                            break;
                        }
                    //case ISYS: //todo: never used - intended for syscalls
                    //	active_col = &al_col_grey;
                    //	break;
                    default:
                        lastnode.lastVertType = eEdgeNodeType.eENLAST;
                        Console.WriteLine("[rgat]Error: render_node unknown itype " + n.ins.itype);
                        Debug.Assert(false);
                        break;
                }
            }
            return lastnode;
        }
        */

        //protected:

        //mutable std::shared_mutex nodeCoordLock_;
        //mutable std::shared_mutex threadReferenceLock_;

        //rgatlocks::UntestableLock callStackLock;

        bool previewNeedsResize = false;
        bool freeMe = false;
        public bool replotScheduled = false;


        //protected List<Tuple<ulong, uint>> MainCallStack = new List<Tuple<ulong, uint>>();
        //protected List<Tuple<ulong, uint>> PreviewCallStack = new List<Tuple<ulong, uint>>();
        protected List<Tuple<ulong, uint>> ThreadCallStack = new List<Tuple<ulong, uint>>();

        public ProtoGraph internalProtoGraph { get; protected set; } = null;
        //PLOT_TRACK lastPlottedNode;
        protected uint lastAnimatedNode = 0;
        Dictionary<uint, EXTTEXT> activeExternTimes = new Dictionary<uint, EXTTEXT>();
        protected List<ANIMATIONENTRY> currentUnchainedBlocks = new List<ANIMATIONENTRY>();
        protected List<WritableRgbaFloat> graphColours = new List<WritableRgbaFloat>();

        protected bool wireframeSupported = false;
        protected bool wireframeActive = false;
        //Tuple<long, long> defaultViewShift;
        long defaultZoom;
        public graphLayouts layout { get; protected set; }

        //private:
        /*
		virtual void positionVert(void* positionStruct, MEM_ADDRESS address) { };
		virtual void display_graph(PROJECTDATA* pd) { };
		virtual FCOORD uintToXYZ(uint index, GRAPH_SCALE* dimensions, float diamModifier) { cerr << "Warning: Virtual uintToXYZ called\n" << endl; FCOORD x; return x; };
		*/
        abstract public void render_node(NodeData n, GraphDisplayData vertdata,  GRAPH_SCALE dimensions);
        /*
                virtual void render_block(block_data &b, GRAPH_SCALE* dimensions)
                {
                    cerr << "Warning: Virtual render_block called\n" << endl;
                };

                void set_max_wait_frames(uint frames) { maxWaitFrames = frames; }
        */



        void extend_faded_edges()
        {

            Console.WriteLine("todo extend_faded_edges");
            /*
            int drawnVerts = mainlinedata.CountVerts();
            int animatedVerts = animlinedata.CountVerts();

            Debug.Assert(drawnVerts >= animatedVerts);
            int pendingVerts = drawnVerts - animatedVerts;
            if (pendingVerts == 0) return;
            */
            //List<VertexPositionColor> animEdgeColours = animlinedata.acquire_vert_read();
            //List<VertexPositionColor> staticEdgeColours = mainlinedata.acquire_vert_read();

            //copy the colours over
            //Console.WriteLine("Todo all of this extend_faded_edges");
            //int fadedIndex = animatedVerts * GL_Constants.COLELEMS;
            //vector<float>::iterator mainEIt = staticEdgeColours.begin();
            //advance(mainEIt, fadedIndex);
            //animEdgeColours.insert(animEdgeColours.end(), mainEIt, staticEdgeColours.end());
            //mainlinedata.release_col_read();

            //fade alpha of new colours
            //int index2 = animatedVerts * GL_Constants.COLELEMS;
            //int end = drawnVerts * GL_Constants.COLELEMS;
            //for (; index2 < end; index2 += GL_Constants.COLELEMS)
            //	animEdgeColours[index2 + GL_Constants.AOFF] = (float)0.01; //TODO: config entry for anim inactive

            //animlinedata.set_numVerts(drawnVerts);
            //animlinedata.release_col_write();
        }

        //void reset_mainlines();

        void render_animation(float fadeRate)
        {
            brighten_new_active();
            maintain_active();
            darken_fading(fadeRate);

            if (!activeAnimNodeTimes.ContainsKey(lastAnimatedNode))
            {
                mainnodesdata.SetNodeAnimAlpha(lastAnimatedNode, GraphicsMaths.getPulseAlpha());
                if (!FadingAnimNodesSet.Contains(lastAnimatedNode)) 
                    FadingAnimNodesSet.Add(lastAnimatedNode);
            }

        }



        //node+edge col+pos
        bool get_block_nodelist(ulong blockAddr, long blockID, out List<uint> newnodelist)
        {
            ProcessRecord piddata = internalProtoGraph.ProcessData;
            ROUTINE_STRUCT? externBlock = new ROUTINE_STRUCT();
            List<InstructionData> block = piddata.getDisassemblyBlock((uint)blockID, ref externBlock, blockAddr);
            if (block == null && externBlock == null)
            {
                newnodelist = null;
                return false;
            }
            //if (internalProtoGraph.terminationFlag) return false;

            if (externBlock != null)
            {
                //cout << "fill block nodelist with extern addr " << std::hex << blockAddr << " mod " << std::dec << externBlock.globalmodnum << endl;
                //assume it's an external block, find node in extern call list
                //piddata.getExternCallerReadLock();
                /*
				auto callvsEdgeIt = externBlock.thread_callers.find(tid);
				if (callvsEdgeIt == externBlock.thread_callers.end())
				{
					piddata.dropExternCallerReadLock();
					std::this_thread::sleep_for(10ms);
					cerr << "[rgat]Fail to find edge for thread " << tid << " calling extern " << blockAddr << endl;
					return false;
				}
				*/
                bool found = false;
                List<Tuple<uint, uint>> calls = null;
                while (!found)
                {
                    lock (piddata.ExternCallerLock)
                    {
                        found = externBlock.Value.thread_callers.TryGetValue(tid, out calls);
                    }
                    if (found) break;
                    Thread.Sleep(10);
                    Console.WriteLine("[rgat]Fail to find edge for thread " + tid + " calling extern " + blockAddr);
                }



                newnodelist = new List<uint>();
                foreach (Tuple<uint, uint> edge in calls) //record each call by caller
                {
                    if (edge.Item1 == lastAnimatedNode)
                    {
                        newnodelist.Add(edge.Item2);
                    }
                }

                return true;
            }


            newnodelist = new List<uint>();
            foreach (InstructionData ins in block)
            {
                if (!ins.threadvertIdx.TryGetValue(tid, out uint val)) return false;
                newnodelist.Add(val);
            }

            return true;
        }

        void brighten_next_block_edge(uint blockID, ulong blockAddress, int brightTime)
        {
            ROUTINE_STRUCT? externStr = null;
            var nextBlock = internalProtoGraph.ProcessData.getDisassemblyBlock(blockID, ref externStr, blockAddress);
            Tuple<uint, uint> LinkingPair = null;
            if (externStr != null)
            {
                var callers = externStr.Value.thread_callers[internalProtoGraph.ThreadID];
                uint callerIdx = callers.Find(n => n.Item1 == lastAnimatedNode).Item2;
                LinkingPair = new Tuple<uint, uint>(lastAnimatedNode, callerIdx);
            }
            else
            {
                //find vert in internal code
                InstructionData nextIns = nextBlock[0];
                uint caller = nextIns.threadvertIdx[internalProtoGraph.ThreadID];

                LinkingPair = new Tuple<uint, uint>(lastAnimatedNode, caller);
            }

            /*
            if it doesn't exist then assume it's because the user is skipping around the animation with the slider
            (there are other reasons but it helps me sleep at night)
            */
            if (internalProtoGraph.EdgeExists(LinkingPair))
            {
                newAnimEdgeTimes[LinkingPair] = brightTime;
            }


        }

        void brighten_node_list(ANIMATIONENTRY entry, int brightTime, List<uint> nodeIDList)
        {
            ulong instructionCount = 0;

            foreach (uint nodeIdx in nodeIDList)
            {
                newAnimNodeTimes[nodeIdx] = brightTime;

                if (internalProtoGraph.safe_get_node(nodeIdx).IsExternal)
                {
                    if (brightTime == Anim_Constants.KEEP_BRIGHT)
                        newExternTimes[new Tuple<uint, ulong>(nodeIdx, entry.callCount)] = Anim_Constants.KEEP_BRIGHT;
                    else
                        newExternTimes[new Tuple<uint, ulong>(nodeIdx, entry.callCount)] = GlobalConfig.ExternAnimDisplayFrames;
                }

                if (!(entry.entryType == eTraceUpdateType.eAnimUnchained && instructionCount == 0))
                {
                    Tuple<uint,uint> edge =  new Tuple<uint, uint>(lastAnimatedNode, nodeIdx);
                    if (internalProtoGraph.EdgeExists(edge))
                    {
                        newAnimEdgeTimes[edge] = brightTime;
                    }
                    //if it doesn't exist it may be because user is skipping code with animation slider
                }

                lastAnimatedNode = nodeIdx;

                ++instructionCount;
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (instructionCount == (entry.count + 1))) break;

            }
        }


        //void draw_condition_ins_text(float zdist, PROJECTDATA* pd, GraphDisplayData* vertsdata, graphGLWidget &gltarget);
        //void draw_edge_heat_text(int zdist, PROJECTDATA* pd, graphGLWidget &gltarget);
        //void set_edge_alpha(NODEPAIR eIdx, GraphDisplayData* edgesdata, float alpha);

        void process_live_animation_updates()
        {
            //too many updates at a time damages interactivity
            //too few creates big backlogs which delays the animation (can still see realtime in Structure mode though)
            int updateLimit = AnimationUpdatesPerFrame;
            while (updateProcessingIndex < internalProtoGraph.SavedAnimationData.Count && (updateLimit-- > 0))
            {
                process_live_update();
            }
        }

        void process_live_update()
        {
            Console.WriteLine("todo process_live_update");
            /*
			//todo: eliminate need for competing with the trace handler for the lock using spsc ringbuffer
			//internalProtoGraph.animationListsRWLOCK_.lock_shared();
			ANIMATIONENTRY entry = internalProtoGraph.SavedAnimationData[updateProcessingIndex];
			//internalProtoGraph.animationListsRWLOCK_.unlock_shared();

			if (entry.entryType == eTraceUpdateType.eAnimLoopLast)
			{
				++updateProcessingIndex;
				return;
			}

			if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
			{
				remove_unchained_from_animation();

				++updateProcessingIndex;
				return;
			}

			if (entry.entryType == eTraceUpdateType.eAnimUnchainedDone)
			{
				end_unchained(&entry);
				++updateProcessingIndex;
				return;
			}

			int brightTime;
			if (entry.entryType == eTraceUpdateType.eAnimUnchained)
			{
				currentUnchainedBlocks.push_back(entry);
				brightTime = KEEP_BRIGHT;
			}
			else
				brightTime = 0;

			//break if block not rendered yet
			List<uint> nodeIDList;
			if (!get_block_nodelist(entry.blockAddr, entry.blockID, &nodeIDList))
			{
				//expect to get an incomplete block with exception or animation attempt before static rendering
				if ((entry.entryType != eAnimExecException) || (nodeIDList.size() < entry.count))
					return;
			}

			//add all the nodes+edges in the block to the brightening list
			brighten_node_list(&entry, brightTime, &nodeIDList);

			//also add brighten edge to next unchained block
			if (entry.entryType == eAnimUnchained)
				brighten_next_block_edge(&entry, brightTime);

			++updateProcessingIndex;
			*/
        }


        void end_unchained(ANIMATIONENTRY entry)
        {

            currentUnchainedBlocks.Clear();
            List<InstructionData> firstChainedBlock = internalProtoGraph.ProcessData.getDisassemblyBlock(entry.blockID);
            lastAnimatedNode = firstChainedBlock[^1].threadvertIdx[tid]; //should this be front()?

        }

        void process_replay_animation_updates(int optionalStepSize = 0)
        {
            if (internalProtoGraph.SavedAnimationData.Count == 0)
            {
                replayState = REPLAY_STATE.eEnded;
                return;
            }

            int stepSize;
            if (optionalStepSize != 0)
            {
                stepSize = optionalStepSize;
            }
            else
            {
                stepSize = (replayState != REPLAY_STATE.ePaused) ? clientState.AnimationStepRate : 0;
            }

            int targetAnimIndex = animationIndex + stepSize;
            if (targetAnimIndex >= internalProtoGraph.SavedAnimationData.Count)
                targetAnimIndex = internalProtoGraph.SavedAnimationData.Count - 1;


            for (; animationIndex < targetAnimIndex; ++animationIndex)
            {
                Console.WriteLine($"Anim Step {animationIndex}");
                process_replay_update();
                Thread.Sleep(100);
            }

            internalProtoGraph.set_active_node(lastAnimatedNode);

            if (animationIndex >= internalProtoGraph.SavedAnimationData.Count - 1)
            {
                replayState = REPLAY_STATE.eEnded;
            }
        }

        void process_replay_update()
        {
            ANIMATIONENTRY entry = internalProtoGraph.SavedAnimationData[animationIndex];

            int stepSize = clientState.AnimationStepRate;
            if (stepSize == 0) stepSize = 1;

            //brighten edge between last block and this
            //todo - probably other situations we want to do this apart from a parent exec tag
            if (animationIndex > 0)
            { 
                ANIMATIONENTRY lastentry = internalProtoGraph.SavedAnimationData[animationIndex - 1]; 
                if (lastentry.entryType == eTraceUpdateType.eAnimExecTag)
                {
                    brighten_next_block_edge(entry.blockID, entry.blockAddr, GlobalConfig.animationLingerFrames);
                }    
            }

            //unchained area finished, stop highlighting it
            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                ProcessRecord piddata = internalProtoGraph.ProcessData;
                List<InstructionData> block = piddata.getDisassemblyBlock(entry.blockID);
                unchainedWaitFrames += calculate_wait_frames(entry.count * (ulong)block.Count);

                uint maxWait = (uint)Math.Floor((float)maxWaitFrames / stepSize); //todo test
                if (unchainedWaitFrames > maxWait)
                    unchainedWaitFrames = maxWait;

                return;
            }

            //all consecutive unchained areas finished, wait until animation paused appropriate frames
            if (entry.entryType == eTraceUpdateType.eAnimUnchainedDone)
            {
                if (unchainedWaitFrames-- > 1) return;

                remove_unchained_from_animation();
                end_unchained(entry);
                return;
            }

            if (entry.entryType == eTraceUpdateType.eAnimLoopLast)
            {
                if (unchainedWaitFrames-- > 1) return;

                remove_unchained_from_animation();
                currentUnchainedBlocks.Clear();
                animBuildingLoop = false;
                return;
            }

            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained || animBuildingLoop)
            {
                currentUnchainedBlocks.Add(entry);
                brightTime = Anim_Constants.KEEP_BRIGHT;
            }
            else
                brightTime = GlobalConfig.animationLingerFrames;

            if (entry.entryType == eTraceUpdateType.eAnimLoop)
            {
                ProcessRecord piddata = internalProtoGraph.ProcessData;
                List<InstructionData> block = piddata.getDisassemblyBlock(entry.blockID);

                if (block == null)
                    unchainedWaitFrames += calculate_wait_frames(entry.count); //external
                else
                    unchainedWaitFrames += calculate_wait_frames(entry.count * (ulong)block.Count);

                uint maxWait = (uint)Math.Floor((float)maxWaitFrames / (float)stepSize);
                if (unchainedWaitFrames > maxWait)
                    unchainedWaitFrames = maxWait;

                animBuildingLoop = true;
            }


            if (!get_block_nodelist(entry.blockAddr, (long)entry.blockID, out List<uint> nodeIDList) &&
                entry.entryType != eTraceUpdateType.eAnimExecException)
            {
                Thread.Sleep(5);
                while (!get_block_nodelist(entry.blockAddr, (long)entry.blockID, out nodeIDList))
                {
                    Thread.Sleep(15);
                    Console.WriteLine("[rgat] ANst block 0x" + entry.blockAddr); //todo hex
                    if (clientState.rgatIsExiting) return;
                }
            }

            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            mainnodesdata.LastRenderedNode.lastVertID = lastAnimatedNode;

            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                brighten_next_block_edge(entry.targetID, entry.targetAddr, brightTime);
            }

        }


        void brighten_new_active_nodes()
        {
            int actioned = 0;
            foreach (KeyValuePair<uint,int> node_time in newAnimNodeTimes)
            {
                uint nodeIdx = node_time.Key;
                int animTime = node_time.Value;

                if (nodeIdx >= mainnodesdata.CountVerts()) break;

                mainnodesdata.SetNodeAnimAlpha(nodeIdx,1);//set animation brightness to full 

                //want to delay fading if in loop/unchained area, 
                if (animTime != 0)
                {
                    Console.WriteLine($"Set node {nodeIdx} to bright for time {animTime}");
                    activeAnimNodeTimes[nodeIdx] = animTime;
                    if (FadingAnimNodesSet.Contains(nodeIdx)) FadingAnimNodesSet.Remove(nodeIdx);
                }
                else
                {
                    Console.WriteLine($"Set node {nodeIdx} to bright for instant fade");
                    if (!FadingAnimNodesSet.Contains(nodeIdx)) FadingAnimNodesSet.Add(nodeIdx); 
                }
                actioned += 1;
            }

            if (actioned > 0)
            {
                if (actioned == newAnimNodeTimes.Count) newAnimNodeTimes.Clear();
                else
                {
                    if (actioned > 0) Console.WriteLine("Warn, janky realpha of nodes, need to erase the ones that worked");
                }
            }




        }


        void brighten_new_active_extern_nodes()
        {
            Console.WriteLine("todo brighten_new_active_extern_nodes");
            /*
			PROCESS_DATA* piddata = internalProtoGraph.get_piddata();
			Dictionary<uint, EXTTEXT> newEntries;
			map < pair < NODEINDEX, unsigned long>, int>::iterator externTimeIt = newExternTimes.begin();
			while (externTimeIt != newExternTimes.end())
			{
				NODEINDEX externNodeIdx = externTimeIt.first.first;
				unsigned long callsSoFar = externTimeIt.first.second;

				internalProtoGraph.getNodeReadLock();

				node_data* externNode = internalProtoGraph.unsafe_get_node(externNodeIdx);
				ARGLIST* args = NULL;
				unsigned long callRecordIndex = NULL;

				internalProtoGraph.externCallsLock.lock () ;
				if (callsSoFar < externNode.callRecordsIndexs.size())
				{
					callRecordIndex = externNode.callRecordsIndexs.at(callsSoFar);
					//todo: maybe make a local copy instead of holding the mutex
					if (callRecordIndex < internalProtoGraph.externCallRecords.size())
						args = &internalProtoGraph.externCallRecords.at(callRecordIndex).argList;
				}

				MEM_ADDRESS insaddr = externNode.address;
				int globalModIDule = externNode.globalModID;

				internalProtoGraph.dropNodeReadLock();

				string externString = generate_funcArg_string(internalProtoGraph.get_node_sym(externNodeIdx), args);
				internalProtoGraph.externCallsLock.unlock();

				boost::filesystem::path modulePath;
				piddata.get_modpath(globalModIDule, &modulePath);

				stringstream callLogEntry;
				callLogEntry << "0x" << std::hex << insaddr << ": ";
				callLogEntry << modulePath << " . ";
				callLogEntry << externString << "\n";
				internalProtoGraph.loggedCalls.push_back(callLogEntry.str());

				EXTTEXT extEntry;
				extEntry.framesRemaining = externTimeIt.second;
				extEntry.displayString = externString;
				extEntry.yOffset = 10;

				newEntries[externNodeIdx] = extEntry;

				externTimeIt = newExternTimes.erase(externTimeIt);
			}

			internalProtoGraph.externCallsLock.lock () ;
			Dictionary<uint, EXTTEXT>::iterator entryIt = newEntries.begin();
			for (; entryIt != newEntries.end(); ++entryIt)
				activeExternTimes[entryIt.first] = entryIt.second;
			internalProtoGraph.externCallsLock.unlock();
			*/
        }

        void brighten_new_active_edges()
        {
            int actioned = 0;
            foreach (KeyValuePair<Tuple<uint, uint>, int> edge_time in newAnimEdgeTimes)
            {
                Tuple<uint, uint> nodePair = edge_time.Key;
                int animTime = edge_time.Value;

                if (!SetEdgeAnimAlpha(nodePair, 1f)) break;

                if (animTime != 0)
                {
                    activeAnimEdgeTimes[nodePair] = animTime;
                    if (fadingAnimEdgesSet.Contains(nodePair)) fadingAnimEdgesSet.Remove(nodePair);
                }
                else
                {
                    if (!fadingAnimEdgesSet.Contains(nodePair)) fadingAnimEdgesSet.Add(nodePair);              
                }
                actioned++;
            }
            if (actioned == newAnimEdgeTimes.Count)
                newAnimEdgeTimes.Clear();
            else
            {
               if (actioned > 0) Console.WriteLine("Warn, janky realpha of edges, need to erase the ones that worked");
            }
        }

        void brighten_new_active()
        {
            //if (animnodesdata.CountVerts() == 0) return;

            brighten_new_active_nodes();
            brighten_new_active_extern_nodes();

            brighten_new_active_edges();
        }

        /*
         Nodes that are continuously lit up due to being blocked or in a busy (unchained) loop
         These pulse
         */
        void maintain_active()
        {

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());
            Console.WriteLine(currentPulseAlpha);
            List<uint> expiredNodes = new List<uint>();
            List<uint> activeNodes = activeAnimNodeTimes.Keys.ToList();
            foreach (uint nodeIdx in activeNodes)
            {
                mainnodesdata.SetNodeAnimAlpha(nodeIdx, currentPulseAlpha);

                int brightTime = activeAnimNodeTimes[nodeIdx];
                if (brightTime != Anim_Constants.KEEP_BRIGHT)
                {
                    brightTime--;
                    if (brightTime > 0)
                    {
                        Console.WriteLine($"maintain_active Node {nodeIdx} has {brightTime} frames remaining bright");
                        activeAnimNodeTimes[nodeIdx] = brightTime;
                    }
                    else
                    {
                        Console.WriteLine($"maintain_active Node {nodeIdx} expired, now fading");
                        expiredNodes.Add(nodeIdx);
                    }
                }
            }

            foreach(uint expiredNodeIdx in expiredNodes)
            {
                if (!FadingAnimNodesSet.Contains(expiredNodeIdx)) 
                    FadingAnimNodesSet.Add(expiredNodeIdx);
                activeAnimNodeTimes.Remove(expiredNodeIdx);
            }

            /*

			currentPulseAlpha = Math.Max(ANIM_INACTIVE_EDGE_ALPHA, getPulseAlpha());
			map<NODEPAIR, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
			for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
			{
				int brightTime = edgeIDIt.second;
				if (brightTime == KEEP_BRIGHT)
				{
					assert(internalProtoGraph.edge_exists(edgeIDIt.first, 0));

					set_edge_alpha(edgeIDIt.first, animlinedata, currentPulseAlpha);
					continue;
				}

				if (--edgeIDIt.second <= 0)
				{
					fadingAnimEdges.insert(edgeIDIt.first);
					edgeIDIt = activeAnimEdgeTimes.erase(edgeIDIt);
					if (edgeIDIt == activeAnimEdgeTimes.end()) break;
				}
			}
			*/
        }

        void darken_fading(float fadeRate)
        {
            /* when switching graph layouts of a big graph it can take
		   a long time for rerendering of all the edges in the protograph.
		   we can end up with a protograph with far more edges than the rendered edges
		   so have to check that we are operating within bounds */


            darken_nodes(fadeRate);

            darken_edges(fadeRate);
        }

        void darken_nodes(float fadeRate)
        {
            List<uint> expiredNodes = new List<uint>();
            foreach (uint nodeIdx in FadingAnimNodesSet)
            {
                Console.WriteLine($"\tdarken_nodes: Darkening node {nodeIdx}");
                if (mainnodesdata.ReduceNodeAnimAlpha(nodeIdx, fadeRate))
                {
                    Console.WriteLine($"\t\t node {nodeIdx} expired - removing from fading");
                    expiredNodes.Add(nodeIdx); 
                }

            }

            foreach (uint expiredNode in expiredNodes) FadingAnimNodesSet.Remove(expiredNode);
            

        }
        void darken_edges(float fadeRate)
        {
            List<Tuple<uint,uint>> expiredEdges = new List<Tuple<uint, uint>>();
            foreach (Tuple<uint, uint> edge in fadingAnimEdgesSet)
            {
                if (ReduceEdgeAnimAlpha(edge, fadeRate))
                    expiredEdges.Add(edge);

                Console.WriteLine($"Darkening edge {edge}");
            }

            foreach (Tuple<uint, uint> expiredEdge in expiredEdges)
            { 
                fadingAnimEdgesSet.Remove(expiredEdge); 
            }
        }

        void remove_unchained_from_animation()
        {
            //get rid of any KEEP_BRIGHT nodes/edges waiting to be activated
            newAnimNodeTimes = newAnimNodeTimes.Where(e => e.Value != Anim_Constants.KEEP_BRIGHT).ToDictionary(e => e.Key, e => e.Value);
            newAnimEdgeTimes = newAnimEdgeTimes.Where(e => e.Value != Anim_Constants.KEEP_BRIGHT).ToDictionary(e => e.Key, e => e.Value);

            //allow any nodes/externals/edges that have already been activated to fade
            List<uint> activeKeys = activeAnimNodeTimes.Keys.ToList();
            foreach (uint nodeIdx in activeKeys)
            {
                if (activeAnimNodeTimes[nodeIdx] == Anim_Constants.KEEP_BRIGHT)
                {
                    Console.WriteLine($"remove_unchained_from_animation allowing active node {nodeIdx} to fade");
                    activeAnimNodeTimes[nodeIdx] = 0; 
                }
            }

            //internalProtoGraph.externCallsLock.lock () ;
            activeKeys = activeExternTimes.Keys.ToList();
            foreach (uint nodeIdx in activeKeys)
            {
                EXTTEXT externEntry = activeExternTimes[nodeIdx];
                if (externEntry.framesRemaining == Anim_Constants.KEEP_BRIGHT)
                {
                    externEntry.framesRemaining = GlobalConfig.ExternAnimDisplayFrames / 2;
                    activeExternTimes[nodeIdx] = externEntry;
                }
            }
            //internalProtoGraph.externCallsLock.unlock();
            var activeEdges = activeAnimEdgeTimes.Keys.ToList();
            foreach (var edgeTuple in activeEdges)
            {
                if (activeAnimEdgeTimes[edgeTuple] == Anim_Constants.KEEP_BRIGHT) activeAnimEdgeTimes[edgeTuple] = 0;
            }

        }

        ulong calculate_wait_frames(ulong executions)
        {
            //assume 10 instructions per step/frame
            ulong stepSize = (ulong)clientState.AnimationStepRate;
            if (stepSize == 0) stepSize = 1;
            ulong frames = (internalProtoGraph.TotalInstructions / Anim_Constants.ASSUME_INS_PER_BLOCK) / stepSize;

            float proportion = (float)executions / internalProtoGraph.TotalInstructions;
            ulong waitFrames = (ulong)Math.Floor(proportion * frames);
            return waitFrames;
        }

        void ResetAllActiveAnimatedAlphas()
        {
            foreach (uint nodeIdx in activeAnimNodeTimes.Keys)
            {
                mainnodesdata.SetNodeAnimAlpha(nodeIdx, GlobalConfig.AnimatedFadeMinimumAlpha);
            }
            activeAnimNodeTimes.Clear();

            foreach (uint nodeIdx in FadingAnimNodesSet)
            {
                mainnodesdata.SetNodeAnimAlpha(nodeIdx, GlobalConfig.AnimatedFadeMinimumAlpha);
            }
            FadingAnimNodesSet.Clear();

            foreach (Tuple<uint,uint> edge in activeAnimEdgeTimes.Keys)
            {
                if (!SetEdgeAnimAlpha(edge, GlobalConfig.AnimatedFadeMinimumAlpha)) Console.WriteLine("Warning: Failed to clear an active edge");
            }
            activeAnimEdgeTimes.Clear();

            foreach (Tuple<uint, uint> edge in fadingAnimEdgesSet)
            {
                if (!SetEdgeAnimAlpha(edge, GlobalConfig.AnimatedFadeMinimumAlpha)) Console.WriteLine("Warning: Failed to clear a fading edge");
            }
            fadingAnimEdgesSet.Clear();
        }

        public bool SetEdgeAnimAlpha(Tuple<uint, uint> edgeTuple, float alpha)
        {
            EdgeData edge = internalProtoGraph.edgeDict[edgeTuple];
            if (mainlinedata.CountVerts() <= (edge.arraypos + edge.vertSize)) return false;

            Console.WriteLine($"Setting edge {edgeTuple.Item1}->{edgeTuple.Item2} alpha to {alpha}");
            mainlinedata.SetEdgeAnimAlpha(edge.arraypos, edge.vertSize, alpha);
            return true;
        }

        public bool ReduceEdgeAnimAlpha(Tuple<uint, uint> edgeTuple, float alpha)
        {
            EdgeData edge = internalProtoGraph.edgeDict[edgeTuple];
            if (mainlinedata.CountVerts() <= (edge.arraypos + edge.vertSize)) return false;

            Console.WriteLine($"Reducing edge {edgeTuple.Item1}{edgeTuple.Item2} alpha by {alpha}");
            mainlinedata.ReduceEdgeAnimAlpha(edge.arraypos, edge.vertSize, alpha);
            return true;
        }

        public void UpdateGraphicBuffers(Vector2 size, GraphicsDevice _gd)
        {
            if (_outputFramebuffer == null)
            {
                InitMainGraphTexture(size, _gd);
            }

        }

        public void UpdatePreviewBuffers(GraphicsDevice _gd)
        {
            if (_previewTexture == null)
            {
                InitPreviewGraphTexture(new Vector2(UI_Constants.PREVIEW_PANE_WIDTH - (UI_Constants.PREVIEW_PANE_PADDING * 2), UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT), _gd);
            }
        }


        public void InitMainGraphTexture(Vector2 size, GraphicsDevice _gd)
        {
            if (_outputTexture != null)
            {
                if (_outputTexture.Width == size.X && _outputTexture.Height == size.Y) return;
                else
                {
                    _outputFramebuffer.Dispose();
                    _outputTexture.Dispose();
                }
            }

            _outputTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                                (uint)size.X,
                                (uint)size.Y,
                                1,
                                1,
                                PixelFormat.R32_G32_B32_A32_Float,
                                TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));

        }

        public void InitPreviewGraphTexture(Vector2 size, GraphicsDevice _gd)
        {
            if (_previewTexture != null)
            {
                if (_previewTexture.Width == size.X && _previewTexture.Height == size.Y) return;
                else
                {
                    _previewFramebuffer.Dispose();
                    _previewTexture.Dispose();
                }
            }

            _previewTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                                (uint)size.X,
                                (uint)size.Y,
                                1,
                                1,
                                PixelFormat.R32_G32_B32_A32_Float,
                                TextureUsage.RenderTarget | TextureUsage.Sampled));
            _previewFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _previewTexture));


        }

        //private:
        public Veldrid.Texture _outputTexture = null;
        public Veldrid.Texture _previewTexture = null;
        public Veldrid.Framebuffer _outputFramebuffer = null;
        public Veldrid.Framebuffer _previewFramebuffer = null;



        protected readonly Object renderingLock = new Object();

        ulong renderedBlocksCount = 0;

        //position out of all the instructions instrumented
        ulong animInstructionIndex = 0;
        /*
		//two sets of VBOs for graph so we can display one
		//while the other is being written
		int lastVBO = 2;
		GLuint activeVBOs[4] = { 0, 0, 0, 0 };
		GLuint conditionalVBOs[2] = { 0 };
		*/
        public uint pid { get; private set; }
        public uint tid { get; private set; }
        //PLOT_TRACK lastPreviewNode;

        Dictionary<Tuple<uint, ulong>, int> newExternTimes = new Dictionary<Tuple<uint, ulong>, int>();

        //prevent graph from being deleted while being used
        //rgatlocks::TestableLock graphBusyLock;

        public Matrix4x4 projection;
        public Matrix4x4 view;
        public Matrix4x4 rotation;

        public int AnimationUpdatesPerFrame = GlobalConfig.animationUpdatesPerFrame;

        ulong animLoopCounter = 0;
        ulong unchainedWaitFrames = 0;
        uint maxWaitFrames = 0;

        //which BB we are pointing to in the sequence list
        int animationIndex = 0;

        //have tried List<Tuple<uint,int>> but it's slower
        Dictionary<uint, int> newAnimNodeTimes = new Dictionary<uint, int>();
        Dictionary<uint, int> activeAnimNodeTimes = new Dictionary<uint, int>();
        List<uint> FadingAnimNodesSet = new List<uint>();

        Dictionary<Tuple<uint, uint>, int> newAnimEdgeTimes = new Dictionary<Tuple<uint, uint>, int>();
        Dictionary<Tuple<uint, uint>, int> activeAnimEdgeTimes = new Dictionary<Tuple<uint, uint>, int>();
        List<Tuple<uint, uint>> fadingAnimEdgesSet = new List<Tuple<uint, uint>>();


        bool animBuildingLoop = false;
        bool Stopping = false;
        //int threadReferences = 0;
        public bool IsAnimated { get; private set; } = false;
        bool animation_needs_reset = false;
        public bool NeedReplotting = false; //all verts need re-plotting from scratch
                                            //bool performSymbolResolve = false;
    }
}
