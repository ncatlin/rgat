using Microsoft.Extensions.DependencyModel;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
        /*
        public int maxA = 360;
        public int maxB = 180;
        public int maxC = 1;
        */
        public float pix_per_A, pix_per_B, original_pix_per_A, original_pix_per_B; //todo rename sep
        public float stretchA = 1, stretchB = 1;
    };


    abstract class PlottedGraph
    {
        public enum REPLAY_STATE { eStopped, ePlaying, ePaused, eEnded };
        public struct PLOT_TRACK
        {
            public uint lastVertID;
            public eEdgeNodeType lastVertType;
        };
        protected struct EXTTEXT
        {
            public int framesRemaining;
            public float yOffset;
            public string displayString;
        };
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

            animlinedata = new GraphDisplayData();
            animnodesdata = new GraphDisplayData();
            //blocklines = new GraphDisplayData();

            needVBOReload_conditional = true;
            needVBOReload_heatmap = true;
            needVBOReload_main = true;
            needVBOReload_preview = true;

            lastMainNode.lastVertID = 0;
            lastMainNode.lastVertType = eEdgeNodeType.eFIRST_IN_THREAD;
            //main_scalefactors = new GRAPH_SCALE;
            //preview_scalefactors = new GRAPH_SCALE;

            internalProtoGraph = protoGraph;
            /*
			if (internalProtoGraph.active)
				animated = true;
			else
				animated = false;
			*/
            graphColours = graphColourslist;

            /*
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Red));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(.75f, .75f, -.25f), RgbaFloat.Green));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Blue));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(.75f, -.75f, 0f), RgbaFloat.Yellow));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -0.75f), RgbaFloat.White));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Red));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-1.75f, 0f, -0.75f), RgbaFloat.Pink));
			mainlinedata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Grey));

			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(.75f, .75f, -.25f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(.75f, -.75f, 0f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -0.75f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-1.75f, 0f, -0.75f), RgbaFloat.Cyan));
			mainnodesdata.VertList.Add(new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Cyan));
			*/
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
        protected abstract bool render_edge(Tuple<uint, uint> nodePair, GraphDisplayData edgedata, WritableRgbaFloat? forceColour, bool preview, bool noUpdate);
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
            animnodesdata = new GraphDisplayData();
            animlinedata = new GraphDisplayData();
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

            if (!render_new_preview_edges())
            {
                Console.WriteLine("ERROR: Failed drawing new edges in render_preview_graph! ");
                //assert(0);
            }
        }

        bool render_new_preview_edges()
        {
            /*
			//draw edges
			EDGELIST::iterator edgeIt, edgeEnd;
			//todo, this should be done without the mutex using indexing instead of iteration
			internalProtoGraph->start_edgeL_iteration(&edgeIt, &edgeEnd);

			std::advance(edgeIt, previewlines->get_renderedEdges());
			if (edgeIt != edgeEnd)
				needVBOReload_preview = true;
			*/

            uint startIndex = previewlines.CountRenderedEdges;
            uint endIndex = Math.Min(internalProtoGraph.get_num_edges(), startIndex + GlobalConfig.Preview_EdgesPerRender);
            for (uint edgeIdx = startIndex; edgeIdx < endIndex; edgeIdx++)
            {
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (edgeNodes.Item1 >= previewnodes.CountVerts())
                {
                    NodeData n1 = internalProtoGraph.safe_get_node(edgeNodes.Item1);
                    render_node(n1, ref lastPreviewNode, previewnodes, null, preview_scalefactors);
                }

                if (edgeNodes.Item2 >= previewnodes.CountVerts())
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeNodes];
                    if (e.edgeClass == eEdgeNodeType.eEdgeException)
                        lastPreviewNode.lastVertType = eEdgeNodeType.eNodeException;

                    NodeData n2 = internalProtoGraph.safe_get_node(edgeNodes.Item2);
                    render_node(n2, ref lastPreviewNode, previewnodes, null, preview_scalefactors);

                }

                if (!render_edge(edgeNodes, previewlines, null, true, false))
                {
                    //internalProtoGraph->stop_edgeL_iteration();
                    return false;
                }
            }
            //internalProtoGraph->stop_edgeL_iteration();
            return true;
        }

        /*
		void changeZoom(double delta, double deltaModifier);

		void draw_instructions_text(int zdist, PROJECTDATA* pd, graphGLWidget &gltarget);
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
                schedule_animation_reset();
                reset_animation_if_scheduled();

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

        public void schedule_animation_reset() { animation_needs_reset = true; }
        public void reset_animation_if_scheduled()
        {
            if (!animation_needs_reset) return;

            //deactivate any active nodes/edges
            clear_active();

            //darken any active drawn nodes
            if (internalProtoGraph.NodeList.Count > 0)
            {
                internalProtoGraph.set_active_node(0);
                darken_fading(1.0f);
                darken_fading(1.0f);
            }

            Debug.Assert(fadingAnimEdgesSet.Count == 0 && fadingAnimNodesSet.Count == 0);

            animInstructionIndex = 0;
            lastAnimatedNode = 0;
            animationIndex = 0;

            //animnodesdata.acquire_col_write();

            newAnimEdgeTimes.Clear();
            newAnimNodeTimes.Clear();
            activeAnimEdgeTimes.Clear();
            activeAnimNodeTimes.Clear();
            unchainedWaitFrames = 0;
            currentUnchainedBlocks.Clear();
            animBuildingLoop = false;
            IsAnimated = false;

            //animnodesdata.release_col_write();
            animation_needs_reset = false;
        }
        //float getAnimationPercent() { return (float)((float)animationIndex / (float)internalProtoGraph.savedAnimationData.size()); }
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
        public GraphDisplayData animnodesdata = null;
        public GraphDisplayData animlinedata = null;
        public GraphDisplayData conditionallines = null;
        public GraphDisplayData conditionalnodes = null;
        public GraphDisplayData previewnodes = null;
        public GraphDisplayData previewlines = null;
        //public GraphDisplayData blocklines = null;
        public GraphDisplayData wireframelines = null;

        protected bool needVBOReload_main = true;
        protected bool needVBOReload_active = true;
        protected bool needVBOReload_preview = true;
        protected bool needVBOReload_heatmap = true;
        protected bool needVBOReload_conditional = true;

        public GRAPH_SCALE main_scalefactors = new GRAPH_SCALE();
        protected GRAPH_SCALE preview_scalefactors = new GRAPH_SCALE();
        //GLuint previewVBOs[4] = { 0, 0, 0, 0 };

        //HIGHLIGHT_DATA highlightData;

        //GLuint heatmapEdgeVBO[1] = { 0 };
        GraphDisplayData heatmaplines = null;
        //lowest/highest numbers of edge iterations
        Tuple<ulong, ulong> heatExtremes;
        Tuple<ulong, ulong> condCounts;

        public ulong vertResizeIndex = 0;
        bool VBOsGenned = false;
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

		protected void display_static(graphGLWidget &gltarget)
        {
			if (needVBOReload_main)
			{
				//lock for reading if corrupt graphics happen occasionally
				gltarget.loadVBOs(graphVBOs, mainnodesdata, mainlinedata, blocklines);
				needVBOReload_main = false;
			}

			if (clientState.showNodes)
				gltarget.array_render_points(GL_Constants.VBO_NODE_POS, GL_Constants.VBO_NODE_COL, graphVBOs, mainnodesdata.CountLoadedVerts);

			if (clientState.showEdges)
				gltarget.array_render_lines(GL_Constants.VBO_LINE_POS, GL_Constants.VBO_LINE_COL, graphVBOs, mainlinedata.CountLoadedVerts);

			gltarget.glLineWidth(5.0);
			gltarget.array_render_lines(GL_Constants.VBO_BLOCKLINE_POS, GL_Constants.VBO_BLOCKLINE_COL, graphVBOs, blocklines.CountLoadedVerts);
			gltarget.glLineWidth(1.0);
		}
		*/

        //protected void display_big_conditional(graphGLWidget &gltarget);
        //protected void display_big_heatmap(graphGLWidget &gltarget);


        protected int render_new_edges()
        {
            GraphDisplayData lines = mainlinedata;

            int edgesDrawn = 0;

            //internalProtoGraph.getEdgeReadLock();
            if (lines.CountRenderedEdges >= internalProtoGraph.edgeList.Count) return 0;

            needVBOReload_main = true;
            for (uint edgeIdx = lines.CountRenderedEdges; edgeIdx != internalProtoGraph.edgeList.Count && !Stopping; edgeIdx++)
            {
                Tuple<uint, uint> edgeIt = internalProtoGraph.edgeList[(int)edgeIdx];
                //render source node if not already done
                if (edgeIt.Item1 >= (uint)mainnodesdata.CountVerts())
                {
                    NodeData n = internalProtoGraph.safe_get_node(edgeIt.Item1);
                    render_node(n, ref lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
                }
                else
                    lastMainNode = setLastNode(edgeIt.Item1);


                //render target node if not already done
                if (edgeIt.Item2 >= (uint)mainnodesdata.CountVerts())
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeIt];
                    if (e.edgeClass == eEdgeNodeType.eEdgeException)
                        lastPreviewNode.lastVertType = eEdgeNodeType.eNodeException;

                    NodeData n = internalProtoGraph.safe_get_node(edgeIt.Item2);
                    render_node(n, ref lastMainNode, mainnodesdata, animnodesdata, main_scalefactors);
                }
                else
                    lastMainNode = setLastNode(edgeIt.Item1);

                if (render_edge(edgeIt, lines, null, false, false))
                {
                    ++edgesDrawn;
                }
                else
                    break;
            }

            extend_faded_edges();
            //internalProtoGraph.dropEdgeReadLock();
            return edgesDrawn;
        }


        //protected int render_new_blocks();
        protected void redraw_anim_edges()
        {

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
        }
        /*
		protected void acquire_nodecoord_read();
		protected void acquire_nodecoord_write();
		protected void release_nodecoord_read();
		protected void release_nodecoord_write();
		*/
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
                            lastnode.lastVertType = !n.IsConditional() ?
                                eEdgeNodeType.eNodeJump :
                                eEdgeNodeType.eNodeNonFlow;
                            break;
                        }
                    case eNodeType.eInsJump:
                        {
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

        //protected:

        //mutable std::shared_mutex nodeCoordLock_;
        //mutable std::shared_mutex threadReferenceLock_;

        //rgatlocks::UntestableLock callStackLock;

        bool previewNeedsResize = false;
        bool freeMe = false;
        public bool replotScheduled = false;


        protected List<Tuple<ulong, uint>> MainCallStack = new List<Tuple<ulong, uint>>();
        protected List<Tuple<ulong, uint>> PreviewCallStack = new List<Tuple<ulong, uint>>();

        public ProtoGraph internalProtoGraph { get; protected set; } = null;
        PLOT_TRACK lastMainNode;
        protected uint lastAnimatedNode = 0;
        //Dictionary<uint, EXTTEXT> activeExternTimes;
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
        abstract public void render_node(NodeData n, ref PLOT_TRACK lastNode, GraphDisplayData vertdata, GraphDisplayData animvertdata,
            GRAPH_SCALE dimensions);
        /*
                virtual void render_block(block_data &b, GRAPH_SCALE* dimensions)
                {
                    cerr << "Warning: Virtual render_block called\n" << endl;
                };

                void set_max_wait_frames(uint frames) { maxWaitFrames = frames; }
        */



        void extend_faded_edges()
        {
            int drawnVerts = mainlinedata.CountVerts();
            int animatedVerts = animlinedata.CountVerts();

            Debug.Assert(drawnVerts >= animatedVerts);
            int pendingVerts = drawnVerts - animatedVerts;
            if (pendingVerts == 0) return;

            //List<VertexPositionColor> animEdgeColours = animlinedata.acquire_vert_read();
            //List<VertexPositionColor> staticEdgeColours = mainlinedata.acquire_vert_read();

            //copy the colours over
            Console.WriteLine("Todo all of this extend_faded_edges");
            int fadedIndex = animatedVerts * GL_Constants.COLELEMS;
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

            set_node_alpha(lastAnimatedNode, animnodesdata, GraphicsMaths.getPulseAlpha());

            //live process always at least has pulsing active node
            needVBOReload_active = true;
        }


        void set_node_alpha(uint nIdx, GraphDisplayData nodesdata, float alpha)
        {
            ulong bufIndex = nIdx * GL_Constants.COLELEMS + GL_Constants.AOFF;
            if (bufIndex >= nodesdata.vcolarraySize) return;

            List<VertexPositionColor> colarray = nodesdata.acquire_vert_write();
            colarray[(int)bufIndex].SetAlpha(alpha); //todo
                                                     //nodesdata.release_col_write();
        }
        //node+edge col+pos
        bool get_block_nodelist(ulong blockAddr, long blockID, out List<uint> nodelist)
        {
            ProcessRecord piddata = internalProtoGraph.ProcessData;
            ROUTINE_STRUCT? externBlock = new ROUTINE_STRUCT();
            List<InstructionData> block = piddata.getDisassemblyBlock((uint)blockID, ref externBlock, blockAddr);
            if (block == null)
            {
                nodelist = null;
                return false;
            }
            //if (internalProtoGraph.terminationFlag) return false;

            if (block != null && externBlock != null)
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
                List < Tuple<uint, uint> > calls = null;
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


                //piddata.dropExternCallerReadLock();
                nodelist = new List<uint>();
                foreach (Tuple<uint, uint> edge in calls) //record each call by caller
                {
                    if (edge.Item1 == lastAnimatedNode)
                    {
                        nodelist.Add(edge.Item2);
                    }
                }
                return true;
            }


            nodelist = new List<uint>();
            foreach (InstructionData ins in block)
            {
                if (!ins.threadvertIdx.TryGetValue(tid, out uint val)) return false;
                nodelist.Add(val);
            }

            return true;
        }

        void brighten_next_block_edge(ANIMATIONENTRY entry, int brightTime)
        {
            Console.WriteLine("Todo brighten_next_block_edge");

            /*
            PROCESS_DATA *piddata = internalProtoGraph.get_piddata();
            NODEINDEX nextNode;
            NODEPAIR linkingPair;

            ROUTINE_STRUCT *externBlock = NULL;
            INSLIST* nextBlock = piddata.getDisassemblyBlock(entry.targetAddr, entry.targetID, &externBlock);
            //if next block is external code, find its vert
            if (externBlock)
            {
                piddata.getExternCallerReadLock();

                EDGELIST callers = externBlock.thread_callers.at(tid);
                EDGELIST::iterator callIt = callers.begin();
                for (; callIt != callers.end(); ++callIt)
                {
                    if (callIt.first == lastAnimatedNode)
                    {
                        nextNode = callIt.second;
                        linkingPair = make_pair(lastAnimatedNode, nextNode);
                        break;
                    }
                }

                if (callIt == callers.end())
                {
                    cerr << "[rgat]Error: Caller for " << hex << entry.targetAddr << " not found" << endl;
                    assert(0);
                }

                piddata.dropExternCallerReadLock();
            }
            else
            {
                //find vert in internal code
                INS_DATA* nextIns = nextBlock.front();
                unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = nextIns.threadvertIdx.find(tid);
                if (threadVIt == nextIns.threadvertIdx.end())
                    return;
                nextNode = threadVIt.second;
                linkingPair = make_pair(lastAnimatedNode, nextNode);
            }

            //check edge exists then add it to list of edges to brighten
            if (internalProtoGraph.edge_exists(linkingPair, 0))
            {
                newAnimEdgeTimes[linkingPair] = brightTime;
            }

            /*
            if it doesn't exist then assume it's because the user is skipping around the animation with the slider
            (there are other reasons but it helps me sleep at night)
            */

        }

        void brighten_node_list(ANIMATIONENTRY entry, int brightTime, List<uint> nodeIDList)
        {
            Console.WriteLine("Todo brighten_node_list");
            int instructionCount = 0;
            /*
			foreach (; nodeIt != nodeIDList.end(); ++nodeIt)
			{
				NODEINDEX nodeIdx = *nodeIt;
				newAnimNodeTimes[nodeIdx] = brightTime;

				if (internalProtoGraph.safe_get_node(nodeIdx).external)
				{
					if (brightTime == KEEP_BRIGHT)
						newExternTimes[make_pair(nodeIdx, entry.callCount)] = KEEP_BRIGHT;
					else
						newExternTimes[make_pair(nodeIdx, entry.callCount)] = EXTERN_LIFETIME_FRAMES;
				}

				if (!(entry.entryType == eAnimUnchained && nodeIt == nodeIDList.begin()))
				{
					NODEPAIR edge = make_pair(lastAnimatedNode, nodeIdx);
					if (internalProtoGraph.edge_exists(edge, 0))
					{
						newAnimEdgeTimes[edge] = brightTime;
					}
					//if it doesn't exist it may be because user is skipping code with animation slider
				}

				lastAnimatedNode = nodeIdx;

				++instructionCount;
				if ((entry.entryType == eAnimExecException) && (instructionCount == (entry.count + 1))) break;
			}
			*/
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
                process_replay_update();
            }

            internalProtoGraph.set_active_node(lastAnimatedNode);

            if (animationIndex >= internalProtoGraph.SavedAnimationData.Count - 1)
            {
                replayState = REPLAY_STATE.eEnded;
                return;
            }

            else
                return;

        }

        void process_replay_update()
        {
            ANIMATIONENTRY entry = internalProtoGraph.SavedAnimationData[animationIndex];

            int stepSize = clientState.AnimationStepRate;
            if (stepSize == 0) stepSize = 1;

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
                brightTime = (int)Anim_Constants.eKB.KEEP_BRIGHT;
            }
            else
                brightTime = 20;

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
                    Thread.Sleep(5);
                    Console.WriteLine("[rgat] ANst block 0x" + entry.blockAddr); //todo hex
                }
            }

            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            lastMainNode.lastVertID = lastAnimatedNode;

            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                brighten_next_block_edge(entry, brightTime);
            }

        }


        void brighten_new_active_nodes()
        {
            Console.WriteLine("todo brighten_new_active_nodes");
            /*
			Dictionary<uint, int>::iterator vertIDIt = newAnimNodeTimes.begin();
			while (vertIDIt != newAnimNodeTimes.end())
			{
				NODEINDEX nodeIdx = vertIDIt.first;
				int animTime = vertIDIt.second;

				float ncol = &animnodesdata.acquire_col_write().at(0);

				const size_t arrIndexNodeAlpha = (nodeIdx * COLELEMS) + AOFF;
				if (arrIndexNodeAlpha >= animnodesdata.col_buf_capacity_floats())
				{
					//trying to brighten nodes we havent rendered yet
					animnodesdata.release_col_write();
					break;
				}

				//set alpha value to 1 in animation colour data
				ncol[arrIndexNodeAlpha] = 1;
				animnodesdata.release_col_write();

				//want to delay fading if in loop/unchained area, 
				if (animTime)
				{
					activeAnimNodeTimes[(NODEINDEX)arrIndexNodeAlpha] = animTime;
					set<NODEINDEX>::iterator fadeIt = fadingAnimNodes.find(arrIndexNodeAlpha);
					if (fadeIt != fadingAnimNodes.end())
						fadingAnimNodes.erase(fadeIt);
				}
				else
					fadingAnimNodes.insert((NODEINDEX)arrIndexNodeAlpha);

				vertIDIt = newAnimNodeTimes.erase(vertIDIt);
			}
			*/
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
            Console.WriteLine("todo brighten_new_active_edges");
            /*
			map<NODEPAIR, int>::iterator edgeIDIt = newAnimEdgeTimes.begin();
			while (edgeIDIt != newAnimEdgeTimes.end())
			{
				NODEPAIR nodePair = edgeIDIt.first;
				unsigned int animTime = edgeIDIt.second;

				if (!internalProtoGraph.edge_exists(nodePair, 0))
				{
					cerr << "[rgat]WARNING: brightening new edges non-existant edge " << nodePair.first << "," << nodePair.second << endl;
					break;
				}

				set_edge_alpha(nodePair, animlinedata, 1.0);

				//want to delay fading if in loop/unchained area, 
				if (animTime)
				{
					activeAnimEdgeTimes[nodePair] = animTime;
					set<NODEPAIR>::iterator fadeIt = fadingAnimEdges.find(nodePair);

					if (fadeIt != fadingAnimEdges.end())
						fadingAnimEdges.erase(fadeIt);
				}
				else
					fadingAnimEdges.insert(nodePair);

				edgeIDIt = newAnimEdgeTimes.erase(edgeIDIt);

			}
			*/
        }

        void brighten_new_active()
        {
            if (animnodesdata.CountVerts() == 0) return;

            brighten_new_active_nodes();
            brighten_new_active_extern_nodes();

            brighten_new_active_edges();
        }

        void maintain_active()
        {
            if (animnodesdata.CountVerts() == 0) return;
            Console.WriteLine("todo maintain_active");
            /*
			Dictionary<uint, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();

			float ncol = &animnodesdata.acquire_col_write().at(0);
			float currentPulseAlpha = Math.Max(ANIM_INACTIVE_NODE_ALPHA, getPulseAlpha());
			while (nodeAPosTimeIt != activeAnimNodeTimes.end())
			{
				int brightTime = nodeAPosTimeIt.second;
				if (brightTime == KEEP_BRIGHT)
				{
					ncol[nodeAPosTimeIt.first] = currentPulseAlpha;
					++nodeAPosTimeIt;
					continue;
				}

				if (--nodeAPosTimeIt.second <= 0)
				{
					fadingAnimNodes.insert(nodeAPosTimeIt.first);
					nodeAPosTimeIt = activeAnimNodeTimes.erase(nodeAPosTimeIt);
				}
				else
					++nodeAPosTimeIt;
			}
			animnodesdata.release_col_write();

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

            if (animnodesdata.CountVerts() > 0)
                darken_nodes(fadeRate);

            if (animlinedata.CountVerts() > 0)
                darken_edges(fadeRate);
        }

        void darken_nodes(float fadeRate)
        {
            //todo
        }
        void darken_edges(float fadeRate)
        {
            //todo
        }

        void remove_unchained_from_animation()
        {
            Console.WriteLine("todo remove_unchained_from_animation");
            /*
			//get rid of any nodes/edges waiting to be activated
			map<NODEINDEX, int>::iterator newNodeIt = newAnimNodeTimes.begin();
			while (newNodeIt != newAnimNodeTimes.end() && !newAnimNodeTimes.empty())
				if (newNodeIt.second == KEEP_BRIGHT)
					newNodeIt = newAnimNodeTimes.erase(newNodeIt);
				else
					++newNodeIt;

			map<NODEPAIR, int>::iterator newEdgeIt = newAnimEdgeTimes.begin();
			while (newEdgeIt != newAnimEdgeTimes.end() && !newAnimEdgeTimes.empty())
				if (newEdgeIt.second == KEEP_BRIGHT)
					newEdgeIt = newAnimEdgeTimes.erase(newEdgeIt);
				else
					++newEdgeIt;

			//get rid of any nodes/externals/edges that have already been activated
			map<NODEINDEX, int>::iterator nodeIt = activeAnimNodeTimes.begin();
			for (; nodeIt != activeAnimNodeTimes.end(); ++nodeIt)
				if (nodeIt.second == KEEP_BRIGHT)
					nodeIt.second = 0;

			internalProtoGraph.externCallsLock.lock () ;
			map<NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
			for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
				if (activeExternIt.second.framesRemaining == KEEP_BRIGHT)
					activeExternIt.second.framesRemaining = (int)(EXTERN_LIFETIME_FRAMES / 2);
			internalProtoGraph.externCallsLock.unlock();

			map<NODEPAIR, int>::iterator edgeIt = activeAnimEdgeTimes.begin();
			for (; edgeIt != activeAnimEdgeTimes.end(); ++edgeIt)
				if (edgeIt.second == KEEP_BRIGHT)
					edgeIt.second = 0;
			*/
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

        void clear_active()
        {
            if (animnodesdata.CountVerts() == 0) return;

            Console.WriteLine("Todo all of this clear_active");
            if (activeAnimNodeTimes.Count > 0)
            {
                /*
				Dictionary<uint, int>::iterator nodeAPosTimeIt = activeAnimNodeTimes.begin();
				float ncol = &animnodesdata.acquire_col_write().at(0);

				for (; nodeAPosTimeIt != activeAnimNodeTimes.end(); ++nodeAPosTimeIt)
					ncol[nodeAPosTimeIt.first] = ANIM_INACTIVE_NODE_ALPHA;
				animnodesdata.release_col_write();
				*/
                //todo obviously this is garbage but just trying to make it compile then come back to it
                List<VertexPositionColor> nodeColours = animnodesdata.acquire_vert_write();
                nodeColours.ForEach(x => x.Color.A += Anim_Constants.ANIM_INACTIVE_NODE_ALPHA);
                animnodesdata.release_vert_write();

            }

            if (activeAnimEdgeTimes.Count > 0)
            {
                /*
				Dictionary<Tuple<uint,uint>, int>::iterator edgeIDIt = activeAnimEdgeTimes.begin();
				for (; edgeIDIt != activeAnimEdgeTimes.end(); ++edgeIDIt)
				{
					edge_data* pulsingEdge;
					if (internalProtoGraph.edge_exists(edgeIDIt.first, &pulsingEdge))
						set_edge_alpha(edgeIDIt.first, animlinedata, ANIM_INACTIVE_EDGE_ALPHA);
				}
				*/
                List<VertexPositionColor> edgeColours = animlinedata.acquire_vert_write();
                edgeColours.ForEach(x => x.Color.A += Anim_Constants.ANIM_INACTIVE_NODE_ALPHA);
                animlinedata.release_vert_write();
            }
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
        PLOT_TRACK lastPreviewNode;

        //Dictionary<Tuple<uint, ulong>, int> newExternTimes;

        //prevent graph from being deleted while being used
        //rgatlocks::TestableLock graphBusyLock;


        public int AnimationUpdatesPerFrame = GlobalConfig.animationUpdatesPerFrame;

        ulong animLoopCounter = 0;
        ulong unchainedWaitFrames = 0;
        uint maxWaitFrames = 0;

        //which BB we are pointing to in the sequence list
        int animationIndex = 0;

        //have tried List<Tuple<uint,int>> but it's slower
        Dictionary<uint, int> newAnimNodeTimes = new Dictionary<uint, int>();
        Dictionary<uint, int> activeAnimNodeTimes = new Dictionary<uint, int>();
        List<uint> fadingAnimNodesSet = new List<uint>();

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
