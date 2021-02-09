using Microsoft.Extensions.DependencyModel;
//using Microsoft.Msagl.Core.Layout;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
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


    class PlottedGraph
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





        public static string GetTestNodesAndEdgesArray()
        {
            //string ijson = "[[1,2,5,8,12,13,19,57,60,61,62,63,65,66,67,99,100,101,102,108,111,9,119,122,125,130,131,132,133,91,134,143,144,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,109,194,195,196,197,7,202,203,204,152,205,231,232,236,237,238,251,289,307,308,309,311,321,324],[0,10,15,17,21,30,47,81,7,120,247],[0],[4,310],[3,9,14,20,23,24,25,26,27,28,29,31,35,36,37,43,44,45,46,55,56,58,59,64,69,63,73,74,75,76,78,79,80,91,93,88,97,98,104,99,105,106,107,112,113,114,116,117,118,124,127,128,135,136,137,145,146,147,148,150,159,160,161,162,163,164,165,166,167,168,173,174,199,201,207,208,209,211,212,215,216,219,220,221,222,223,224,225,226,227,230,231,233,234,235,239,240,155,158,245,249,250,252,253,254,256,257,258,259,260,242,262,263,264,265,299,300,305,71,313],[0],[7,312],[6,30,1,0,81,10],[0],[4,0],[1,11,52,53,19,54,68,72,109,110,126,129,139,140,141,142,198,206,143,144,246,261,242,266,94,267,268,269,270,271,272,99,273,274,275,276,277,278,279,280,281,282,283,284,285,286,7,287,288,289,290,291,292,293,294,295,296,297,298,299,301,302,303,304,85,306,316,317,318,319,320,322,323],[10],[0,15],[0,15],[4],[1,16,13,77,68,123,200,12,217,218,255,54],[15],[1,18,70,138,210,248],[17],[0,10],[4],[1,22,115,213,214,130],[21],[4],[4],[4],[4],[4],[4],[4],[1,32,33,34,38,39,40,41,42,7,171,172,315],[4],[30],[30],[30],[4],[4],[4],[30],[30],[30],[30],[30],[4],[4],[4],[4],[1,48,49,50,51,103,169,170,228,229],[47],[47],[47],[47],[10],[10],[10,15],[4],[4],[0],[4],[4],[0],[0],[0],[0,4],[4],[0],[0],[0],[10,15],[4],[17],[72,4],[71,10],[4],[4],[4],[4],[15],[4],[4],[4],[82,83,1,84,85,86,87,88,89,90,91,92,93,94,95,96,97,149,150,151,152,153,154,155,156,157,158,241,242,243,7,244,314],[81],[81],[81],[81,10],[81],[81],[81,4],[81],[81],[4,81,0],[81],[4,81],[81,10],[81],[81],[81,4],[4],[0,4,10],[0],[0],[0],[47],[4],[4],[4],[4],[0],[10,0],[10],[0],[4],[4],[4],[21],[4],[4],[4],[0],[121,1,206],[120],[0],[15],[4],[0],[10],[4],[4],[10],[0,21],[0],[0],[0],[0],[4],[4],[4],[17],[10],[10],[10],[10],[0,10],[0,10],[4],[4],[4],[4],[81],[4,81],[81],[81,0],[81],[81],[81,4],[81],[81],[81,4],[4],[4],[4],[4],[4],[4],[4],[4],[4],[4],[47],[47],[30],[30],[4],[4],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[10],[4],[15],[4],[0],[0],[0],[0],[10,247,120],[4],[4],[4],[17],[4],[4],[21],[21],[4],[4],[15],[15],[4],[4],[4],[4],[4],[4],[4],[4],[4],[47],[47],[4],[0,4],[0],[4],[4],[4],[0],[0],[0],[4],[4],[81],[81,4,10],[81],[81],[4],[10],[1,206],[17],[4],[4],[0],[4],[4],[4],[15],[4],[4],[4],[4],[4],[10],[4],[4],[4],[4],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10,0],[10],[10],[10],[10],[10],[10],[10],[10],[10],[10,4],[4],[10],[10],[10],[10],[4],[10],[0],[0],[0],[3],[0],[6],[4],[81],[30],[10],[10],[10],[10],[10],[0],[10],[10],[0]]";
            //string ijson = "[[1,2,3,4],[0],[0],[0],[0,5,6,7,8],[4],[4],[4],[4]]";

            /*
            0 Color.Red;
            1 Color.SandyBrown;
            2 Color.White;
            3 Color.Green;
            4 Color.Blue;
            5 Color.Yellow;
            6 Color.Purple;
            7 Color.Gray;
            8 Color.Orange;
             */
            //string ijson = "[[1],[0,2,3],[1],[1]]";
            string ijson = "[[1],[0],[1],[1],[0],[0],[0],[0],[1],[1]]";
            //string ijson = "[[1],[0],[1],[1],[0],[0]]";
            //string ijson = "[[1],[0],[1],[2]]";
            return ijson;
        }



        /*
 * The drawing graph has one way edges. 
 * This makes them 2 way for the purpose of attraction during velocity computation 
    before "[[1],        [0],        [1],[1],[0],[0],[0],[0],[1],[1]]";
    after  "[[1,4,5,6,7],[0,2,3,8,9],[1],[1],[0],[0],[0],[0],[1],[1]]";
*/
        static List<List<int>> DoubleEdgeify(List<List<int>> ingraph)
        {
            List<List<int>> outgraph = new List<List<int>>(ingraph);
            for (var srcNodeIdx = 0; srcNodeIdx < ingraph.Count; srcNodeIdx++)
            {
                List<int> outEdges = ingraph[srcNodeIdx];
                for (var outEdgeIdx = 0; outEdgeIdx < outEdges.Count; outEdgeIdx++)
                {
                    int outNodeIdx = outEdges[outEdgeIdx];
                    if (!outgraph[outNodeIdx].Contains(srcNodeIdx))
                    {
                        outgraph[outNodeIdx].Add(srcNodeIdx);
                    }
                }

            }
            return outgraph;
        }


        public PlottedGraph(ProtoGraph protoGraph, List<WritableRgbaFloat> graphColourslist)
        {

            //List<List<int>> initialTestNodes = Newtonsoft.Json.JsonConvert.DeserializeObject<List<List<int>>>(GetTestNodesAndEdgesArray());
            //AddInitialNodes(initialTestNodes);


            pid = protoGraph.TraceData.PID;
            tid = protoGraph.ThreadID;

            //possibly conditional. diff graphs won't want heatmaps etc
            NodesDisplayData = new GraphDisplayData();
            EdgesDisplayData = new GraphDisplayData();
            HighlightsDisplayData = new GraphDisplayData();

            //conditionallines = new GraphDisplayData();
            //conditionalnodes = new GraphDisplayData();
            //heatmaplines = new GraphDisplayData();

            //blocklines = new GraphDisplayData();


            //main_scalefactors = new GRAPH_SCALE;
            //preview_scalefactors = new GRAPH_SCALE;

            internalProtoGraph = protoGraph;

            IsAnimated = !internalProtoGraph.Terminated;
            graphColours = graphColourslist;

            //TestLayoutSettings = new GRAPH_LAYOUT_SETTINGS();
            scalefactors.plotSize = 300;
            scalefactors.basePlotSize = 300f;
            scalefactors.userSizeModifier = 1;
            CameraClippingFar = 60000f;
            CameraZoom = -6000f;
            CameraXOffset = -400;
            CameraYOffset = 0;
            PlotZRotation = 0f;
        }


        void AddInitialNodes(List<List<int>> nodesList)
        {

            for (uint i = 0; i < nodesList.Count; i++)
            {
                AddNode(i, new List<int>(), true);
            }
            for (var srcI = 0; srcI < nodesList.Count; srcI++)
            {
                var nodeNeighbours = nodesList[srcI];
                for (var destI = 0; destI < nodeNeighbours.Count; destI++)
                {
                    AddEdge(srcI, nodeNeighbours[destI]);
                }
            }
        }


        //public GRAPH_LAYOUT_SETTINGS TestLayoutSettings;

        public void InitialiseDefaultDimensions()
        {

            //todo
        }
        public void InitialisePreviewDimensions()
        {

            //todo
        }
        public void initialiseCustomDimensions(GRAPH_SCALE scale)
        {

            //todo
        }
        /*
		virtual void plot_wireframe(graphGLWidget &gltarget) { };
		virtual void maintain_draw_wireframe(graphGLWidget &gltarget) { };

		virtual bool get_visible_node_pos(uint nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget)
		{
			cerr << "Warning: Virtual gvnp called" << endl; return false;
		};
		*/
        public void render_graph()
        {
            render_new_blocks();
        }
        /*
		virtual void performMainGraphDrawing(graphGLWidget &gltarget) { cout << "virtual pmgd called" << endl; };
		virtual void performDiffGraphDrawing(graphGLWidget &gltarget, void* divergeNodePosition);

		virtual void orient_to_user_view() { };
		*/
        protected bool render_edge(Tuple<uint, uint> nodePair, WritableRgbaFloat? forceColour)
        {
            //todo
            return true;
        }
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

        protected void PlotRerender()
        {
          // ReRender();
        }


        public void ReRender()
        {
            EdgesDisplayData = new GraphDisplayData();
            NodesDisplayData = new GraphDisplayData();
            HighlightsDisplayData = new GraphDisplayData();
            wireframelines = new GraphDisplayData();
            NeedReplotting = false;
            PlotRerender();
        }

        public void UpdateMainRender()
        {
            render_graph();
        }

        public void SeekToAnimationPosition(float position)
        {
            if (ReplayState == REPLAY_STATE.eStopped)
            {
                ReplayState = REPLAY_STATE.ePaused;
                SetAnimated(true);
            }

            int NewPosition = (int)(position * (float)internalProtoGraph.SavedAnimationData.Count);
            userSelectedAnimPosition = NewPosition;

        }

        //void changeZoom(double delta, double deltaModifier);

        //iterate through all the nodes, draw instruction text for the ones in view
        //TODO: in animation mode don't show text for inactive nodes
        void DrawInstructionsText(int zdist)//, PROJECTDATA* pd, graphGLWidget &gltarget)
        {
            string displayText = "?";

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
                //NeedReplotting = true;

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

        //This should only ever be called from the rendering thread
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
            NodesDisplayData.LastAnimatedNode.lastVertID = 0;
            animationIndex = 0;

            //animnodesdata.acquire_col_write();

            newAnimEdgeTimes.Clear();
            newAnimNodeTimes.Clear();

            unchainedWaitFrames = 0;
            currentUnchainedBlocks.Clear();
            animBuildingLoop = false;
            IsAnimated = false;

            ReplayState = REPLAY_STATE.eStopped;
            NodesDisplayData.LastAnimatedNode.lastVertID = 0;
            Console.WriteLine("Animation Stopped");
            //animnodesdata.release_col_write();


        }

        public float GetAnimationPercent()
        {
            if (internalProtoGraph.SavedAnimationData.Count == 0) return 0;
            return (float)((float)animationIndex / (float)internalProtoGraph.SavedAnimationData.Count);
        }

        public void render_live_animation(float fadeRate)
        {
            process_live_animation_updates();
            render_animation(fadeRate);

        }


        public  void draw_highlight_lines()
        {
            //todo
            return;
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
            IsAnimated = newState;
        }

        //public float zoomMultiplier() { return GraphicsMaths.zoomFactor(cameraZoomlevel, scalefactors.plotSize); }
        /*
		bool isWireframeSupported() { return wireframeSupported; }
		bool isWireframeActive() { return wireframeActive; }
		*/

        public static rgatState clientState;

        //GLuint graphVBOs[6] = { 0, 0, 0, 0, 0, 0 };


        public GraphDisplayData NodesDisplayData = null;
        //public GraphDisplayData BlocksDisplayData = null;
        public GraphDisplayData EdgesDisplayData = null;
        public GraphDisplayData HighlightsDisplayData = null;
        //public GraphDisplayData blocklines = null;
        public GraphDisplayData wireframelines = null;


        public GRAPH_SCALE scalefactors = new GRAPH_SCALE();

        //lowest/highest numbers of edge iterations
        Tuple<ulong, ulong> heatExtremes;
        Tuple<ulong, ulong> condCounts;

        public ulong vertResizeIndex = 0;
        public int userSelectedAnimPosition = -1;

        public REPLAY_STATE ReplayState = REPLAY_STATE.eEnded;
        int updateProcessingIndex = 0;
        protected float maxA = 0, maxB = 0, maxC = 0;

        int threadReferences = 0;
        bool schedule_performSymbolResolve = false;

        protected List<TEXTRECT> labelPositions = new List<TEXTRECT>();

        protected readonly Object textLock = new Object();
        protected List<TEXTITEM> texts = new List<TEXTITEM>();


        public List<TEXTITEM> GetOnScreenTexts(GraphicsMaths.SCREENINFO scrn)
        {
            //todo
            return null;
        }

        int wireframeMode; //used to query the current mode

        public void PlayPauseClicked()
        {
            switch (ReplayState)
            {
                case REPLAY_STATE.eStopped: //start it from beginning
                    ReplayState = REPLAY_STATE.ePlaying;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Stopped -> Playing");
                    break;

                case REPLAY_STATE.ePlaying: //pause it
                    ReplayState = REPLAY_STATE.ePaused;
                    Console.WriteLine("Animation state Playing -> Paused");
                    break;

                case REPLAY_STATE.ePaused: //unpause it
                    ReplayState = REPLAY_STATE.ePlaying;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Paused -> Playing");
                    break;

            }
        }

        public void ResetClicked()
        {
            ReplayState = REPLAY_STATE.eEnded;

        }

        protected void render_new_blocks()
        {
            int edgesDrawn = 0;
            uint startIndex = EdgesDisplayData.CountRenderedEdges;
            int endIndex = internalProtoGraph.edgeList.Count;
            for (uint edgeIdx = startIndex; edgeIdx < endIndex; edgeIdx++)
            {
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (edgeNodes.Item1 >= NodesDisplayData.CountVerts())
                {
                    NodeData n1 = internalProtoGraph.safe_get_node(edgeNodes.Item1);
                    //render_node(n1);
                    AddNode(edgeNodes.Item1);
                }

                if (edgeNodes.Item2 >= NodesDisplayData.CountVerts())
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeNodes];
                    if (e.edgeClass == eEdgeNodeType.eEdgeException)
                        NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeException;
                    AddNode(edgeNodes.Item2);

                }

                AddEdge((int)edgeNodes.Item1, (int)edgeNodes.Item2);
                edgesDrawn++;

                if (NeedReplotting || clientState.rgatIsExiting) break;
            }
        }



        bool freeMe = false;

        protected Stack<Tuple<ulong, uint>> ThreadCallStack = new Stack<Tuple<ulong, uint>>();

        public ProtoGraph internalProtoGraph { get; protected set; } = null;

        Dictionary<uint, EXTTEXT> activeExternTimes = new Dictionary<uint, EXTTEXT>();
        protected List<ANIMATIONENTRY> currentUnchainedBlocks = new List<ANIMATIONENTRY>();
        protected List<WritableRgbaFloat> graphColours = new List<WritableRgbaFloat>();

        protected bool wireframeSupported;
        protected bool wireframeActive;
        //Tuple<long, long> defaultViewShift;
        long defaultZoom;
        public graphLayouts layout { get; protected set; }

        public float[] positionsArray1 = Array.Empty<float>();
        public float[] positionsArray2 = Array.Empty<float>();
        public float[] velocityArray1 = Array.Empty<float>();
        public float[] velocityArray2 = Array.Empty<float>();
        public float[] nodeAttribArray1 = Array.Empty<float>();
        public float[] nodeAttribArray2 = Array.Empty<float>();
        public float[] presetPositionsArray = Array.Empty<float>();


        /// <summary>
        /// The raw list of nodes with a one way edge they connect to
        /// This is used for drawing nodes and edges
        /// </summary>
        List<List<int>> _graphStructureLinear = new List<List<int>>();
        public int NodeCount() { return _graphStructureLinear.Count; }

        /// <summary>
        /// The list of nodes and edges where each node connects to its partner and that node connects back
        /// This is used for the attraction velocity computation
        /// </summary>
        List<List<int>> _graphStructureBalanced = new List<List<int>>();
        public float temperature = 0;

        public unsafe int[] GetEdgeDataInts()
        {
            //var textureSize = indexTextureSize(_graphStructureLinear.Count);
            List<List<int>> targetArray = _graphStructureBalanced;
            var textureSize = indexTextureSize(targetArray.Count);
            int[] textureArray = new int[textureSize * textureSize * 4];

            var currentIndex = 0;
            for (var i = 0; i < targetArray.Count; i++)
            {
                for (var j = 0; j < targetArray[i].Count; j++)
                {
                    textureArray[currentIndex] = targetArray[i][j];
                    currentIndex++;
                }
            }

            for (var i = currentIndex; i < textureArray.Length; i++)
            {
                //fill unused RGBA slots with -1
                textureArray[i] = -1;
            }

            return textureArray;
        }

        public void UpdateNodePositions(MappedResourceView<float> newPositions, uint count)
        {
            Debug.Assert(positionsArray1.Length <= count);  //This is assumed to never shrink
            if (positionsArray1.Length < count)
                positionsArray1 = new float[count];
            for (var i = 0; i < count; i++)
                positionsArray1[i] = newPositions[i];
            
        }

        //This is assumed to never shrink
        public void UpdateNodeVelocities(MappedResourceView<float> newVelocities, uint count)
        {
            Debug.Assert(velocityArray1.Length <= count); //This is assumed to never shrink
            if (velocityArray1.Length < count)
                velocityArray1 = new float[count];
            for (var i = 0; i < count; i++)
                velocityArray1[i] = newVelocities[i];
        }


        public float[] GetVelocityFloats()
        {
            return velocityArray1;
        }
        public float[] GetPositionFloats()
        {
            return positionsArray1;
        }
        public float[] GetNodeAttribFloats()
        {
            return nodeAttribArray1;
        }
        public float[] GetPresetPositionFloats()
        {
            return presetPositionsArray;
        }

        public void IncreaseTemperature()
        {
            temperature += _graphStructureLinear.Count / 2;
        }


        void EnlargeRAMDataBuffers(uint size)
        {
            float[] newVelocityArr1 = new float[size];
            float[] newVelocityArr2 = new float[size];
            float[] newPositionsArr1 = new float[size];
            float[] newPositionsArr2 = new float[size];
            float[] newAttsArr1 = new float[size];
            float[] newAttsArr2 = new float[size];
            float[] newPresetsArray = new float[size];

            int endLength = 0;
            if (velocityArray1 != null)
            {
                endLength = velocityArray1.Length;
                for (var i = 0; i < endLength; i++)
                {
                    newVelocityArr1[i] = velocityArray1[i];
                    newVelocityArr2[i] = velocityArray2[i];
                    newPositionsArr1[i] = positionsArray1[i];
                    newPositionsArr2[i] = positionsArray2[i];
                    newAttsArr1[i] = nodeAttribArray1[i];
                    newAttsArr2[i] = nodeAttribArray2[i];
                    newPresetsArray[i] = presetPositionsArray[i];
                }
            }

            for (var i = endLength; i < size; i++)
            {
                newVelocityArr1[i] = -1;
                newVelocityArr2[i] = -1;
                newPositionsArr1[i] = -1;
                newPositionsArr2[i] = -1;
                newAttsArr1[i] = -1;
                newAttsArr2[i] = -1;
                newPresetsArray[i] = 0;
            }


            positionsArray1 = newPositionsArr1;
            positionsArray2 = newPositionsArr2;
            velocityArray1 = newVelocityArr1;
            velocityArray2 = newVelocityArr2;
            nodeAttribArray1 = newAttsArr1;
            nodeAttribArray2 = newAttsArr2;
            presetPositionsArray = newPresetsArray;
        }


        void AddNode(uint nodeIdx)
        {
            if (nodeIdx < _graphStructureLinear.Count) return;
            AddNode(nodeIdx, new List<int>(), false);
        }
        
        unsafe void AddNode(uint nodeIdx, List<int> destNodes, bool doubleEdge)
        {
            Debug.Assert(nodeIdx == _graphStructureLinear.Count);

            var bounds = 1000;
            var bounds_half = bounds / 2;

            _graphStructureLinear.Add(destNodes);
            _graphStructureBalanced.Add(destNodes);

            if (doubleEdge)
            {
                var srcNodeIdx = _graphStructureBalanced.Count - 1;
                foreach (int dstNodeIdx in destNodes)
                {
                    if (!_graphStructureBalanced[dstNodeIdx].Contains(srcNodeIdx))
                    {
                        _graphStructureBalanced[dstNodeIdx].Add(srcNodeIdx);
                    }
                }
            }


            int oldVelocityArraySize = (velocityArray1 != null) ? velocityArray1.Length * sizeof(float) : 0;

            var bufferWidth = indexTextureSize(_graphStructureLinear.Count);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            var bufferSize = bufferFloatCount * sizeof(float);

            if (bufferSize > oldVelocityArraySize)
            {
                Console.WriteLine($"Recreating graph RAM buffers as {bufferSize} > {oldVelocityArraySize}");
                EnlargeRAMDataBuffers(bufferFloatCount);
            }

            Random rnd = new Random();
            float[] nodePositionEntry = {
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half, 1 };

            uint offset = ((uint)(_graphStructureLinear.Count - 1)) * 4;
            positionsArray1[offset] = nodePositionEntry[0];
            positionsArray1[offset + 1] = nodePositionEntry[1];
            positionsArray1[offset + 2] = nodePositionEntry[2];
            positionsArray1[offset + 3] = nodePositionEntry[3];
            positionsArray2[offset] = nodePositionEntry[0];
            positionsArray2[offset + 1] = nodePositionEntry[1];
            positionsArray2[offset + 2] = nodePositionEntry[2];
            positionsArray2[offset + 3] = nodePositionEntry[3];

            presetPositionsArray[offset] = 0;
            presetPositionsArray[offset + 1] = 0;
            presetPositionsArray[offset + 2] = 0;
            presetPositionsArray[offset + 3] = 0;

            velocityArray1[offset] = 0;
            velocityArray1[offset + 1] = 0;
            velocityArray1[offset + 2] = 0;
            velocityArray1[offset + 3] = 0;
            velocityArray2[offset] = 0;
            velocityArray2[offset + 1] = 0;
            velocityArray2[offset + 2] = 0;
            velocityArray2[offset + 3] = 0;


            nodeAttribArray1[offset] = 200f;
            nodeAttribArray1[offset + 1] = 1f;// 0.5f;
            nodeAttribArray1[offset + 2] = 0;
            nodeAttribArray1[offset + 3] = 0;
            nodeAttribArray2[offset] = 200f;
            nodeAttribArray2[offset + 1] = 1f;// 0.5f;
            nodeAttribArray2[offset + 2] = 0;
            nodeAttribArray2[offset + 3] = 0;

        }


        public unsafe int[] GetEdgeIndicesInts()
        {
            List<List<int>> targetArray = _graphStructureBalanced;
            var textureSize = indexTextureSize(targetArray.Count);

            int[] sourceData = new int[textureSize * textureSize * 4];
            int currentPixel = 0;
            int currentCoord = 0;

            for (var i = 0; i < targetArray.Count; i++)
            {

                //keep track of the beginning of the array for this node

                int startPixel = currentPixel;
                int startCoord = currentCoord;

                for (var j = 0; j < targetArray[i].Count; j++)
                {

                    // look inside each node array and see how many things it links to

                    currentCoord++;

                    if (currentCoord == 4)
                    {

                        // remainder is only 0-3.  If you hit 4, increment pixel and reset coord

                        currentPixel++;
                        currentCoord = 0;

                    }

                }

                //write the two sets of texture indices out.  We'll fill up an entire pixel on each pass
                sourceData[i * 4] = startPixel;
                sourceData[i * 4 + 1] = startCoord;
                sourceData[i * 4 + 2] = currentPixel;
                sourceData[i * 4 + 3] = currentCoord;

            }

            for (var i = targetArray.Count * 4; i < sourceData.Length; i++)
            {

                // fill unused RGBA slots with -1
                sourceData[i] = -1;
            }
            return sourceData;
        }

        //todo: convert to uint
        void AddEdge(int srcNodeIdx, int destNodeIdx)
        {
            Debug.Assert(srcNodeIdx >= 0 && destNodeIdx >= 0);
            Debug.Assert(srcNodeIdx < _graphStructureLinear.Count && destNodeIdx < _graphStructureLinear.Count);

            if (!_graphStructureBalanced[destNodeIdx].Contains(srcNodeIdx))
            {
                _graphStructureBalanced[destNodeIdx].Add(srcNodeIdx);
            }
            if (!_graphStructureBalanced[srcNodeIdx].Contains(destNodeIdx))
            {
                _graphStructureBalanced[srcNodeIdx].Add(destNodeIdx);
            }


        }

        public void AddRandomEdge()
        {
            Random rnd = new Random();
            int src = rnd.Next(0, _graphStructureLinear.Count - 1);
            int dst = src;
            while (dst == src)
                dst = rnd.Next(0, _graphStructureLinear.Count - 1);
            Console.WriteLine($"Adding edge between {src} and {dst}");
            AddEdge(src, dst);
            //RegenerateEdgeDataBuffers();
            temperature += 3 * 10.0f;
        }

        public unsafe void AddTestNodes()
        {
            Random rnd = new Random();

            int nodesToAdd = rnd.Next(1, 5);
            for (var i = 0; i < nodesToAdd; i++)
            {
                var linksList = new List<int>();
                int linksToAdd = rnd.Next(1, 3);
                for (var vl = 0; vl < linksToAdd; vl++)
                {
                    int val = rnd.Next(Math.Max(0,_graphStructureLinear.Count - 8), _graphStructureLinear.Count);
                    if(!linksList.Contains(val))
                        linksList.Add(val);
                }

                AddNode((uint)_graphStructureLinear.Count, linksList, true);
            }

            temperature += nodesToAdd * 10.0f;
        }

        void InitBlankPresetLayout()
        {
            var bufferWidth = indexTextureSize(_graphStructureLinear.Count);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            float[] presetPositionsArray = new float[bufferFloatCount];
            
            for (var i = 0; i < presetPositionsArray.Length; i += 4)
            {
                if (i < _graphStructureLinear.Count * 4)
                {
                    presetPositionsArray[i] = 0.0f;
                    presetPositionsArray[i + 1] = 0.0f;
                    presetPositionsArray[i + 2] = 0.0f;
                    presetPositionsArray[i + 3] = 0.0f;
                }
                else
                {
                    // fill the remaining pixels with -1
                    presetPositionsArray[i] = -1.0f;
                    presetPositionsArray[i + 1] = -1.0f;
                    presetPositionsArray[i + 2] = -1.0f;
                    presetPositionsArray[i + 3] = -1.0f;
                }

            }
            
        }

        public uint LinearIndexTextureSize() { return indexTextureSize(_graphStructureLinear.Count); }
        public uint EdgeTextureWidth() { return dataTextureSize(countDataArrayItems(_graphStructureLinear)); }

        public static Color Getcolor(uint index)
        {
            //return Color.White;
            if (index == 0) return Color.Red;
            if (index == 1) return Color.SandyBrown;
            if (index == 2) return Color.White;
            if (index == 3) return Color.Green;
            if (index == 4) return Color.Blue;
            if (index == 5) return Color.Yellow;
            if (index == 6) return Color.Purple;
            if (index == 7) return Color.Gray;
            if (index == 8) return Color.Orange;
            return Color.Aquamarine;
        }

        public GraphPlotWidget.TestVertexPositionColor[] GetNodeVerts(
            out List<uint> nodeIndices,
            out GraphPlotWidget.TestVertexPositionColor[] nodePickingColors)

        {

            uint textureSize = LinearIndexTextureSize();
            GraphPlotWidget.TestVertexPositionColor[] TestNodeVerts = new GraphPlotWidget.TestVertexPositionColor[textureSize * textureSize];
            nodePickingColors = new GraphPlotWidget.TestVertexPositionColor[textureSize * textureSize];

            nodeIndices = new List<uint>();
            for (uint y = 0; y < textureSize; y++)
            {
                for (uint x = 0; x < textureSize; x++)
                {
                    var index = y * textureSize + x;
                    if (index >= NodeCount()) return TestNodeVerts;
                    TestNodeVerts[index] =
                        new GraphPlotWidget.TestVertexPositionColor { TexPosition = new Vector2(x, y), Color = new WritableRgbaFloat(Getcolor(index)) };
                    nodeIndices.Add(index);
                    nodePickingColors[index] = new GraphPlotWidget.TestVertexPositionColor { TexPosition = new Vector2(x, y), Color = new WritableRgbaFloat(index, 0, 0, 1) };
                }
            }
            return TestNodeVerts;
        }

        public GraphPlotWidget.TestVertexPositionColor[] GetEdgeLineVerts(out List<uint> edgeIndices)
        {
            uint telvTextSize = EdgeTextureWidth();
            GraphPlotWidget.TestVertexPositionColor[] TestEdgeLineVerts =
                    new GraphPlotWidget.TestVertexPositionColor[telvTextSize * telvTextSize * 16];

            uint txIdx = 0;
            edgeIndices = new List<uint>();
            uint textureSize = LinearIndexTextureSize();
            for (var srcNodeIdx = 0; srcNodeIdx < NodeCount(); srcNodeIdx++)
            {
                List<int> destNodes = _graphStructureLinear[srcNodeIdx];
                for (var dstNodeIdx = 0; dstNodeIdx < destNodes.Count; dstNodeIdx++)
                {
                    TestEdgeLineVerts[txIdx] =
                        new GraphPlotWidget.TestVertexPositionColor
                        {
                            TexPosition = new Vector2(srcNodeIdx % textureSize, (float)Math.Floor((float)(srcNodeIdx / textureSize))),
                            Color = new WritableRgbaFloat(Getcolor((uint)srcNodeIdx))
                        };
                    edgeIndices.Add(txIdx);
                    txIdx++;

                    var dstNodeID = destNodes[dstNodeIdx];
                    TestEdgeLineVerts[txIdx] =
                        new GraphPlotWidget.TestVertexPositionColor
                        {
                            TexPosition = new Vector2(dstNodeID % textureSize,
                                        (float)Math.Floor((float)(dstNodeID / textureSize))),
                            Color = new WritableRgbaFloat(Getcolor((uint)dstNodeID))
                        };
                    edgeIndices.Add(txIdx);
                    txIdx++;
                }
            }
            return TestEdgeLineVerts;
        }



        public static uint dataTextureSize(int num)
        {
            return indexTextureSize((int)Math.Ceiling((double)num / 4.0));
        }

        public static uint indexTextureSize(int nodesEdgesLength)
        {
            var power = 1;
            while (power * power < nodesEdgesLength)
            {
                power *= 2;
            }
            return power / 2 > 1 ? (uint)power : 2;
        }

        //todo: linq
        static int countDataArrayItems(List<List<int>> dataArray)
        {
            int counter = 0;
            for (var i = 0; i < dataArray.Count; i++)
            {
                counter += dataArray[i].Count;
            }
            return counter;
        }

























        //private:
        /*
		virtual void positionVert(void* positionStruct, MEM_ADDRESS address) { };
		virtual void display_graph(PROJECTDATA* pd) { };
		virtual FCOORD uintToXYZ(uint index, GRAPH_SCALE* dimensions, float diamModifier) { cerr << "Warning: Virtual uintToXYZ called\n" << endl; FCOORD x; return x; };
		*/
        public void render_node(NodeData n)
        {
            //todo
        }
        /*
                virtual void render_block(block_data &b, GRAPH_SCALE* dimensions)
                {
                    cerr << "Warning: Virtual render_block called\n" << endl;
                };

                void set_max_wait_frames(uint frames) { maxWaitFrames = frames; }
        */

        protected void Add_to_callstack(ulong address, uint idx)
        {
            ThreadCallStack.Push(new Tuple<ulong, uint>(address, idx));
        }


        void render_animation(float fadeRate)
        {
            brighten_new_active();
            maintain_active();
            darken_fading(fadeRate);

            uint lastNodeID = NodesDisplayData.LastAnimatedNode.lastVertID;
            if (!activeAnimNodeTimes.ContainsKey(lastNodeID))
            {
                NodesDisplayData.SetNodeAnimAlpha(lastNodeID, GraphicsMaths.getPulseAlpha());
                if (!FadingAnimNodesSet.Contains(lastNodeID))
                    FadingAnimNodesSet.Add(lastNodeID);
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
                        if (externBlock.Value.thread_callers == null)
                        {
                            Console.WriteLine($"Error: Extern block thread_callers was null [block 0x{blockAddr:x}]");
                        }
                        else
                        {
                            found = externBlock.Value.thread_callers.TryGetValue(tid, out calls);
                        }
                    }
                    if (found) break;
                    Thread.Sleep(200);
                    Console.WriteLine($"[rgat]Fail to find edge for thread {tid} calling extern 0x{blockAddr:x}");
                }



                newnodelist = new List<uint>();
                foreach (Tuple<uint, uint> edge in calls) //record each call by caller
                {
                    if (edge.Item1 == NodesDisplayData.LastAnimatedNode.lastVertID)
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
                uint callerIdx = callers.Find(n => n.Item1 == NodesDisplayData.LastAnimatedNode.lastVertID).Item2;
                LinkingPair = new Tuple<uint, uint>(NodesDisplayData.LastAnimatedNode.lastVertID, callerIdx);

            }
            else
            {
                //find vert in internal code
                InstructionData nextIns = nextBlock[0];
                if (nextIns.threadvertIdx.TryGetValue(internalProtoGraph.ThreadID, out uint caller))
                {
                    LinkingPair = new Tuple<uint, uint>(NodesDisplayData.LastAnimatedNode.lastVertID, caller);
                }
                else return;
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
                    Tuple<uint, uint> edge = new Tuple<uint, uint>(NodesDisplayData.LastAnimatedNode.lastVertID, nodeIdx);
                    if (internalProtoGraph.EdgeExists(edge))
                    {
                        newAnimEdgeTimes[edge] = brightTime;
                    }
                    //if it doesn't exist it may be because user is skipping code with animation slider
                }

                NodesDisplayData.LastAnimatedNode.lastVertID = nodeIdx;

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
                if (!process_live_update()) break;
            }

        }

        bool process_live_update()
        {


            //todo: eliminate need for competing with the trace handler for the lock using spsc ringbuffer
            //internalProtoGraph.animationListsRWLOCK_.lock_shared();
            ANIMATIONENTRY entry = internalProtoGraph.SavedAnimationData[updateProcessingIndex];
            //internalProtoGraph.animationListsRWLOCK_.unlock_shared();

            if (entry.entryType == eTraceUpdateType.eAnimLoopLast)
            {
                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                remove_unchained_from_animation();

                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedDone)
            {
                end_unchained(entry);
                ++updateProcessingIndex;
                return true;
            }

            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                currentUnchainedBlocks.Add(entry);
                brightTime = Anim_Constants.KEEP_BRIGHT;
            }
            else
                brightTime = 0;

            //break if block not rendered yet
            if (!get_block_nodelist(entry.blockAddr, entry.blockID, out List<uint> nodeIDList))
            {
                //expect to get an incomplete block with exception or animation attempt before static rendering
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (nodeIDList.Count > (int)entry.count))
                    return true;
                return false;
            }

            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            //also add brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
                brighten_next_block_edge(entry.blockID, entry.blockAddr, brightTime);

            ++updateProcessingIndex;
            return true;
        }


        void end_unchained(ANIMATIONENTRY entry)
        {

            currentUnchainedBlocks.Clear();
            List<InstructionData> firstChainedBlock = internalProtoGraph.ProcessData.getDisassemblyBlock(entry.blockID);
            NodesDisplayData.LastAnimatedNode.lastVertID = firstChainedBlock[^1].threadvertIdx[tid]; //should this be front()?

        }

        void process_replay_animation_updates(int optionalStepSize = 0)
        {
            if (internalProtoGraph.SavedAnimationData.Count == 0)
            {
                ReplayState = REPLAY_STATE.eEnded;
                return;
            }

            int stepSize;
            if (optionalStepSize != 0)
            {
                stepSize = optionalStepSize;
            }
            else
            {
                stepSize = (ReplayState != REPLAY_STATE.ePaused) ? clientState.AnimationStepRate : 0;
            }

            int targetAnimIndex = animationIndex + stepSize;
            if (targetAnimIndex >= internalProtoGraph.SavedAnimationData.Count)
                targetAnimIndex = internalProtoGraph.SavedAnimationData.Count - 1;


            for (; animationIndex < targetAnimIndex; ++animationIndex)
            {
                Console.WriteLine($"Anim Step {animationIndex}");
                process_replay_update();
            }

            internalProtoGraph.set_active_node(NodesDisplayData.LastAnimatedNode.lastVertID);

            if (animationIndex >= internalProtoGraph.SavedAnimationData.Count - 1)
            {
                ReplayState = REPLAY_STATE.eEnded;
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


            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                brighten_next_block_edge(entry.targetID, entry.targetAddr, brightTime);
            }

        }


        void brighten_new_active_nodes()
        {
            int actioned = 0;
            foreach (KeyValuePair<uint, int> node_time in newAnimNodeTimes)
            {
                uint nodeIdx = node_time.Key;
                int animTime = node_time.Value;


                if (nodeIdx >= NodesDisplayData.CountVerts()) break;

                NodesDisplayData.SetNodeAnimAlpha(nodeIdx, 1);//set animation brightness to full 

                //want to delay fading if in loop/unchained area, 
                if (animTime != 0)
                {
                    //Console.WriteLine($"Set node {nodeIdx} to bright for time {animTime}");
                    activeAnimNodeTimes[nodeIdx] = animTime;
                    if (FadingAnimNodesSet.Contains(nodeIdx)) FadingAnimNodesSet.Remove(nodeIdx);
                }
                else
                {
                    //Console.WriteLine($"Set node {nodeIdx} to bright for instant fade");
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

                NodesDisplayData.SetNodeAnimAlpha(nodeIdx, currentPulseAlpha);

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

            foreach (uint expiredNodeIdx in expiredNodes)
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
                //Console.WriteLine($"\tdarken_nodes: Darkening node {nodeIdx}");

                if (NodesDisplayData.ReduceNodeAnimAlpha(nodeIdx, fadeRate))
                {
                    //Console.WriteLine($"\t\t node {nodeIdx} expired - removing from fading");
                    expiredNodes.Add(nodeIdx);
                }


            }
            foreach (uint expiredNode in expiredNodes) FadingAnimNodesSet.Remove(expiredNode);


        }
        void darken_edges(float fadeRate)
        {
            List<Tuple<uint, uint>> expiredEdges = new List<Tuple<uint, uint>>();
            foreach (Tuple<uint, uint> edge in fadingAnimEdgesSet)
            {
                if (ReduceEdgeAnimAlpha(edge, fadeRate))
                    expiredEdges.Add(edge);

                //Console.WriteLine($"Darkening edge {edge}");
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

        public  void ApplyMouseDelta(Vector2 mousedelta)
        {
            //todo
        }

        void ResetAllActiveAnimatedAlphas()
        {

            foreach (uint nodeIdx in activeAnimNodeTimes.Keys)
            {
                NodesDisplayData.SetNodeAnimAlpha(nodeIdx, GlobalConfig.AnimatedFadeMinimumAlpha);
            }
            activeAnimNodeTimes.Clear();

            foreach (uint nodeIdx in FadingAnimNodesSet)
            {
                NodesDisplayData.SetNodeAnimAlpha(nodeIdx, GlobalConfig.AnimatedFadeMinimumAlpha);
            }
            FadingAnimNodesSet.Clear();

            foreach (Tuple<uint, uint> edge in activeAnimEdgeTimes.Keys)
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
            if (edge.EdgeIndex >= EdgesDisplayData.Edges_VertSizes_ArrayPositions.Count) return false;
            EdgesDisplayData.GetEdgeDrawData((int)edge.EdgeIndex, out int vertcount, out int arraypos);

            if (EdgesDisplayData.CountVerts() <= (arraypos + vertcount)) return false;

            //Console.WriteLine($"Setting edge {edgeTuple.Item1}->{edgeTuple.Item2} alpha to {alpha}");
            EdgesDisplayData.SetEdgeAnimAlpha(arraypos, vertcount, alpha);
            return true;
        }

        public bool ReduceEdgeAnimAlpha(Tuple<uint, uint> edgeTuple, float alpha)
        {
            EdgeData edge = internalProtoGraph.edgeDict[edgeTuple];
            if (edge.EdgeIndex >= EdgesDisplayData.Edges_VertSizes_ArrayPositions.Count) return false;

            EdgesDisplayData.GetEdgeDrawData((int)edge.EdgeIndex, out int vertcount, out int arraypos);
            if (EdgesDisplayData.CountVerts() <= (arraypos + vertcount)) return false;

            //Console.WriteLine($"Reducing edge {edgeTuple.Item1}{edgeTuple.Item2} alpha by {alpha}");
            EdgesDisplayData.ReduceEdgeAnimAlpha(arraypos, vertcount, alpha);
            return true;
        }

        public void UpdateGraphicBuffers(Vector2 size, GraphicsDevice _gd)
        {
            if (_outputFramebuffer == null)
            {
                InitGraphTexture(size, _gd);
            }

        }

        public void UpdatePreviewBuffers(GraphicsDevice _gd)
        {
            if (_outputTexture == null)
            {
                InitGraphTexture(new Vector2(UI_Constants.PREVIEW_PANE_WIDTH - (UI_Constants.PREVIEW_PANE_PADDING * 2), UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT), _gd);
            }
        }


        public void InitGraphTexture(Vector2 size, GraphicsDevice _gd)
        {
            if (_outputTexture != null)
            {
                if (_outputTexture.Width != size.X || _outputTexture.Height != size.Y)
                {
                    _outputFramebuffer.Dispose();
                    _outputTexture.Dispose();
                }
                else
                    return;
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

        protected bool HighlightsChanged = false;
        public void AddHighlightedNodes(List<uint> newnodeidxs, eHighlightType highlightType)
        {
            lock (textLock)
            {
                switch (highlightType)
                {
                    case eHighlightType.eExternals:
                        HighlightedSymbolNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        break;
                    case eHighlightType.eAddresses:
                        HighlightedAddressNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        break;
                    case eHighlightType.eExceptions:
                        HighlightedExceptionNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        break;
                }
                HighlightsChanged = true;
            }
        }

        public void RemoveHighlightedNodes(List<uint> nodeidxs, eHighlightType highlightType)
        {
            lock (textLock)
            {
                switch (highlightType)
                {
                    case eHighlightType.eExternals:
                        HighlightedSymbolNodes = HighlightedSymbolNodes.Except(nodeidxs).ToList();
                        break;
                    case eHighlightType.eAddresses:
                        HighlightedAddressNodes = HighlightedAddressNodes.Except(nodeidxs).ToList();
                        break;
                    case eHighlightType.eExceptions:
                        HighlightedExceptionNodes = HighlightedExceptionNodes.Except(nodeidxs).ToList();
                        break;
                }

                HighlightsChanged = true;
            }
        }

        public void AddHighlightedAddress(ulong address)
        {
            lock (textLock)
            {
                if (!HighlightedAddresses.Contains(address)) HighlightedAddresses.Add(address);
            }
        }

        public void DoHighlightAddresses()
        {
            for (int i = 0; i < HighlightedAddresses.Count; i++)
            {
                ulong address = HighlightedAddresses[i];
                List<uint> nodes = internalProtoGraph.ProcessData.GetNodesAtAddress(address, this.tid);
                lock (textLock)
                {
                    AddHighlightedNodes(nodes, eHighlightType.eAddresses);
                }
            }
        }

        public Veldrid.Texture _outputTexture = null;
        public Veldrid.Framebuffer _outputFramebuffer = null;


        public float CameraZoom = -5000;
        public float CameraFieldOfView = 0.6f;
        public float CameraClippingFar = 60000;
        public float CameraClippingNear = 1; //extern jut
        public float CameraXOffset = 0f;
        public float CameraYOffset = 0f;
        public float PlotZRotation = 0f;


        public readonly Object RenderingLock = new Object();

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

        public List<uint> HighlightedSymbolNodes = new List<uint>();
        public List<uint> HighlightedAddressNodes = new List<uint>();
        public List<ulong> HighlightedAddresses = new List<ulong>();
        public List<uint> HighlightedExceptionNodes = new List<uint>();

        bool animBuildingLoop = false;

        public bool IsAnimated { get; private set; } = false;
        public bool NeedReplotting = false; //all verts need re-plotting from scratch
                                            //bool performSymbolResolve = false;

        public string LayoutName()
        {
            switch (layout)
            {
                case graphLayouts.eTreeLayout:
                    return "Tree";
                case graphLayouts.eBarsLayout:
                    return "Bars";
                case graphLayouts.eCylinderLayout:
                    return "Cylinder";
                case graphLayouts.eForceDirected3D:
                    return "ForceDirected3D";
                default:
                    return "UnknownPlotType" + layout.ToString();
            }
        }
    }
}
