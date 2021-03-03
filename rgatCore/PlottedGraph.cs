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
using static rgatCore.VeldridGraphBuffers;

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
            pid = protoGraph.TraceData.PID;
            tid = protoGraph.ThreadID;

            //possibly conditional. diff graphs won't want heatmaps etc
            NodesDisplayData = new GraphDisplayData();
            EdgesDisplayData = new GraphDisplayData();
            HighlightsDisplayData = new GraphDisplayData();


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


        public void render_graph()
        {
            lock (RenderingLock)
            {
                render_new_blocks();
            }
        }

        //for tracking how big the graph gets
        protected void updateStats(float a, float b, float c)
        {
            //the extra work of 2xabs() happens so rarely that its worth avoiding
            //the stack allocations of a variable every call
            if (Math.Abs(a) > maxA) maxA = Math.Abs(a);
            if (Math.Abs(b) > maxB) maxB = Math.Abs(b);
        }


        //virtual int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, NodeData* node) { return INT_MAX; };

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
        //todo use this
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
            }

            //animInstructionIndex = 0;
            NodesDisplayData.LastAnimatedNode.lastVertID = 0;
            animationIndex = 0;

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

        }


        public void draw_highlight_lines()
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


        public void StepPausedAnimation(int steps)
        {
            process_replay_animation_updates(steps);
        }


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
            int endIndex = internalProtoGraph.edgeList.Count;
            int drawCount = endIndex - (int)DrawnEdgesCount;
            if (drawCount <= 0) return;
            for (int edgeIdx = DrawnEdgesCount; edgeIdx < endIndex; edgeIdx++)
            {
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (edgeNodes.Item1 >= _graphStructureLinear.Count)
                {
                    //NodeData n1 = internalProtoGraph.safe_get_node(edgeNodes.Item1);
                    //render_node(n1);
                    AddNode(edgeNodes.Item1);
                }

                if (edgeNodes.Item2 >= _graphStructureLinear.Count)
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeNodes];
                    if (e.edgeClass == eEdgeNodeType.eEdgeException)
                        NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeException;
                    AddNode(edgeNodes.Item2);

                }

                UpdateNodeLinks((int)edgeNodes.Item1, (int)edgeNodes.Item2);
                DrawnEdgesCount++;

                if (NeedReplotting || clientState.rgatIsExiting) break;
            }
        }


        public void UpdateRenderFrameVersion(ulong newVersion)
        {
            Debug.Assert(newVersion > renderFrameVersion);
            Debug.Assert(newVersion != ulong.MaxValue);
            renderFrameVersion = newVersion;
        }
        public void UpdateRenderFrameVersion()
        {
            renderFrameVersion++;
        }

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

            if (positionsArray1.Length < count)
                positionsArray1 = new float[count];
            for (var i = 0; i < count; i++)
            {
                if (positionsArray1[i] > 0 && newPositions[i] == 0)
                {
                    Console.WriteLine("bad");
                }
                positionsArray1[i] = newPositions[i];
                if (positionsArray1[i] == 0)
                    Console.WriteLine($"!----UpdateNodePositions {i} -> {newPositions[i]} ");
            }


        }

        //This is assumed to never shrink
        public void UpdateNodeVelocities(MappedResourceView<float> newVelocities, uint count)
        {
            if (velocityArray1.Length < count)
                velocityArray1 = new float[count];
            for (var i = 0; i < count; i++)
                velocityArray1[i] = newVelocities[i];
        }


        public float[] GetVelocityFloats()
        {
            //Console.WriteLine($"Getvelocity floats returning {velocityArray1.Length} floats");
            lock (RenderingLock)
            {
                return velocityArray1.ToArray();
            }
        }
        public float[] GetPositionFloats()
        {
            //Console.WriteLine($"GetPositionFloats floats returning {positionsArray1.Length} floats");
            lock (RenderingLock)
            {
                return positionsArray1.ToArray();
            }

        }
        public float[] GetNodeAttribFloats()
        {
            return nodeAttribArray1;
        }

        eGraphLayout _presetLayoutStyle = eGraphLayout.eLayoutInvalid;
        uint _presetEdgeCount;

        public float[] GetPresetPositionFloats()
        {
            if (_presetLayoutStyle != LayoutStyle || _presetEdgeCount != internalProtoGraph.get_num_edges())
                GeneratePresetPositions();
            return presetPositionsArray;
        }

        void ZeroisePreset()
        {

        }

        void GeneratePresetPositions()
        {
            _presetLayoutStyle = LayoutStyle;
            _presetEdgeCount = internalProtoGraph.get_num_edges();
            switch (LayoutStyle)
            {
                case eGraphLayout.eCylinderLayout:
                    GenerateCylinderLayout();
                    break;
                case eGraphLayout.eCircle:
                    GenerateCircleLayout();
                    break;
                case eGraphLayout.eForceDirected3D:
                    if (savedForcePositionsArray1.Length == 0)
                    {
                        InitBlankPresetLayout();
                        RandomisePositionTextures();
                    }
                    else
                    {
                        presetPositionsArray = savedForcePositionsArray1.ToArray();
                    }
                    break;
                default:
                    Console.WriteLine("Error: Tried to layout invalid preset style: " + LayoutName());
                    break;
            }
        }


        void GenerateSimpleCylinderLayout()
        {

            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();
            var textureArray = new float[textureSize * textureSize * 4];
            for (var i = 0; i < nodeCount; i++)
            {

                var phi = i * 0.125 + Math.PI;


                // modify to change the radius and position of a circle
                float y = i * -15;
                float z = 500 * (float)Math.Sin(phi);
                float x = 500 * (float)Math.Cos(phi);

                textureArray[i * 4] = x;
                textureArray[i * 4 + 1] = y;
                textureArray[i * 4 + 2] = z;
                textureArray[i * 4 + 3] = 1f;

            }

            for (var i = nodeCount * 4; i < textureArray.Length; i++)
            {

                // fill unused RGBA slots with -1
                textureArray[i] = -1;

            }
            presetPositionsArray = textureArray;
        }

        void GenerateCylinderLayout()
        {

            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();
            var textureArray = new float[textureSize * textureSize * 4];
            float a = 0;
            float b = 0;
            float radius = 500f;

            textureArray[0] = radius;
            textureArray[1] = 0;
            textureArray[2] = 0;
            textureArray[3] = 1;

            float B_BETWEEN_BLOCKNODES = 5f;
            float JUMPA = 3f;
            float JUMPB = 10f;
            float JUMPA_CLASH = 1.5f;
            float CALLA = 5f;
            float CALLB = 10f;
            float CALLB_CLASH = 12;

            Dictionary<Tuple<float, float>, bool> usedCoords = new Dictionary<Tuple<float, float>, bool>();

            for (uint i = 1; i < nodeCount; i++)
            {
                NodeData n = internalProtoGraph.safe_get_node(i);
                NodeData firstParent = internalProtoGraph.safe_get_node(n.parentIdx);

                if (n.IsExternal)
                {
                    a = a + (-0.5f) - 1f * firstParent.childexterns;
                    b = b + (0.5f) + 0.7f * firstParent.childexterns;
                }
                else
                {
                    switch (firstParent.VertType())
                    {
                        case eEdgeNodeType.eNodeNonFlow:
                            b += B_BETWEEN_BLOCKNODES;
                            break;

                        case eEdgeNodeType.eNodeJump:

                            if (firstParent.conditional != eConditionalType.NOTCONDITIONAL && n.address == firstParent.ins.condDropAddress)
                            {
                                b += B_BETWEEN_BLOCKNODES;
                                break;
                            }
                            a += JUMPA;
                            b += JUMPB;
                            while (usedCoords.ContainsKey(new Tuple<float, float>(a, b))) { a += JUMPA_CLASH; }
                            break;


                        case eEdgeNodeType.eNodeException:
                            a += JUMPA;
                            b += JUMPB;
                            while (usedCoords.ContainsKey(new Tuple<float, float>(a, b))) { a += JUMPA_CLASH; }
                            break;

                        case eEdgeNodeType.eNodeCall:
                            a += CALLA;
                            b += CALLB;
                            bool clash = false;
                            while (usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                            {
                                b += CALLB_CLASH;
                            }
                            break;

                        case eEdgeNodeType.eNodeReturn:
                        case eEdgeNodeType.eNodeExternal:

                            a += 4;
                            b += 4;
                            break;

                    }
                }


                float x = radius * (float)Math.Cos(a * Math.PI);
                float y = -1 * CYLINDER_PIXELS_PER_B * b;
                float z = radius * (float)Math.Sin(a * Math.PI);

                textureArray[i * 4] = x;
                textureArray[i * 4 + 1] = y;
                textureArray[i * 4 + 2] = z;
                textureArray[i * 4 + 3] = 1f;

                if (b > _cylinderMaxB) _cylinderMaxB = b;

            }

            for (var i = nodeCount * 4; i < textureArray.Length; i++)
            {

                // fill unused RGBA slots with -1
                textureArray[i] = -1;

            }
            presetPositionsArray = textureArray;
        }

        float CYLINDER_PIXELS_PER_B = 10f;
        void GenerateCylinderWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            int CYLINDER_PIXELS_PER_ROW = 500;
            float WF_POINTSPERLINE = 50f;
            int wireframe_loop_count = (int)Math.Ceiling((_cylinderMaxB * CYLINDER_PIXELS_PER_B) / CYLINDER_PIXELS_PER_ROW) + 1;
            float radius = 500f;

            for (int rowY = 0; rowY < wireframe_loop_count; rowY++)
            {
                int rowYcoord = -rowY * CYLINDER_PIXELS_PER_ROW;
                for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
                {
                    float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                    if (circlePoint > 1)
                        edgeIndices.Add((uint)verts.Count - 1);

                    edgeIndices.Add((uint)verts.Count);
                    GeomPositionColour gpc = new GeomPositionColour
                    {
                        Color = new WritableRgbaFloat(Color.White),
                        Position = new Vector4(radius * (float)Math.Cos(angle), (float)rowYcoord, radius * (float)Math.Sin(angle), 0)
                    };
                    verts.Add(gpc);
                }

            }
        }


        eGraphLayout _wireframeLayout = eGraphLayout.eLayoutInvalid;
        uint _wireframeEdgeCount;
        float _cylinderMaxB;

        //todo cache

        public GeomPositionColour[] GetIllustrationEdges(out List<uint> edgeIndices)
        {

            List<GeomPositionColour> resultList = new List<GeomPositionColour>();
            edgeIndices = new List<uint>();
            if (WireframeEnabled)
            {
                _presetLayoutStyle = LayoutStyle;
                _presetEdgeCount = internalProtoGraph.get_num_edges();
                switch (LayoutStyle)
                {
                    case eGraphLayout.eCylinderLayout:
                        GenerateCylinderWireframe(ref resultList, ref edgeIndices);
                        break;
                    default:
                        Console.WriteLine("Error: Tried to layout invalid wireframe style: " + LayoutName());
                        break;
                }

            }

            if (AllHighlightedNodes.Count > 0)
            {
                uint textureSize = LinearIndexTextureSize();
                List<uint> hilightnodes;
                lock (textLock)
                {
                    hilightnodes = AllHighlightedNodes.ToList();
                }
                foreach (uint node in hilightnodes)
                {
                    WritableRgbaFloat ecol = new WritableRgbaFloat(Color.Cyan);

                    edgeIndices.Add((uint)resultList.Count);
                    resultList.Add(new GeomPositionColour{
                        Position = new Vector4(0, 0, 0, 0),
                        Color = ecol
                    });

                    edgeIndices.Add((uint)resultList.Count);
                    resultList.Add(new GeomPositionColour
                    {   
                        //w = 1 => this is a position texture coord, not a space coord
                        Position = new Vector4(node % textureSize, (float)Math.Floor((float)(node / textureSize)), 0,   1),
                        Color = ecol
                    });

                }
            }

            return resultList.ToArray();
        }


        public bool WireframeEnabled => LayoutStyle == eGraphLayout.eCylinderLayout;




        //Adapted from analytics textureGenerator.js 
        void GenerateCircleLayout()
        {
            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();

            float increase = ((float)Math.PI * 2.0f) / (float)_graphStructureLinear.Count;
            float angle = 0;
            float radius = nodeCount * 4f * 2f;

            var textureArray = new float[textureSize * textureSize * 4];

            for (var i = 0; i < textureArray.Length; i += 4)
            {

                if (i < nodeCount * 4)
                {
                    // modify to change the radius and position of a circle
                    float x = radius * (float)Math.Cos(angle);
                    float y = radius * (float)Math.Sin(angle);
                    float z = 0;
                    float w = 1.0f;

                    textureArray[i] = x;
                    textureArray[i + 1] = y;
                    textureArray[i + 2] = z;
                    textureArray[i + 3] = w;

                    angle += increase;

                }
                else
                {

                    textureArray[i] = -1.0f;
                    textureArray[i + 1] = -1.0f;
                    textureArray[i + 2] = -1.0f;
                    textureArray[i + 3] = -1.0f;

                }

            }
            presetPositionsArray = textureArray;
        }


        public void IncreaseTemperature()
        {
            temperature += _graphStructureLinear.Count / 2;
        }
        public void IncreaseTemperature(float temp)
        {
            temperature = temp;
        }


        void EnlargeRAMDataBuffers(uint size)
        {
            float[] newVelocityArr1 = new float[size];
            float[] newPositionsArr1 = new float[size];
            float[] newAttsArr1 = new float[size];
            float[] newPresetsArray = new float[size];

            int endLength = 0;
            if (velocityArray1 != null)
            {
                endLength = velocityArray1.Length;
                for (var i = 0; i < endLength; i++)
                {
                    newVelocityArr1[i] = velocityArray1[i];
                    newPositionsArr1[i] = positionsArray1[i];
                    newAttsArr1[i] = nodeAttribArray1[i];
                    newPresetsArray[i] = presetPositionsArray[i];
                }
            }

            for (var i = endLength; i < size; i++)
            {
                newVelocityArr1[i] = -1;
                newPositionsArr1[i] = -1;
                newAttsArr1[i] = -1;
                newPresetsArray[i] = 0;
            }


            positionsArray1 = newPositionsArr1;
            velocityArray1 = newVelocityArr1;
            nodeAttribArray1 = newAttsArr1;
            presetPositionsArray = newPresetsArray;

        }



        unsafe void AddNode(uint nodeIdx)
        {
            Debug.Assert(nodeIdx == _graphStructureLinear.Count);

            var bounds = 1000;
            var bounds_half = bounds / 2;

            int oldVelocityArraySize = (velocityArray1 != null) ? velocityArray1.Length * sizeof(float) : 0;
            uint futureCount = (uint)_graphStructureLinear.Count + 1;
            var bufferWidth = indexTextureSize((int)futureCount);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            var bufferSize = bufferFloatCount * sizeof(float);

            if (bufferSize > oldVelocityArraySize)
            {
                Console.WriteLine($"Recreating graph RAM buffers as {bufferSize} > {oldVelocityArraySize}");
                EnlargeRAMDataBuffers(bufferFloatCount);
            }

            //possible todo here - shift Y down as the index increases
            Random rnd = new Random();
            float[] nodePositionEntry = {
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half, 1 };

            uint currentOffset = (futureCount - 1) * 4;

            positionsArray1[currentOffset] = nodePositionEntry[0];
            positionsArray1[currentOffset + 1] = nodePositionEntry[1];
            positionsArray1[currentOffset + 2] = nodePositionEntry[2];
            positionsArray1[currentOffset + 3] = nodePositionEntry[3];

            presetPositionsArray[currentOffset] = 0;
            presetPositionsArray[currentOffset + 1] = 0;
            presetPositionsArray[currentOffset + 2] = 0;
            presetPositionsArray[currentOffset + 3] = 0;

            velocityArray1[currentOffset] = 0;
            velocityArray1[currentOffset + 1] = 0;
            velocityArray1[currentOffset + 2] = 0;
            velocityArray1[currentOffset + 3] = 1;


            nodeAttribArray1[currentOffset] = 200f;
            nodeAttribArray1[currentOffset + 1] = 1f;// 0.5f;
            nodeAttribArray1[currentOffset + 2] = 0;
            nodeAttribArray1[currentOffset + 3] = 0;


            List<int> connectedNodeIDs = new List<int>();
            lock (animationLock)
            {
                _graphStructureLinear.Add(connectedNodeIDs);
                _graphStructureBalanced.Add(connectedNodeIDs);
            }
        }


        public unsafe int[] GetNodeNeighbourDataOffsets()
        {
            List<List<int>> targetArray = null;
            lock (animationLock)
            {
                targetArray = _graphStructureBalanced.ToList(); //eg: [[1,3],[0,2],[1],[0]]
            }
            var textureSize = indexTextureSize(targetArray.Count);

            int[] sourceData = new int[textureSize * textureSize * 2];
            int current = 0;

            for (var srcNodeIndex = 0; srcNodeIndex < targetArray.Count; srcNodeIndex++)
            {

                //keep track of the beginning of the array for this node
                int start = current;

                foreach (int destNodeID in targetArray[srcNodeIndex])
                {
                    current++;
                }

                //write the two sets of texture indices out.  We'll fill up an entire pixel on each pass

                if (start != current)
                {
                    sourceData[srcNodeIndex * 2] = start;
                    sourceData[srcNodeIndex * 2 + 1] = current;
                }
                else
                {

                    sourceData[srcNodeIndex * 2] = -1;
                    sourceData[srcNodeIndex * 2 + 1] = -1;
                }

            }

            for (var i = targetArray.Count * 2; i < sourceData.Length; i++)
            {

                // fill unused RGBA slots with -1
                sourceData[i] = -1;
            }
            //Console.WriteLine($"GetEdgeIndicesInts Returning indexes with {targetArray.Count} filled and {sourceData.Length - targetArray.Count} empty");
            return sourceData;
        }

        public int DrawnEdgesCount = 0;
        void UpdateNodeLinks(int srcNodeIdx, int destNodeIdx)
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


        public void InitBlankPresetLayout()
        {
            var bufferWidth = indexTextureSize(_graphStructureLinear.Count);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            presetPositionsArray = new float[bufferFloatCount];

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

        void RandomisePositionTextures()
        {
            var bounds = 1000;
            var bounds_half = bounds / 2;
            Random rnd = new Random();
            for (var i = 0; i < presetPositionsArray.Length; i += 4)
            {
                if (i < _graphStructureLinear.Count * 4)
                {
                    positionsArray1[i] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positionsArray1[i + 1] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positionsArray1[i + 2] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positionsArray1[i + 3] = 1;
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
        public uint NestedIndexTextureSize() { return indexTextureSize(_graphStructureBalanced.Count); }

        public uint EdgeTextureWidth() { return dataTextureSize(countDataArrayItems(_graphStructureBalanced)); }
        public uint EdgeVertsTextureWidth() { return dataTextureSize(internalProtoGraph.edgeList.Count); }


        public WritableRgbaFloat GetNodeColor(int nodeIndex, eRenderingMode renderingMode)
        {
            if (nodeIndex >= internalProtoGraph.NodeList.Count)
            {
                return new WritableRgbaFloat(0, 0, 0, 0);
            }

            NodeData n = internalProtoGraph.NodeList[nodeIndex];

            if (n.Highlighted)
            {
                return new WritableRgbaFloat(0, 1, 1, 1f);
            }
            switch (renderingMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    return graphColours[(int)n.VertType()];
                case eRenderingMode.eHeatmap:
                    return new WritableRgbaFloat(1, 0, 0, 1);
                case eRenderingMode.eConditionals:
                    {
                        if (n.conditional == eConditionalType.NOTCONDITIONAL)
                            return new WritableRgbaFloat(0, 0, 0, 0.7f);
                        if (n.conditional == eConditionalType.CONDCOMPLETE)
                            return new WritableRgbaFloat(1, 1, 1, .7f);
                        if (((int)n.conditional & (int)eConditionalType.CONDTAKEN) != 0)
                            return new WritableRgbaFloat(0, 1, 0, 0.7f);
                        if (((int)n.conditional & (int)eConditionalType.CONDFELLTHROUGH) != 0)
                            return new WritableRgbaFloat(1, 0, 0, 0.7f);
                        return new WritableRgbaFloat(Color.Yellow);
                    }
                default:
                    return graphColours[(int)n.VertType()];
            }
        }


        public WritableRgbaFloat GetEdgeColor(Tuple<uint, uint> edge, eRenderingMode renderingMode)
        {

            EdgeData e = internalProtoGraph.edgeDict[edge]; //todo - thread safe dict access or caching
            switch (renderingMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    return graphColours[(int)e.edgeClass];
                case eRenderingMode.eHeatmap:
                    {
                        switch (e.heatRank)
                        {
                            case 0:
                                return new WritableRgbaFloat(0, 0, 1, 0.7f);
                            case 1:
                                return new WritableRgbaFloat(0.1f, 0, 0.9f, 1);
                            case 2:
                                return new WritableRgbaFloat(0.3f, 0, 0.7f, 1);
                            case 3:
                                return new WritableRgbaFloat(0.5f, 0, 0.5f, 1);
                            case 4:
                                return new WritableRgbaFloat(0.3f, 0, 0.7f, 1);
                            case 5:
                                return new WritableRgbaFloat(0.9f, 0, 0.1f, 1);
                            case 6:
                                return new WritableRgbaFloat(1, 0, 1, 1);
                            case 7:
                                return new WritableRgbaFloat(1, 0.3f, 1, 1);
                            case 8:
                                return new WritableRgbaFloat(1, 0.7f, 1, 1);
                            case 9:
                                return new WritableRgbaFloat(1, 1, 1, 1);
                            default:
                                return new WritableRgbaFloat(Color.Green);
                        }
                    }
                case eRenderingMode.eConditionals:
                    return new WritableRgbaFloat(0.8f, 0.8f, 0.8f, 1);
                default:
                    return graphColours[(int)e.edgeClass];
            }
        }


        Tuple<string, Color> createNodeLabel(int index, eRenderingMode renderingMode, bool forceNew = false)
        {
            NodeData n = internalProtoGraph.NodeList[index];
            if (n.label == null || n.newArgsRecorded || forceNew)
            {
                if (n.IsExternal)
                {
                    n.newArgsRecorded = false;
                    n.label = GenerateSymbolLabel(n);
                }
                else
                {
                    n.label = $"{index}: {n.ins.ins_text}";
                    if (renderingMode == eRenderingMode.eHeatmap)
                    {
                        n.label += $" [x{n.executionCount}] ";
                        if (n.OutgoingNeighboursSet.Count > 1)
                        {
                            n.label += "<";
                            foreach (int nidx in n.OutgoingNeighboursSet)
                            {
                                EdgeData e = internalProtoGraph.edgeDict[new Tuple<uint, uint>(n.index, (uint)nidx)];
                                n.label += $" {nidx}:{e.executionCount}, ";
                            }
                            n.label += ">";
                        }
                    }
                    if (n.ins.hasSymbol)
                    {
                        internalProtoGraph.ProcessData.GetSymbol(n.GlobalModuleID, n.address, out string sym);
                        n.label += $" [{sym}]";
                    }
                }
            }

            Color color = n.IsExternal ? Color.SpringGreen : Color.White;
            return new Tuple<string, Color>(n.label, color);
        }

        eRenderingMode lastRenderingMode = eRenderingMode.eStandardControlFlow;
        //important todo - cacheing!  once the result is good
        public TextureOffsetColour[] GetMaingraphNodeVerts(
            out List<uint> nodeIndices,
            out TextureOffsetColour[] nodePickingColors,
            out List<Tuple<string, Color>> captions,
            eRenderingMode renderingMode)
        {
            bool createNewLabels = false;
            if (renderingMode != lastRenderingMode)
            {
                createNewLabels = true;
                lastRenderingMode = renderingMode;
            }

            uint textureSize = LinearIndexTextureSize();
            TextureOffsetColour[] NodeVerts = new TextureOffsetColour[textureSize * textureSize];

            nodePickingColors = new TextureOffsetColour[textureSize * textureSize];
            captions = new List<Tuple<string, Color>>();

            nodeIndices = new List<uint>();
            int nodeCount = RenderedNodeCount();
            for (uint y = 0; y < textureSize; y++)
            {
                for (uint x = 0; x < textureSize; x++)
                {
                    var index = y * textureSize + x;
                    if (index >= nodeCount) return NodeVerts;

                    nodeIndices.Add(index);

                    NodeVerts[index] = new TextureOffsetColour
                    {
                        TexPosition = new Vector2(x, y),
                        Color = GetNodeColor((int)index, renderingMode)
                    };

                    nodePickingColors[index] = new TextureOffsetColour
                    {
                        TexPosition = new Vector2(x, y),
                        Color = new WritableRgbaFloat(index, 0, 0, 1)
                    };
                    //if (index == 120)
                    captions.Add(createNodeLabel((int)index, renderingMode, createNewLabels));
                    //else
                    //    captions.Add(new Tuple<string, Color>("", Color.Black));

                }
            }
            return NodeVerts;
        }


        public TextureOffsetColour[] GetPreviewgraphNodeVerts(out List<uint> nodeIndices, eRenderingMode renderingMode)
        {
            uint textureSize = LinearIndexTextureSize();
            TextureOffsetColour[] NodeVerts = new TextureOffsetColour[textureSize * textureSize];

            nodeIndices = new List<uint>();
            int nodeCount = RenderedNodeCount();
            for (uint y = 0; y < textureSize; y++)
            {
                for (uint x = 0; x < textureSize; x++)
                {
                    var index = y * textureSize + x;
                    if (index >= nodeCount) return NodeVerts;

                    nodeIndices.Add(index);

                    NodeVerts[index] = new TextureOffsetColour
                    {
                        TexPosition = new Vector2(x, y),
                        Color = GetNodeColor((int)index, renderingMode)
                    };
                }
            }
            return NodeVerts;
        }


        string GenerateSymbolLabel(NodeData n, int specificCallIndex = -1)
        {
            string symbolText = "";
            bool found = false;
            if (internalProtoGraph.ProcessData.GetSymbol(n.GlobalModuleID, n.address, out symbolText))
            {
                found = true;
            }
            else
            {
                //search back from the instruction to try and find symbol of a function it may (or may not) be part of
                ulong searchLimit = Math.Min(GlobalConfig.SymbolSearchDistance, n.address);
                for (ulong symOffset = 0; symOffset < searchLimit; symOffset++)
                {
                    if (internalProtoGraph.ProcessData.GetSymbol(n.GlobalModuleID, n.address - symOffset, out symbolText))
                    {
                        symbolText += $"+0x{symOffset}";
                        found = true;
                        break;
                    }
                }
            }

            if (!found) return $"[No Symbol]0x{n.address:x}";


            if (n.callRecordsIndexs.Count == 0)
            {
                return $"{symbolText}()";
            }

            EXTERNCALLDATA lastCall;
            if (specificCallIndex == -1)
            {
                lastCall = internalProtoGraph.ExternCallRecords[(int)n.callRecordsIndexs[^1]];
            }
            else
            {
                Debug.Assert(n.callRecordsIndexs.Count > specificCallIndex);
                lastCall = internalProtoGraph.ExternCallRecords[(int)n.callRecordsIndexs[specificCallIndex]];
            }

            string argstring = "";
            for (var i = 0; i < lastCall.argList.Count; i++)
            {
                Tuple<int, string> arg = lastCall.argList[i];
                argstring += $"{arg.Item1}:{arg.Item2}";
                if (i < (lastCall.argList.Count - 1)) argstring += ", ";
            }

            if (n.callRecordsIndexs.Count == 1)
            {
                return $"{symbolText}({argstring})";
            }
            else
            {
                return $"{symbolText}({argstring}) +{n.callRecordsIndexs.Count - 1} saved";
            }
        }


        public TextureOffsetColour[] GetEdgeLineVerts(eRenderingMode renderingMode,
            out List<uint> edgeIndices, out int vertCount, out int graphDrawnEdgeCount)
        {
            uint evTexWidth = EdgeVertsTextureWidth();
            TextureOffsetColour[] EdgeLineVerts = new TextureOffsetColour[evTexWidth * evTexWidth * 16];

            vertCount = 0;
            edgeIndices = new List<uint>();
            uint textureSize = LinearIndexTextureSize();

            var edgeList = internalProtoGraph.GetEdgelistCopy();

            foreach (Tuple<uint, uint> edge in edgeList)
            {
                int srcNodeIdx = (int)edge.Item1;
                int destNodeIdx = (int)edge.Item2;
                WritableRgbaFloat ecol = GetEdgeColor(edge, renderingMode);

                EdgeLineVerts[vertCount] =
                        new TextureOffsetColour
                        {
                            TexPosition = new Vector2(srcNodeIdx % textureSize, (float)Math.Floor((float)(srcNodeIdx / textureSize))),
                            Color = ecol
                        };
                edgeIndices.Add((uint)vertCount); vertCount++;

                EdgeLineVerts[vertCount] =
                    new TextureOffsetColour
                    {
                        TexPosition = new Vector2(destNodeIdx % textureSize, (float)Math.Floor((float)(destNodeIdx / textureSize))),
                        Color = ecol
                    };
                edgeIndices.Add((uint)vertCount); vertCount++;

            }
            graphDrawnEdgeCount = DrawnEdgesCount;
            return EdgeLineVerts;
        }

        public TextureOffsetColour[] getHighlightLineVerts(out List<uint> edgeIndices, out int vertCount)
        {
            List<TextureOffsetColour> HighlightLineVerts = new List<TextureOffsetColour>();

            vertCount = 0;
            edgeIndices = new List<uint>();
            uint textureSize = LinearIndexTextureSize();
            List<uint> hilightnodes;
            lock (textLock)
            {
                hilightnodes = AllHighlightedNodes.ToList();
            }
            foreach (uint node in hilightnodes)
            {
                WritableRgbaFloat ecol = new WritableRgbaFloat(Color.Cyan);

                HighlightLineVerts.Add(new TextureOffsetColour
                {
                    TexPosition = new Vector2(0, 0),
                    Color = ecol
                });
                edgeIndices.Add((uint)HighlightLineVerts.Count); ;

                HighlightLineVerts.Add(new TextureOffsetColour
                {
                    TexPosition = new Vector2(node % textureSize, (float)Math.Floor((float)(node / textureSize))),
                    Color = ecol
                });
                edgeIndices.Add((uint)HighlightLineVerts.Count);

            }
            vertCount = HighlightLineVerts.Count;
            return HighlightLineVerts.ToArray();
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



        protected void Add_to_callstack(ulong address, uint idx)
        {
            ThreadCallStack.Push(new Tuple<ulong, uint>(address, idx));
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
                    Console.WriteLine($"[rgat]get_block_nodelist() Fail to find edge for thread {tid} calling extern 0x{blockAddr:x}");
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
                AddPulseActiveNode(LinkingPair.Item1);
                AddPulseActiveNode(LinkingPair.Item2);
            }


        }

        void brighten_node_list(ANIMATIONENTRY entry, int brightTime, List<uint> nodeIDList)
        {
            ulong listOffset = 0;

            foreach (uint nodeIdx in nodeIDList)
            {
                //Console.WriteLine($"BNL node {nodeIdx}");

                if (listOffset == 0 && internalProtoGraph.safe_get_node(nodeIdx).IsExternal)
                {
                    if (brightTime == Anim_Constants.KEEP_BRIGHT)
                        AddRisingExtern(nodeIdx, entry.count - 1, Anim_Constants.KEEP_BRIGHT);
                    else
                        AddRisingExtern(nodeIdx, entry.count - 1, GlobalConfig.ExternAnimDisplayFrames);
                }


                if (!(entry.entryType == eTraceUpdateType.eAnimUnchained) && listOffset == 0)
                {
                    Tuple<uint, uint> edge = new Tuple<uint, uint>(NodesDisplayData.LastAnimatedNode.lastVertID, nodeIdx);
                    if (internalProtoGraph.EdgeExists(edge))
                    {
                        AddPulseActiveNode(edge.Item1);
                    }
                    //if it doesn't exist it may be because user is skipping code with animation slider
                }

                if (brightTime == Anim_Constants.KEEP_BRIGHT)
                    AddContinuousActiveNode(nodeIdx);
                else
                    AddPulseActiveNode(nodeIdx);
                NodesDisplayData.LastAnimatedNode.lastVertID = nodeIdx;

                ++listOffset;
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (listOffset == (entry.count + 1))) break;

            }
        }


        //void draw_condition_ins_text(float zdist, PROJECTDATA* pd, GraphDisplayData* vertsdata, graphGLWidget &gltarget);
        //void draw_edge_heat_text(int zdist, PROJECTDATA* pd, graphGLWidget &gltarget);
        //void set_edge_alpha(NODEPAIR eIdx, GraphDisplayData* edgesdata, float alpha);




        void end_unchained(ANIMATIONENTRY entry)
        {

            currentUnchainedBlocks.Clear();
            List<InstructionData> firstChainedBlock = internalProtoGraph.ProcessData.getDisassemblyBlock(entry.blockID);
            NodesDisplayData.LastAnimatedNode.lastVertID = firstChainedBlock[^1].threadvertIdx[tid]; //should this be front()?

        }


        void process_live_animation_updates()
        {
            //too many updates at a time damages interactivity
            //too few creates big backlogs which delays the animation (can still see realtime in Structure mode though)
            int updateLimit = LiveAnimationUpdatesPerFrame;
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
                Console.WriteLine("Live update: eAnimLoopLast");
                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                Console.WriteLine($"Live update: eAnimUnchainedResults. Block {entry.blockID} executed {entry.count} times");
                remove_unchained_from_animation();

                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedDone)
            {
                Console.WriteLine("Live update: eAnimUnchainedDone");
                end_unchained(entry);
                ++updateProcessingIndex;
                return true;
            }

            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                string s = "";
                if (get_block_nodelist(0, entry.blockID, out List<uint> nodeIDListFFF))
                {
                    foreach (int x in nodeIDListFFF) s += $"{x},";
                }

                Console.WriteLine($"Live update: eAnimUnchained block {entry.blockID}: " + s);
                currentUnchainedBlocks.Add(entry); //todo see if removable
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




        void process_replay_animation_updates(int optionalStepSize = 0)
        {
            if (internalProtoGraph.SavedAnimationData.Count == 0)
            {
                Console.WriteLine("Ending animation immediately - no animation data");
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
            bool verbose = true;
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
                    if (verbose) Console.WriteLine($"\tLast entry was block exec - brighten edge to block address 0x{entry.blockAddr:x} ");
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

                if (verbose) Console.WriteLine($"\tUpdate eAnimUnchainedResults block 0x{entry.blockAddr:x} ");
                return;
            }

            //all consecutive unchained areas finished, wait until animation paused appropriate frames
            if (entry.entryType == eTraceUpdateType.eAnimUnchainedDone)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimUnchainedDone");
                if (unchainedWaitFrames-- > 1) return;

                remove_unchained_from_animation();
                end_unchained(entry);
                return;
            }

            if (entry.entryType == eTraceUpdateType.eAnimLoopLast)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimLoopLast");
                if (unchainedWaitFrames-- > 1) return;

                remove_unchained_from_animation();
                currentUnchainedBlocks.Clear();
                animBuildingLoop = false;
                return;
            }



            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained || animBuildingLoop)
            {
                if (verbose) Console.WriteLine($"\tUpdate Replay eAnimUnchained/buildingloop");
                currentUnchainedBlocks.Add(entry);
                brightTime = Anim_Constants.KEEP_BRIGHT;
            }
            else
            {
                brightTime = GlobalConfig.animationLingerFrames;
            }

            if (entry.entryType == eTraceUpdateType.eAnimLoop)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimLoop");
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
                    Console.WriteLine($"[rgat] process_replay_update waiting for block 0x{entry.blockAddr:x}");
                    if (clientState.rgatIsExiting) return;
                }
            }


            //add all the nodes+edges in the block to the brightening list
            Console.WriteLine($"Brightening nodelist with {nodeIDList.Count} for time {brightTime}");
            brighten_node_list(entry, brightTime, nodeIDList);

            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimUnchained");
                brighten_next_block_edge(entry.targetID, entry.targetAddr, brightTime);
            }

        }


        /*
         Nodes that are continuously lit up due to being blocked or in a busy (unchained) loop
         These pulse
         */
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

        public void ApplyMouseDelta(Vector2 mousedelta)
        {
            //todo
        }





        public void InitPreviewTexture(Vector2 size, GraphicsDevice _gd)
        {
            if (_previewTexture != null)
            {
                if (_previewTexture.Width != size.X || _previewTexture.Height != size.Y)
                {
                    _previewFramebuffer.Dispose();
                    _previewTexture.Dispose();
                }
                else
                    return;
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

        public bool HighlightsChanged;
        public void AddHighlightedNodes(List<uint> newnodeidxs, eHighlightType highlightType)
        {
            lock (textLock)
            {
                switch (highlightType)
                {
                    case eHighlightType.eExternals:
                        HighlightedSymbolNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    case eHighlightType.eAddresses:
                        HighlightedAddressNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    case eHighlightType.eExceptions:
                        HighlightedExceptionNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    default:
                        Console.WriteLine($"Error: Unknown highlight type: {highlightType}");
                        break;
                }
                foreach (uint nidx in newnodeidxs)
                {
                    nodeAttribArray1[nidx * 4 + 0] = 400f;
                    nodeAttribArray1[nidx * 4 + 3] = 1.0f;
                    internalProtoGraph.safe_get_node(nidx).SetHighlighted(true);
                }
                HighlightsChanged = true;
            }
        }

        public long lastRenderTime;
        public bool flipflop;
        public uint RenderedEdgeCount; //todo - this is really all we need
        public uint ComputeBufferNodeCount; //this is gross and temporary

        public void RemoveHighlightedNodes(List<uint> nodeidxs, eHighlightType highlightType)
        {
            List<uint> removedNodes = new List<uint>();
            List<uint> remainingNodes = new List<uint>();
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
                AllHighlightedNodes.Clear();
                AllHighlightedNodes.AddRange(HighlightedSymbolNodes);
                AllHighlightedNodes.AddRange(HighlightedAddressNodes.Where(n => !AllHighlightedNodes.Contains(n)));
                AllHighlightedNodes.AddRange(HighlightedExceptionNodes.Where(n => !AllHighlightedNodes.Contains(n)));
                foreach (uint nidx in nodeidxs)
                {
                    if (!AllHighlightedNodes.Contains(nidx))
                    {
                        nodeAttribArray1[nidx * 4 + 0] = 200f;
                        nodeAttribArray1[nidx * 4 + 3] = 0.0f;
                    }
                    internalProtoGraph.safe_get_node(nidx).SetHighlighted(false);
                }
            }



            HighlightsChanged = true;

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

        void MakeMemoryResident(bool state)
        {
            Debug.Assert(state != _isLoadedInVRAM);
            if (state)
            {
                Console.WriteLine($"PlottedGraph Loading Graph PID{internalProtoGraph.TraceData.PID} TID{internalProtoGraph.ThreadID} into memory");
            }
            else
            {
                Console.WriteLine($"PlottedGraph Unloading Graph PID{internalProtoGraph.TraceData.PID} TID{internalProtoGraph.ThreadID} from memory");
            }
        }




        public List<uint> GetActiveNodeIDs(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes)
        {
            List<uint> res = new List<uint>();

            lock (animationLock)
            {
                pulseNodes = _PulseActiveNodes.ToList();
                _PulseActiveNodes.Clear();
                lingerNodes = _LingeringActiveNodes.ToList();
                deactivatedNodes = _DeactivatedNodes.ToArray();
                _DeactivatedNodes = Array.Empty<uint>();

            }
            return res;
        }


        public void GetActiveExternRisings(out List<Tuple<uint, string>> risingExterns, out List<Tuple<uint, string>> risingLingering)
        {
            lock (animationLock)
            {
                risingExterns = _RisingExterns.ToList();
                _RisingExterns.Clear();
                risingLingering = _RisingExternsLingering.ToList();
            }
        }




        public void AddRisingExtern(uint nodeIdx, ulong callIndex, int lingerFrames)
        {
            NodeData n = internalProtoGraph.safe_get_node(nodeIdx);
            string label = GenerateSymbolLabel(n, (int)callIndex);
            lock (animationLock)
            {
                if (lingerFrames == Anim_Constants.KEEP_BRIGHT)
                {
                    _RisingExternsLingering.Add(new Tuple<uint, string>(nodeIdx, label));
                }
                else
                {
                    Console.WriteLine($"Adding new rising: node {nodeIdx}:'{label}'");
                    _RisingExterns.Add(new Tuple<uint, string>(nodeIdx, label));
                }
            }
        }


        //this node was executed once, make it pulse on the animation
        public void AddPulseActiveNode(uint nodeIdx)
        {
            lock (animationLock)
            {
                if (!_PulseActiveNodes.Contains(nodeIdx))
                    _PulseActiveNodes.Add(nodeIdx);
            }
        }

        //this node is active in a loop or blocking, keep it lit up until deactivated
        public void AddContinuousActiveNode(uint nodeIdx)
        {
            lock (animationLock)
            {
                Console.WriteLine($"Making node {nodeIdx} lingering");
                if (!_LingeringActiveNodes.Contains(nodeIdx))
                {
                    _LingeringActiveNodes.Add(nodeIdx);
                }
            }
        }

        void RemoveContinuousActiveNode(uint nodeIdx)
        {
            Console.WriteLine($"Purgin node {nodeIdx} from lingering");
            lock (animationLock)
            {
                _LingeringActiveNodes.RemoveAll(n => n == nodeIdx);
            }
        }

        void remove_unchained_from_animation()
        {
            Console.WriteLine("Removing all lingering");
            lock (animationLock)
            {
                _DeactivatedNodes = _LingeringActiveNodes.ToArray();
                _LingeringActiveNodes.Clear();
            }
        }

        void ResetAllActiveAnimatedAlphas()
        {
            lock (animationLock)
            {
                _PulseActiveNodes.Clear();
                _LingeringActiveNodes.Clear();
                _DeactivatedNodes = Array.Empty<uint>();
            }
        }

        public string LayoutName()
        {
            switch (LayoutStyle)
            {
                case eGraphLayout.eCircle:
                    return "Circle";
                case eGraphLayout.eCylinderLayout:
                    return "Cylinder";
                case eGraphLayout.eForceDirected3D:
                    return "ForceDirected3D";
                default:
                    return "UnknownPlotType_" + LayoutStyle.ToString();
            }
        }

        public bool SetLayout(eGraphLayout newStyle)
        {
            if (newStyle == LayoutStyle) return false;
            if (LayoutStyle == eGraphLayout.eForceDirected3D && newStyle != eGraphLayout.eForceDirected3D)
            {
                savedForcePositionsArray1 = positionsArray1.ToArray();
            }
            else if (LayoutStyle != eGraphLayout.eForceDirected3D && newStyle == eGraphLayout.eForceDirected3D)
            {
                if (savedForcePositionsArray1.Length > 0)
                    presetPositionsArray = savedForcePositionsArray1;
            }
            LayoutStyle = newStyle;
            return true;
        }


        public List<uint> HighlightedSymbolNodes = new List<uint>();
        public List<uint> HighlightedAddressNodes = new List<uint>();
        public List<ulong> HighlightedAddresses = new List<ulong>();
        public List<uint> HighlightedExceptionNodes = new List<uint>();
        public List<uint> AllHighlightedNodes = new List<uint>();

        bool animBuildingLoop = false;

        public bool IsAnimated { get; private set; } = false;
        public bool NeedReplotting = false; //all verts need re-plotting from scratch
                                            //bool performSymbolResolve = false;

        public bool NodesVisible = true;
        public bool EdgesVisible = true;
        public bool TextEnabled = true;





        bool freeMe = false;

        protected Stack<Tuple<ulong, uint>> ThreadCallStack = new Stack<Tuple<ulong, uint>>();

        public ProtoGraph internalProtoGraph { get; protected set; } = null;

        protected List<ANIMATIONENTRY> currentUnchainedBlocks = new List<ANIMATIONENTRY>();
        protected List<WritableRgbaFloat> graphColours = new List<WritableRgbaFloat>();

        protected bool wireframeSupported;
        protected bool wireframeActive;
        long defaultZoom;
        public eGraphLayout LayoutStyle { get; protected set; } = eGraphLayout.eForceDirected3D;

        public float[] positionsArray1 = Array.Empty<float>();
        public float[] savedForcePositionsArray1 = Array.Empty<float>();
        public float[] velocityArray1 = Array.Empty<float>();
        public float[] nodeAttribArray1 = Array.Empty<float>();
        public float[] presetPositionsArray = Array.Empty<float>();
        public ulong renderFrameVersion;


        public Veldrid.Texture _previewTexture;
        public Veldrid.Framebuffer _previewFramebuffer;


        public float CameraZoom = -5000;
        public float CameraFieldOfView = 0.6f;
        public float CameraClippingFar = 60000;
        public float CameraClippingNear = 1; //extern jut
        public float CameraXOffset = 0f;
        public float CameraYOffset = 0f;
        public float PlotZRotation = 0f;


        public readonly Object RenderingLock = new Object();

        public uint pid { get; private set; }
        public uint tid { get; private set; }

        public int LiveAnimationUpdatesPerFrame = GlobalConfig.LiveAnimationUpdatesPerFrame;

        bool _isLoadedInVRAM = true;
        public bool MemoryResident { get { return _isLoadedInVRAM; } set { MakeMemoryResident(value); _isLoadedInVRAM = true; } }

        ulong unchainedWaitFrames = 0;
        uint maxWaitFrames = 20; //limit how long we spend 'executing' busy code in replays

        //which BB we are pointing to in the sequence list
        int animationIndex = 0;

        List<uint> _PulseActiveNodes = new List<uint>();
        List<uint> _LingeringActiveNodes = new List<uint>();
        List<Tuple<uint, string>> _RisingExterns = new List<Tuple<uint, string>>();
        List<Tuple<uint, string>> _RisingExternsLingering = new List<Tuple<uint, string>>();

        uint[] _DeactivatedNodes = Array.Empty<uint>();
        private readonly object animationLock = new object();


        //public float zoomMultiplier() { return GraphicsMaths.zoomFactor(cameraZoomlevel, scalefactors.plotSize); }


        public static rgatState clientState;

        public GraphDisplayData NodesDisplayData = null;
        //public GraphDisplayData BlocksDisplayData = null;
        public GraphDisplayData EdgesDisplayData = null;
        public GraphDisplayData HighlightsDisplayData = null;
        //public GraphDisplayData blocklines = null;
        public GraphDisplayData wireframelines = null;


        public GRAPH_SCALE scalefactors = new GRAPH_SCALE();

        public ulong vertResizeIndex = 0;
        public int userSelectedAnimPosition = -1;

        public REPLAY_STATE ReplayState = REPLAY_STATE.eEnded;
        int updateProcessingIndex = 0;
        protected float maxA = 0, maxB = 0, maxC = 0;

        int threadReferences = 0;
        bool schedule_performSymbolResolve = false;

        protected readonly Object textLock = new Object();


        /// <summary>
        /// The raw list of nodes with a one way edge they connect to
        /// This is used for drawing nodes and edges
        /// </summary>
        List<List<int>> _graphStructureLinear = new List<List<int>>();
        public int GraphNodeCount() { return internalProtoGraph.NodeList.Count; }
        public int RenderedNodeCount() { return _graphStructureLinear.Count; }

        /// <summary>
        /// The list of nodes and edges where each node connects to its partner and that node connects back
        /// This is used for the attraction velocity computation
        /// </summary>
        List<List<int>> _graphStructureBalanced = new List<List<int>>();
        public float temperature = 100f;

    }
}
