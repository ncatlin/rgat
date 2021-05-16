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

            savedForcePositions[eGraphLayout.eForceDirected3DNodes] = Array.Empty<float>();
            savedForcePositions[eGraphLayout.eForceDirected3DBlocks] = Array.Empty<float>();

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
        uint _lastAnimatedVert;

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
            _lastAnimatedVert = 0;
            animationIndex = 0;

            unchainedWaitFrames = 0;
            currentUnchainedBlocks.Clear();
            animBuildingLoop = false;
            IsAnimated = false;

            ReplayState = REPLAY_STATE.eStopped;
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

        public bool RenderingComplete() => DrawnEdgesCount >= internalProtoGraph.edgeList.Count;

        protected void render_new_blocks()
        {
            int endIndex = internalProtoGraph.edgeList.Count;
            int drawCount = endIndex - (int)DrawnEdgesCount;
            if (drawCount <= 0) return;
            int dbglimit = 9999;
            if (DrawnEdgesCount > dbglimit) return;
            for (int edgeIdx = DrawnEdgesCount; edgeIdx < endIndex; edgeIdx++)
            {
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (edgeNodes.Item1 >= _graphStructureLinear.Count)
                {
                    AddNode(edgeNodes.Item1);
                }

                if (edgeNodes.Item2 >= _graphStructureLinear.Count)
                {
                    EdgeData e = internalProtoGraph.edgeDict[edgeNodes];
                    //if (e.edgeClass == eEdgeNodeType.eEdgeException)
                    //    NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeException;
                    AddNode(edgeNodes.Item2, e);

                }

                UpdateNodeLinks((int)edgeNodes.Item1, (int)edgeNodes.Item2);
                DrawnEdgesCount++;

                if (NeedReplotting || clientState.rgatIsExiting) break;

                if (DrawnEdgesCount > dbglimit) return;
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


        float GetAttractionForce(EdgeData edge)
        {
            switch (edge.edgeClass)
            {
                case eEdgeNodeType.eEdgeNew:
                    if (edge.sourceNodeType == eEdgeNodeType.eNodeJump)
                        return 0.4f;
                    else
                        return 1f;
                case eEdgeNodeType.eEdgeLib:
                    return 1f;
                case eEdgeNodeType.eEdgeCall:
                    return 0.4f;
                case eEdgeNodeType.eEdgeOld:
                    return 0.3f;
                case eEdgeNodeType.eEdgeReturn:
                    return 0.2f;
                case eEdgeNodeType.eEdgeException:
                    return 2f;
                default:
                    Console.WriteLine($"Unhandled edgetype {edge.edgeClass} with edge {edge.EdgeIndex}");
                    return 1f;
            }

            return 1f;
        }


        public void UpdateNodePositions(MappedResourceView<float> newPositions)
        {
            lock (RenderingLock)
            {
                int floatCount = _computeBufferNodeCount * 4; //xyzw
                if (positionsArray1.Length < floatCount)
                    positionsArray1 = new float[floatCount];

                for (var i = 0; i < floatCount; i++)
                {
                    positionsArray1[i] = newPositions[i];
                }
            }

        }

        //This is assumed to never shrink
        public void UpdateNodeVelocities(MappedResourceView<float> newVelocities, uint count)
        {
            lock (this.RenderingLock)
            {
                if (velocityArray1.Length < count)
                    velocityArray1 = new float[count];
                for (var i = 0; i < count; i++)
                    velocityArray1[i] = newVelocities[i];
            }
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

        public float[] GetPresetPositionFloats(out bool hasPresetNodes)
        {
            if (_presetLayoutStyle != LayoutStyle || _presetEdgeCount != internalProtoGraph.get_num_edges())
                hasPresetNodes = GeneratePresetPositions();
            else
                hasPresetNodes = false;

            return presetPositionsArray;
        }



        void ZeroisePreset()
        {

        }

        //returns true if there are actually preset nodes to return to, false if a blank preset
        bool GeneratePresetPositions()
        {
            _presetLayoutStyle = LayoutStyle;
            _presetEdgeCount = internalProtoGraph.get_num_edges();
            switch (LayoutStyle)
            {
                case eGraphLayout.eCylinderLayout:
                    GenerateCylinderLayout();
                    return true;

                case eGraphLayout.eCircle:
                    GenerateCircleLayout();
                    return true;

                default:
                    if (LayoutIsForceDirected(LayoutStyle))
                    {
                        if (savedForcePositions[LayoutStyle].Length == 0)
                        {
                            InitBlankPresetLayout();
                            RandomisePositionTextures();
                            return false;
                        }
                        else
                        {
                            presetPositionsArray = savedForcePositions[LayoutStyle].ToArray();
                            return true;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error: Tried to layout invalid preset style: " + LayoutName());
                        return false;
                    }
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
                float z = CYLINDER_RADIUS * (float)Math.Sin(phi);
                float x = CYLINDER_RADIUS * (float)Math.Cos(phi);

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
            float radius = CYLINDER_RADIUS;

            textureArray[0] = radius;
            textureArray[1] = 0;
            textureArray[2] = 0;
            textureArray[3] = 1;

            float B_BETWEEN_BLOCKNODES = 5f;
            float JUMPA = 3f;
            float JUMPB = 10f;
            float A_CLASH = 1.5f;
            float CALLA = 8f;
            float CALLB = 3f;
            float B_CLASH = 12;

            List<Tuple<Tuple<float, float>, ulong>> callStack = new List<Tuple<Tuple<float, float>, ulong>>();
            Dictionary<Tuple<float, float>, bool> usedCoords = new Dictionary<Tuple<float, float>, bool>();
            float callCeiling = 0f;

            for (uint i = 1; i < nodeCount; i++)
            {
                NodeData n = internalProtoGraph.safe_get_node(i);
                NodeData firstParent = internalProtoGraph.safe_get_node(n.parentIdx);

                if (n.IsExternal)
                {
                    //todo - test multiple extern calls from same node
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
                            break;


                        case eEdgeNodeType.eNodeException:
                            a += JUMPA;
                            b += JUMPB;
                            break;

                        case eEdgeNodeType.eNodeCall:
                            a += CALLA;
                            if (b < callCeiling) b = callCeiling;
                            b += CALLB;
                            break;

                        case eEdgeNodeType.eNodeReturn:
                        case eEdgeNodeType.eNodeExternal: //treat all externs as if they end in a return

                            Tuple<float, float> callerPos = null;
                            for (var stackI = callStack.Count - 1; stackI >= 0; stackI--)
                            {
                                if (callStack[stackI].Item2 == n.address)
                                {
                                    callerPos = callStack[stackI].Item1;
                                    callStack.RemoveRange(stackI, callStack.Count - stackI);
                                    break;
                                }
                            }
                            if (callerPos != null)
                            {
                                a = callerPos.Item1;
                                b = callerPos.Item2 + 10f;
                            }
                            else
                            {
                                a += 4;
                                b += 4;
                            }
                            break;

                    }
                }

                //not great overlap prevention, looks for exact coord clashes
                while (usedCoords.ContainsKey(new Tuple<float, float>(a, b))) { a += A_CLASH; b += B_CLASH; }
                usedCoords.Add(new Tuple<float, float>(a, b), true);

                //record return address
                if (n.VertType() == eEdgeNodeType.eNodeCall)
                {
                    callStack.Add(new Tuple<Tuple<float, float>, ulong>(new Tuple<float, float>(a, b), n.address + (ulong)n.ins.numbytes));
                }

                //if returning from a function, limit drawing any new functions to below this one
                if (n.VertType() == eEdgeNodeType.eNodeReturn)
                {
                    callCeiling = b + 8;
                }

                //used to work out how far down to draw the wireframe
                if (b > _lowestWireframeLoop) _lowestWireframeLoop = b;

                double aPix = -1 * a * CYLINDER_PIXELS_PER_A;
                float x = (float)(radius * Math.Cos((aPix * Math.PI) / radius));
                float y = -1 * CYLINDER_PIXELS_PER_B * b;
                float z = (float)(radius * Math.Sin((aPix * Math.PI) / radius));

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

        float CYLINDER_RADIUS = 5000f;
        float CYLINDER_PIXELS_PER_B = 10f;
        float CYLINDER_PIXELS_PER_A = 60f;
        void GenerateCylinderWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            int CYLINDER_PIXELS_PER_ROW = 500;
            float WF_POINTSPERLINE = 50f;
            int wireframe_loop_count = (int)Math.Ceiling((_lowestWireframeLoop * CYLINDER_PIXELS_PER_B) / CYLINDER_PIXELS_PER_ROW) + 1;
            float radius = CYLINDER_RADIUS;

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



        float _lowestWireframeLoop;
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
                CreateHighlightEdges(edgeIndices, resultList);
            }

            if ((IsAnimated || !internalProtoGraph.Terminated) && _liveNodeEdgeEnabled)
            { 
                CreateLiveNodeEdge(edgeIndices, resultList);
            }
            

            return resultList.ToArray();
        }

        void CreateHighlightEdges(List<uint> edgeIndices, List<GeomPositionColour> resultList)
        {
            List<uint> highlightNodes;

            lock (textLock)
            {
                highlightNodes = AllHighlightedNodes.ToList();
            }
            uint textureSize = LinearIndexTextureSize();
            WritableRgbaFloat defaultColour = new WritableRgbaFloat(Color.Cyan);
            foreach (uint node in highlightNodes)
            {
                WritableRgbaFloat edgeColour;
                if (_customHighlightColours.Count > 0)
                {
                    Vector4? customColour = GetCustomHighlightColour((int)node);
                    if (customColour != null)
                        edgeColour = new WritableRgbaFloat(customColour.Value);
                    else
                        edgeColour = defaultColour;
                }   
                else
                {
                    edgeColour = defaultColour;
                }

                edgeIndices.Add((uint)resultList.Count);
                resultList.Add(new GeomPositionColour
                {
                    Position = new Vector4(0, 0, 0, 0), //better ideas??
                    Color = edgeColour
                });

                edgeIndices.Add((uint)resultList.Count);
                resultList.Add(new GeomPositionColour
                {
                    //w = 1 => this is a position texture coord, not a space coord
                    Position = new Vector4(node % textureSize, (float)Math.Floor((float)(node / textureSize)), 0, 1),
                    Color = edgeColour
                });

            }
        }

        void CreateLiveNodeEdge(List<uint> edgeIndices, List<GeomPositionColour> resultList)
        {
            uint node = _lastAnimatedVert;
            if (internalProtoGraph.HasRecentStep)
            {
                var addrnodes = internalProtoGraph.ProcessData.GetNodesAtAddress(internalProtoGraph.RecentStepAddr, internalProtoGraph.ThreadID);
                if (addrnodes.Count > 0)
                    node = addrnodes[^1];
            }

            lock (animationLock)
            {
                if (_LingeringActiveNodes.Count > 0)
                {
                    node = _LingeringActiveNodes[new Random().Next(0, _LingeringActiveNodes.Count)];
                }
                else
                {
                    if (_PulseActiveNodes.Count > 0)
                    {
                        node = _PulseActiveNodes[new Random().Next(0, _PulseActiveNodes.Count)];
                    }
                }

            }

            uint textureSize = LinearIndexTextureSize();
            WritableRgbaFloat ecol = new WritableRgbaFloat(Color.Red);

            edgeIndices.Add((uint)resultList.Count);
            resultList.Add(new GeomPositionColour
            {
                Position = new Vector4(0, 0, 0, 0),
                Color = ecol
            });

            edgeIndices.Add((uint)resultList.Count);
            resultList.Add(new GeomPositionColour
            {
                //w = 1 => this is a position texture coord, not a space coord
                Position = new Vector4(node % textureSize, (float)Math.Floor((float)(node / textureSize)), 0, 1),
                Color = ecol
            });
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
                newPresetsArray[i] = -1;
            }


            positionsArray1 = newPositionsArr1;
            velocityArray1 = newVelocityArr1;
            nodeAttribArray1 = newAttsArr1;
            presetPositionsArray = newPresetsArray;

        }



        unsafe void AddNode(uint nodeIdx, EdgeData edge = null)
        {
            Debug.Assert(nodeIdx == _graphStructureLinear.Count);

            var bounds = 1000;
            var bounds_half = bounds / 2;

            int oldVelocityArraySize = (velocityArray1 != null) ? velocityArray1.Length * sizeof(float) : 0;
            uint futureCount = (uint)_graphStructureLinear.Count + 1;
            var bufferWidth = indexTextureSize((int)futureCount);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            var bufferSize = bufferFloatCount * sizeof(float);

            uint currentOffset = (futureCount - 1) * 4;

            if (bufferSize > oldVelocityArraySize || currentOffset >= oldVelocityArraySize) //todo this is bad
            {
                uint newSize = Math.Max(currentOffset + 4, bufferFloatCount);
                Console.WriteLine($"Recreating graph RAM buffers as {newSize} > {oldVelocityArraySize}");
                EnlargeRAMDataBuffers(newSize);
            }

            //possible todo here - shift Y down as the index increases
            Random rnd = new Random();
            float[] nodePositionEntry = {
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half, 1 };


            positionsArray1[currentOffset] = nodePositionEntry[0];      //X
            positionsArray1[currentOffset + 1] = nodePositionEntry[1];  //Y
            positionsArray1[currentOffset + 2] = nodePositionEntry[2];  //Z
            positionsArray1[currentOffset + 3] = nodePositionEntry[3];  //type of position (none, preset, force directed)

            presetPositionsArray[currentOffset] = 0;      //X
            presetPositionsArray[currentOffset + 1] = 0;  //Y
            presetPositionsArray[currentOffset + 2] = 0;  //Z
            presetPositionsArray[currentOffset + 3] = 0;  //>=1 => an active preset

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


        public unsafe int[] GetEdgeDataInts()
        {
            //var textureSize = indexTextureSize(_graphStructureLinear.Count);
            List<List<int>> targetArray = _graphStructureBalanced;
            var textureSize = countDataArrayItems(targetArray) * 2;
            int[] textureArray = new int[textureSize];

            _edgeStrengthFloats = new float[textureSize];
            if (textureSize == 0) return textureArray;


            int currentNodeIndex = 0;
            int edgeIndex = 0;
            for (currentNodeIndex = 0; currentNodeIndex < internalProtoGraph.NodeList.Count; currentNodeIndex++)
            {
                List<uint> neigbours = internalProtoGraph.NodeList[currentNodeIndex].OutgoingNeighboursSet;
                for (var nidx = 0; nidx < neigbours.Count; nidx++)
                {
                    textureArray[edgeIndex] = (int)neigbours[nidx];
                    _edgeStrengthFloats[edgeIndex] = GetAttractionForce(internalProtoGraph.GetEdge((uint)currentNodeIndex, neigbours[nidx]));
                    edgeIndex++;
                    if (edgeIndex == textureArray.Length) return textureArray;
                }

                neigbours = internalProtoGraph.NodeList[currentNodeIndex].IncomingNeighboursSet;
                for (var nidx = 0; nidx < neigbours.Count; nidx++)
                {
                    textureArray[edgeIndex] = (int)neigbours[nidx];
                    _edgeStrengthFloats[edgeIndex] = GetAttractionForce(internalProtoGraph.GetEdge(neigbours[nidx], (uint)currentNodeIndex));
                    edgeIndex++;
                    if (edgeIndex == textureArray.Length) return textureArray;
                }
            }

            /*
            var currentIndex = 0;
            for (var i = 0; i < targetArray.Count; i++)
            {
                for (var j = 0; j < targetArray[i].Count; j++)
                {
                    textureArray[currentIndex] = targetArray[i][j];
                    currentIndex++;
                }
            }*/

            for (var i = edgeIndex; i < textureArray.Length; i++)
            {
                //fill unused RGBA slots with -1
                textureArray[i] = -1;
                _edgeStrengthFloats[edgeIndex] = -1;
            }

            return textureArray;
        }

        float[] _edgeStrengthFloats;
        public unsafe float[] GetEdgeStrengthFloats()
        {
            return _edgeStrengthFloats;
        }

        int[] _blockDataInts;
        bool _blockDataIncomplete;
        public unsafe int[] GetNodeBlockData()
        {
            return _blockDataInts;
        }

        void createBlockDataBuf(int nodecount)
        {

            _blockDataInts = new int[nodecount * 4];
            Dictionary<int, int> blockMiddles = new Dictionary<int, int>();
            for (int blockIdx = 0; blockIdx < internalProtoGraph.BlocksFirstLastNodeList.Count; blockIdx++)
            {
                var firstIdx_LastIdx = internalProtoGraph.BlocksFirstLastNodeList[blockIdx];
                if (firstIdx_LastIdx == null) continue;

                if (firstIdx_LastIdx.Item1 == firstIdx_LastIdx.Item2)
                {
                    blockMiddles[blockIdx] = (int)firstIdx_LastIdx.Item1;
                }
                else
                {
                    Debug.Assert(firstIdx_LastIdx.Item1 < firstIdx_LastIdx.Item2);
                    uint centerNodeID = firstIdx_LastIdx.Item1 + (uint)Math.Ceiling((double)(firstIdx_LastIdx.Item2 - firstIdx_LastIdx.Item1) / 2.0);
                    blockMiddles[blockIdx] = (int)centerNodeID;
                }

                Debug.Assert(blockMiddles[blockIdx] >= firstIdx_LastIdx.Item1 && blockMiddles[blockIdx] <= firstIdx_LastIdx.Item2);
            }

            for (uint nodeIdx = 0; nodeIdx < nodecount; nodeIdx++)
            {
                NodeData n = internalProtoGraph.safe_get_node(nodeIdx);
                var firstIdx_LastIdx = internalProtoGraph.BlocksFirstLastNodeList[(int)n.BlockID];
                if (firstIdx_LastIdx == null) continue;

                var blockSize = (firstIdx_LastIdx.Item2 - firstIdx_LastIdx.Item1) + 1;
                int blockID = (int)n.BlockID;
                if (!blockMiddles.ContainsKey(blockID)) 
                    continue;
                int blockMid = blockMiddles[blockID];


                int offsetFromCenter = 0;
                if (blockSize > 1)
                {
                    offsetFromCenter = (int)nodeIdx - blockMid;
                }
                else
                {
                    offsetFromCenter = 0;
                }

                int centerPseudoBlockTopID = -1;
                int centerPseudoBlockBaseID = -1;
                if (nodeIdx == blockMid || blockSize == 1)
                {
                    centerPseudoBlockTopID = (int)firstIdx_LastIdx.Item1;
                    centerPseudoBlockBaseID = (int)firstIdx_LastIdx.Item2;
                }



                _blockDataInts[nodeIdx * 4] = blockID;
                _blockDataInts[nodeIdx * 4 + 1] = offsetFromCenter;
                _blockDataInts[nodeIdx * 4 + 2] = centerPseudoBlockTopID;
                _blockDataInts[nodeIdx * 4 + 3] = centerPseudoBlockBaseID;
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

            createBlockDataBuf(targetArray.Count);


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
                    presetPositionsArray[i + 3] = -1.0f;
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
                        Debug.Assert(e.heatRank >= 0 && e.heatRank <= 9);
                        GlobalConfig.eThemeColour heatColEnum = (GlobalConfig.eThemeColour)((float)GlobalConfig.eThemeColour.eHeat0Lowest + e.heatRank);
                        return new WritableRgbaFloat(GlobalConfig.ThemeColoursCustom[heatColEnum]);
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
                    if (!TextEnabledIns && !n.ins.hasSymbol) {
                        n.label = null;
                        return null;
                    };

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

        void RegenerateLabels() => _newLabels = true;
        bool _newLabels;

        eRenderingMode lastRenderingMode = eRenderingMode.eStandardControlFlow;
        //important todo - cacheing!  once the result is good
        public Position2DColour[] GetMaingraphNodeVerts(eRenderingMode renderingMode,
            out List<uint> nodeIndices,
            out Position2DColour[] nodePickingColors,
            out List<Tuple<string, Color>> captions)
        {
            bool createNewLabels = false;
            if (renderingMode != lastRenderingMode || _newLabels)
            {
                createNewLabels = true;
                _newLabels = false;
                lastRenderingMode = renderingMode;
            }

            uint textureSize = LinearIndexTextureSize();
            Position2DColour[] NodeVerts = new Position2DColour[textureSize * textureSize];

            nodePickingColors = new Position2DColour[textureSize * textureSize];
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

                    NodeVerts[index] = new Position2DColour
                    {
                        Position = new Vector2(x, y),
                        Color = GetNodeColor((int)index, renderingMode)
                    };

                    nodePickingColors[index] = new Position2DColour
                    {
                        Position = new Vector2(x, y),
                        Color = new WritableRgbaFloat(index, 0, 0, 1)
                    };

                    if (TextEnabled)
                    {
                        var caption = createNodeLabel((int)index, renderingMode, createNewLabels);
                        captions.Add(caption);
                    }


                }
            }
            return NodeVerts;
        }


        public Position2DColour[] GetPreviewgraphNodeVerts(out List<uint> nodeIndices, eRenderingMode renderingMode)
        {
            uint textureSize = LinearIndexTextureSize();
            Position2DColour[] NodeVerts = new Position2DColour[textureSize * textureSize];

            nodeIndices = new List<uint>();
            int nodeCount = RenderedNodeCount();
            for (uint y = 0; y < textureSize; y++)
            {
                for (uint x = 0; x < textureSize; x++)
                {
                    var index = y * textureSize + x;
                    if (index >= nodeCount) return NodeVerts;

                    nodeIndices.Add(index);

                    NodeVerts[index] = new Position2DColour
                    {
                        Position = new Vector2(x, y),
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


        public Position2DColour[] GetEdgeLineVerts(eRenderingMode renderingMode,
            out List<uint> edgeIndices, out int vertCount, out int graphDrawnEdgeCount)
        {
            uint evTexWidth = EdgeVertsTextureWidth();
            Position2DColour[] EdgeLineVerts = new Position2DColour[evTexWidth * evTexWidth * 16];

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
                        new Position2DColour
                        {
                            Position = new Vector2(srcNodeIdx % textureSize, (float)Math.Floor((float)(srcNodeIdx / textureSize))),
                            Color = ecol
                        };
                edgeIndices.Add((uint)vertCount); vertCount++;

                EdgeLineVerts[vertCount] =
                    new Position2DColour
                    {
                        Position = new Vector2(destNodeIdx % textureSize, (float)Math.Floor((float)(destNodeIdx / textureSize))),
                        Color = ecol
                    };
                edgeIndices.Add((uint)vertCount); vertCount++;

            }
            graphDrawnEdgeCount = DrawnEdgesCount;
            return EdgeLineVerts;
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
                    if (edge.Item1 == _lastAnimatedVert)
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
                uint callerIdx = callers.Find(n => n.Item1 == _lastAnimatedVert).Item2;
                LinkingPair = new Tuple<uint, uint>(_lastAnimatedVert, callerIdx);

            }
            else
            {
                //find vert in internal code
                InstructionData nextIns = nextBlock[0];
                if (nextIns.threadvertIdx.TryGetValue(internalProtoGraph.ThreadID, out uint caller))
                {
                    LinkingPair = new Tuple<uint, uint>(_lastAnimatedVert, caller);
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

                if (TextEnabledLive && listOffset == 0 && internalProtoGraph.safe_get_node(nodeIdx).IsExternal)
                {
                    if (brightTime == Anim_Constants.KEEP_BRIGHT)
                        AddRisingExtern(nodeIdx, entry.count - 1, Anim_Constants.KEEP_BRIGHT);
                    else
                        AddRisingExtern(nodeIdx, entry.count - 1, GlobalConfig.ExternAnimDisplayFrames);
                }


                if (!(entry.entryType == eTraceUpdateType.eAnimUnchained) && listOffset == 0)
                {
                    Tuple<uint, uint> edge = new Tuple<uint, uint>(_lastAnimatedVert, nodeIdx);
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

                _lastAnimatedVert = nodeIdx;

                ++listOffset;
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (listOffset == (entry.count + 1))) break;

            }
        }


        void end_unchained(ANIMATIONENTRY entry)
        {

            currentUnchainedBlocks.Clear();
            List<InstructionData> firstChainedBlock = internalProtoGraph.ProcessData.getDisassemblyBlock(entry.blockID);
            _lastAnimatedVert = firstChainedBlock[^1].threadvertIdx[tid]; //should this be front()?

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


        //return false if we need more trace data to do further updates
        bool process_live_update()
        {
            if (internalProtoGraph.HasRecentStep) return false;

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

            internalProtoGraph.set_active_node(_lastAnimatedVert);

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

        public void ApplyMouseWheelDelta(float delta)
        {
            CameraZoom += delta * 120;
        }


        public Matrix4x4 GetProjectionMatrix(float aspectRatio)
        {
            return Matrix4x4.CreatePerspectiveFieldOfView(CameraFieldOfView, aspectRatio, CameraClippingNear, CameraClippingFar);
        }

        public Matrix4x4 GetViewMatrix()
        {
            Vector3 translation = new Vector3(CameraXOffset, CameraYOffset, CameraZoom);
            Matrix4x4 viewMatrix = Matrix4x4.CreateTranslation(translation);
            viewMatrix = Matrix4x4.Multiply(viewMatrix, RotationMatrix);
            return viewMatrix;
        }

        public Matrix4x4 GetPreviewViewMatrix()
        {
            Vector3 translation = new Vector3(PreviewCameraXOffset, PreviewCameraYOffset, PreviewCameraZoom);
            Matrix4x4 viewMatrix = Matrix4x4.CreateTranslation(translation);
            viewMatrix = Matrix4x4.Multiply(viewMatrix, RotationMatrix);
            return viewMatrix;
        }


        public void ApplyMouseDragDelta(Vector2 delta)
        {
            CameraXOffset -= delta.X;
            CameraYOffset += delta.Y;
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
                                width: (uint)size.X, height: (uint)size.Y, mipLevels: 1, arrayLayers: 1,
                                format: PixelFormat.R32_G32_B32_A32_Float, usage: TextureUsage.RenderTarget | TextureUsage.Sampled));
            _previewFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _previewTexture));
        }

        public bool HighlightsChanged;

        Dictionary<int, Vector4> _customHighlightColours = new Dictionary<int, Vector4>();
        public Vector4? GetCustomHighlightColour(int nodeIdx)
        {
            lock (textLock)
            {
                if (_customHighlightColours.TryGetValue(nodeIdx, out Vector4 col)) return col;
                return null;
            }
        }


        public void SetCustomHighlightColour(int nodeIdx, Vector4 colour)
        {
            lock (textLock)
            {
                _customHighlightColours[nodeIdx] = colour;
            }
        }


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
                    nodeAttribArray1[nidx * 4 + 0] = 400f;  // make bigger
                    nodeAttribArray1[nidx * 4 + 3] = 1.0f;  // set target icon
                    internalProtoGraph.safe_get_node(nidx).SetHighlighted(true);
                }
                HighlightsChanged = true;
            }
        }

        public long lastRenderTime;
        public bool flipflop;
        public uint RenderedEdgeCount; //todo - this is really all we need

        int _computeBufferNodeCount; //this is gross and temporary
        public int ComputeBufferNodeCount
        {
            get => _computeBufferNodeCount;
            set => _computeBufferNodeCount = value;
        }

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
                case eGraphLayout.eForceDirected3DNodes:
                    return "ForceDirected3D";
                default:
                    return "UnknownPlotType_" + LayoutStyle.ToString();
            }
        }

        public static bool LayoutIsForceDirected(eGraphLayout style)
        {
            switch (style)
            {
                case eGraphLayout.eForceDirected3DBlocks:
                case eGraphLayout.eForceDirected3DNodes:
                    return true;
                default:
                    return false;
            }
        }

        public bool SetLayout(eGraphLayout newStyle)
        {
            if (newStyle == LayoutStyle) return false;
            if (LayoutIsForceDirected(LayoutStyle))
            {
                savedForcePositions[LayoutStyle] = positionsArray1.ToArray();
            }

            if (LayoutIsForceDirected(newStyle))
            {
                presetPositionsArray = savedForcePositions[newStyle];
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
        //public bool 
        public bool NeedReplotting = false; //all verts need re-plotting from scratch
                                            //bool performSymbolResolve = false;

        public bool NodesVisible = true;
        public bool EdgesVisible = true;

        bool _textEnabled = true;
        public bool TextEnabled {
            get => _textEnabled;
            set {
                _textEnabled = value;
                if (_textEnabled) RegenerateLabels();
            }
        }

        bool _textEnabledIns = true;
        public bool TextEnabledIns {
            get => _textEnabledIns;
            set {
                _textEnabledIns = value;
                RegenerateLabels();
            }
        }

        bool _textEnabledLive = true;
        public bool TextEnabledLive {
            get => _textEnabledLive;
            set => _textEnabledLive = value;
        }

        bool _liveNodeEdgeEnabled = true;
        public bool LiveNodeEdgeEnabled
        {
            get => _liveNodeEdgeEnabled;
            set => _liveNodeEdgeEnabled = value;
        }

        public Vector3 _unprojWorldCoordTL, _unprojWorldCoordBR;


        public void UpdatePreviewVisibleRegion(Vector2 graphWidgetSize)
        {

            Matrix4x4 proj = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, (float)graphWidgetSize.X / graphWidgetSize.Y, CameraClippingNear, CameraClippingFar);
            Matrix4x4 world = RotationMatrix;
            Matrix4x4 view = Matrix4x4.CreateTranslation(new Vector3(CameraXOffset, CameraYOffset, CameraZoom));

            Matrix4x4.Invert(proj, out Matrix4x4 invProj);
            Matrix4x4.Invert(world * view, out Matrix4x4 invWV);

            Vector4 ClipAfterProj = Vector4.Transform(new Vector3(0, 0, CameraZoom), proj);
            Vector3 NDC = Vector3.Divide(new Vector3(ClipAfterProj.X, ClipAfterProj.Y, ClipAfterProj.Z), ClipAfterProj.W);

            _unprojWorldCoordTL = GraphicsMaths.ScreenToWorldCoord(new Vector2(0, 0), NDC.Z, ClipAfterProj.W, invWV, invProj, graphWidgetSize);
            _unprojWorldCoordBR = GraphicsMaths.ScreenToWorldCoord(graphWidgetSize, NDC.Z, ClipAfterProj.W, invWV, invProj, graphWidgetSize);
        }


        public void GetPreviewVisibleRegion(Vector2 PrevWidgetSize, Matrix4x4 previewProjection, out Vector2 TopLeft, out Vector2 BaseRight)
        {
            //Vector2 PrevWidgetSize = new Vector2(290, 150);

            Matrix4x4 worldP = RotationMatrix;
            Matrix4x4 viewP = Matrix4x4.CreateTranslation(new Vector3(PreviewCameraXOffset, PreviewCameraYOffset, PreviewCameraZoom));
            Matrix4x4 worldviewP = worldP * viewP;

            TopLeft = GraphicsMaths.WorldToScreenCoord(_unprojWorldCoordTL, worldviewP, previewProjection, PrevWidgetSize);
            BaseRight = GraphicsMaths.WorldToScreenCoord(_unprojWorldCoordBR, worldviewP, previewProjection, PrevWidgetSize);
        }


        /*
         * I'm not good enough at graphics to work out how far to move the camera in one click, instead move towards the click location
         * In a few frames it will get there.
         */
        public void MoveCameraToPreviewClick(Vector2 pos, Vector2 previewSize, Vector2 mainGraphWidgetSize, Matrix4x4 previewProjection)
        {
            Vector4 ClipAfterProj = Vector4.Transform(new Vector3(0, 0, PreviewCameraZoom), previewProjection);
            Vector3 NDC = Vector3.Divide(new Vector3(ClipAfterProj.X, ClipAfterProj.Y, ClipAfterProj.Z), ClipAfterProj.W);

            Matrix4x4 worldP = RotationMatrix;
            Matrix4x4 viewP = Matrix4x4.CreateTranslation(new Vector3(PreviewCameraXOffset, PreviewCameraYOffset, PreviewCameraZoom));
            Matrix4x4.Invert(worldP * viewP, out Matrix4x4 invVWP);
            Matrix4x4.Invert(previewProjection, out Matrix4x4 invPrevProj);

            Matrix4x4 projMain = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, mainGraphWidgetSize.X / mainGraphWidgetSize.Y, CameraClippingNear, CameraClippingFar);
            Matrix4x4 worldMain = RotationMatrix;
            Matrix4x4 viewMain = Matrix4x4.CreateTranslation(new Vector3(CameraXOffset, CameraYOffset, CameraZoom));

            Vector3 clickWorldCoord = GraphicsMaths.ScreenToWorldCoord(pos, NDC.Z, ClipAfterProj.W, invVWP, invPrevProj, previewSize);
            Vector2 clickMainViewCoord = GraphicsMaths.WorldToScreenCoord(clickWorldCoord, worldMain * viewMain, projMain, mainGraphWidgetSize);
            
            float XDiff = (mainGraphWidgetSize.X / 2f) - clickMainViewCoord.X;
            float YDiff = (mainGraphWidgetSize.Y / 2f) - clickMainViewCoord.Y;

            CameraXOffset += XDiff; 
            CameraYOffset += YDiff;
        }



        bool freeMe = false;

        protected Stack<Tuple<ulong, uint>> ThreadCallStack = new Stack<Tuple<ulong, uint>>();

        public ProtoGraph internalProtoGraph { get; protected set; } = null;

        protected List<ANIMATIONENTRY> currentUnchainedBlocks = new List<ANIMATIONENTRY>();
        protected List<WritableRgbaFloat> graphColours = new List<WritableRgbaFloat>();

        public eGraphLayout LayoutStyle { get; protected set; } = eGraphLayout.eForceDirected3DNodes;

        public float[] positionsArray1 = Array.Empty<float>();
        Dictionary<eGraphLayout, float[]> savedForcePositions = new Dictionary<eGraphLayout, float[]>();
        public float[] velocityArray1 = Array.Empty<float>();
        public float[] nodeAttribArray1 = Array.Empty<float>();
        public float[] presetPositionsArray = Array.Empty<float>();
        public ulong renderFrameVersion;


        public Veldrid.Texture _previewTexture;
        public Veldrid.Framebuffer _previewFramebuffer;

        //todo - methods
        public float CameraZoom = -5000;
        public float CameraXOffset = 0f;
        public float CameraYOffset = 0f;

        public float PreviewCameraXOffset = 0f;
        public float PreviewCameraYOffset = 0f;
        public float PreviewCameraZoom = -4000;
        public float CameraFieldOfView = 0.6f;
        public float CameraClippingFar = 60000;
        public float CameraClippingNear = 1; //extern jut
        public Matrix4x4 RotationMatrix = Matrix4x4.Identity;


        public readonly Object RenderingLock = new Object();

        public uint pid { get; private set; }
        public uint tid { get; private set; }

        public int LiveAnimationUpdatesPerFrame = GlobalConfig.LiveAnimationUpdatesPerFrame;

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
