﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Threading;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.VeldridGraphBuffers;

namespace rgat
{
    /// <summary>
    /// Represents the graphical rendering of a thread (ProtoGraph)
    /// </summary>
    public class PlottedGraph
    {
        /// <summary>
        /// The animation replay state of this graph
        /// </summary>
        public enum REPLAY_STATE
        {
            /// <summary>
            /// Not being replayed
            /// </summary>
            Stopped,
            /// <summary>
            /// Currently being played
            /// </summary>
            Playing,
            /// <summary>
            /// Paused in an animated state
            /// </summary>
            Paused,
            /// <summary>
            /// Awaiting reset to a stopped state
            /// </summary>
            Ended
        };

        /// <summary>
        /// Create a plotted graph
        /// </summary>
        /// <param name="protoGraph">ProtoGraph of the thread</param>
        /// <param name="device">GraphicsDevice of the GPU this thread is being rendered on</param>
        public PlottedGraph(ProtoGraph protoGraph, GraphicsDevice device)
        {
            InternalProtoGraph = protoGraph;
            LayoutState = new GraphLayoutState(this, device, LayoutStyles.Style.ForceDirected3DNodes);


            IsAnimated = !InternalProtoGraph.Terminated;
            InitGraphColours();

            CameraClippingFar = 60000f;
            CameraZoom = -6000f;
            CameraXOffset = -400;
        }

        readonly ReaderWriterLockSlim _renderLock = new ReaderWriterLockSlim();
        /// <summary>
        /// Takes edges that have been through the trace processor worker and
        /// inserts them into the graphcis buffers for layout/drawing
        /// </summary>
        public void RenderGraph()
        {
            if (_renderLock.TryEnterWriteLock(0))
            {
                render_new_blocks();
                _renderLock.ExitWriteLock();
            }
        }


        /// <summary>
        /// Seek to a user specified position in the replay
        /// </summary>
        /// <param name="position">A position in the replay from 0-1</param>
        public void SeekToAnimationPosition(float position)
        {
            if (ReplayState == REPLAY_STATE.Stopped)
            {
                ReplayState = REPLAY_STATE.Paused;
                SetAnimated(true);
            }

            int NewPosition = (int)(position * (float)InternalProtoGraph.SavedAnimationData.Count);
            _userSelectedAnimPosition = NewPosition;
            Console.WriteLine($"Animation set index: {NewPosition}, last: {_lastReplayedIndex}");

        }

        /// <summary>
        /// Process more animation replay updates
        /// </summary>
        public void ProcessReplayUpdates()
        {
            if (_userSelectedAnimPosition != -1)
            {
                SetAnimated(true);
                _lastReplayedIndex = Math.Max(0, _userSelectedAnimPosition - 2 * (int)Math.Ceiling(AnimationRate));
                AnimationIndex = _userSelectedAnimPosition;
                remove_unchained_from_animation();
            }
            process_replay_animation_updates();

            if (_userSelectedAnimPosition != -1)
                _userSelectedAnimPosition = -1;
        }


        /// <summary>
        /// Last instruction that was replayed
        /// </summary>
        public uint LastAnimatedVert { get; private set; }


        /// <summary>
        /// Reset the replay animation state
        /// This should only ever be called from the maingraph rendering thread
        /// </summary>
        public void ResetAnimation()
        {
            ResetAllActiveAnimatedAlphas();

            //animInstructionIndex = 0;
            LastAnimatedVert = 0;
            AnimationIndex = 0;
            _lastReplayedIndex = -1;

            unchainedWaitFrames = 0;
            remove_unchained_from_animation();
            animBuildingLoop = false;
            SetAnimated(false);

            ReplayState = REPLAY_STATE.Stopped;
            Logging.RecordLogEvent("Animation reset to stopped state");
        }


        /// <summary>
        /// How far the animation as progressed through the recorded animation entries
        /// </summary>
        /// <returns>Progress as a float from 0-1</returns>
        public float GetAnimationProgress()
        {
            if (InternalProtoGraph.SavedAnimationData.Count == 0) return 0;
            return (float)((float)AnimationIndex / (float)InternalProtoGraph.SavedAnimationData.Count);
        }


        /// <summary>
        /// probably defunct. todo for when trace deletion is implemented
        /// </summary>
        public bool BeingDeleted { private set; get; } = false;


        /// <summary>
        /// Set the graph animation state
        /// </summary>
        /// <param name="newState">animated or not</param>
        public void SetAnimated(bool newState)
        {
            IsAnimated = newState;

            _newLabels = true;
            if (!newState)
            {
                remove_unchained_from_animation();
            }
        }

        /// <summary>
        /// Move forward in the animation
        /// </summary>
        /// <param name="steps">The number of animation entries to process</param>
        public void StepPausedAnimation(int steps)
        {
            process_replay_animation_updates(steps);
            AnimationIndex = (int)Math.Floor(AnimationIndex);
        }


        /// <summary>
        /// Toggle replay paused state
        /// </summary>
        public void PlayPauseClicked()
        {
            switch (ReplayState)
            {
                case REPLAY_STATE.Stopped: //start it from beginning
                    ReplayState = REPLAY_STATE.Playing;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Stopped -> Playing");
                    break;

                case REPLAY_STATE.Playing: //pause it
                    ReplayState = REPLAY_STATE.Paused;
                    Console.WriteLine("Animation state Playing -> Paused");
                    break;

                case REPLAY_STATE.Paused: //unpause it
                    ReplayState = REPLAY_STATE.Playing;
                    SetAnimated(true);
                    Console.WriteLine("Animation state Paused -> Playing");
                    break;

            }
        }


        /// <summary>
        /// Schedule the animation to be reset
        /// </summary>
        public void ResetClicked()
        {
            ReplayState = REPLAY_STATE.Ended;
        }


        /// <summary>
        /// Are all of the edges rendered
        /// </summary>
        public bool RenderingComplete => DrawnEdgesCount >= InternalProtoGraph.EdgeCount;


        /// <summary>
        /// Construct more graph geometry from un-rendered edges in the ProtoGraph
        /// </summary>
        protected void render_new_blocks()
        {
            int endIndex = InternalProtoGraph.EdgeCount;
            int drawCount = endIndex - (int)DrawnEdgesCount;
            if (drawCount <= 0) return;
            int dbglimit = 9999;
            if (DrawnEdgesCount > dbglimit) return;


            for (int edgeIdx = DrawnEdgesCount; edgeIdx < endIndex; edgeIdx++)
            {
                InternalProtoGraph.GetEdgeNodes(edgeIdx, out Tuple<uint, uint> edgeNodes, out EdgeData e);

                if (edgeNodes.Item1 >= _graphStructureLinear.Count)
                {
                    AddNode(edgeNodes.Item1);
                }

                if (edgeNodes.Item2 >= _graphStructureLinear.Count)
                {
                    //if (e.edgeClass == eEdgeNodeType.eEdgeException)
                    //    NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeException;
                    AddNode(edgeNodes.Item2, e);

                }

                UpdateNodeLinks((int)edgeNodes.Item1, (int)edgeNodes.Item2);
                DrawnEdgesCount++;

                if (rgatState.rgatIsExiting) break;

                if (DrawnEdgesCount > dbglimit) return;
            }
        }


        float GetAttractionForce(EdgeData edge)
        {
            //don't attract node to other nodes with lots of connections.
            //todo: do this at edge creation time, add a flag to the edgedata class
            //GlobalConfig.NodeClumpLimit = 1;
            if (GlobalConfig.NodeClumpLimit > 0)
            {
                InternalProtoGraph.GetEdgeNodes(edge.EdgeListIndex, out NodeData source, out NodeData target);
                if (source.OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit) return GlobalConfig.NodeClumpForce;
                if (target.IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit) return GlobalConfig.NodeClumpForce;
                if (source.IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit) return GlobalConfig.NodeClumpForce;
                if (target.OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit) return GlobalConfig.NodeClumpForce;
            }

            //return 5000;

            float force;
            switch (edge.edgeClass)
            {
                case eEdgeNodeType.eEdgeNew:
                    if (edge.sourceNodeType == eEdgeNodeType.eNodeJump)
                        force = 0.4f;
                    else
                        force = 1f;
                    break;
                case eEdgeNodeType.eEdgeLib:
                    force = 1f;
                    break;
                case eEdgeNodeType.eEdgeCall:
                    force = 0.4f;
                    break;
                case eEdgeNodeType.eEdgeOld:
                    force = 0.3f;
                    break;
                case eEdgeNodeType.eEdgeReturn:
                    force = 0.2f;
                    break;
                case eEdgeNodeType.eEdgeException:
                    force = 2f;
                    break;
                default:
                    Console.WriteLine($"Unhandled edgetype {edge.edgeClass} with edge {edge.EdgeListIndex}");
                    force = 1f;
                    break;
            }


            return force;
        }


        /// <summary>
        /// Create a preset graph layout for the specified style
        /// If force directed it will retrieve a saved layout if available, or randomise if not
        /// </summary>
        /// <param name="style">The layout style</param>
        /// <returns>Positions for each node</returns>
        public float[]? GeneratePresetPositions(LayoutStyles.Style style)
        {
            //_presetEdgeCount = InternalProtoGraph.get_num_edges();
            switch (style)
            {
                case LayoutStyles.Style.CylinderLayout:
                    Console.WriteLine("Generating cylinder presets");
                    return GenerateCylinderLayout();

                case LayoutStyles.Style.Circle:
                    return GenerateCircleLayout();

                default:
                    if (LayoutStyles.IsForceDirected(style))
                    {
                        if (!LayoutState.GetSavedLayout(style, out float[]? layout))
                        {
                            Console.WriteLine("Generating forcedir presets");
                            return CreateRandomPresetLayout();
                        }
                        else
                        {
                            Console.WriteLine("Returning old forcedir presets");
                            return layout;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error: Tried to layout invalid preset style: " + ActiveLayoutStyle.ToString());
                        return null;
                    }
            }
        }


        float[] GenerateCylinderLayout()
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
                NodeData? n = InternalProtoGraph.GetNode(i);
                Debug.Assert(n is not null);
                NodeData? firstParent = InternalProtoGraph.GetNode(n.parentIdx);
                Debug.Assert(firstParent is not null);

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

                            if (firstParent.IsConditional && n.address == firstParent.ins.condDropAddress)
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

                            Tuple<float, float>? callerPos = null;
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
                    callStack.Add(new Tuple<Tuple<float, float>, ulong>(new Tuple<float, float>(a, b), n.address + (ulong)n.ins.NumBytes));
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

            return textureArray;
        }

        readonly float CYLINDER_RADIUS = 5000f;
        readonly float CYLINDER_PIXELS_PER_B = 30f;
        readonly float CYLINDER_PIXELS_PER_A = 60f;
        void GenerateCylinderWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            int CYLINDER_PIXELS_PER_ROW = 500;
            float WF_POINTSPERLINE = 50f;
            int wireframe_loop_count = (int)Math.Ceiling((_lowestWireframeLoop * CYLINDER_PIXELS_PER_B) / CYLINDER_PIXELS_PER_ROW) + 1;
            float radius = CYLINDER_RADIUS;

            WritableRgbaFloat wireframeColour = Themes.GetThemeColourWRF(Themes.eThemeColour.WireFrame);
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
                        Color = wireframeColour,
                        Position = new Vector4(radius * (float)Math.Cos(angle), (float)rowYcoord, radius * (float)Math.Sin(angle), 0)
                    };
                    verts.Add(gpc);
                }

            }
        }



        void GenerateRotationWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            float WF_POINTSPERLINE = 50f;
            float radius = _furthestNodeDimension;

            WritableRgbaFloat YawColour = new WritableRgbaFloat(0xFFE69F00);
            WritableRgbaFloat RollColour = new WritableRgbaFloat(0xFF56B4E9);
            WritableRgbaFloat PitchColour = new WritableRgbaFloat(0xFF009E73);

            for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
            {
                float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                if (circlePoint > 1)
                    edgeIndices.Add((uint)verts.Count - 1);

                edgeIndices.Add((uint)verts.Count);
                GeomPositionColour gpc = new GeomPositionColour
                {
                    Color = YawColour, //new WritableRgbaFloat(Color.Cyan),
                    Position = new Vector4(radius * (float)Math.Cos(angle), 0, radius * (float)Math.Sin(angle), 0)
                };
                verts.Add(gpc);
            }

            for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
            {
                float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                if (circlePoint > 1)
                    edgeIndices.Add((uint)verts.Count - 1);

                edgeIndices.Add((uint)verts.Count);
                GeomPositionColour gpc = new GeomPositionColour
                {
                    Color = RollColour,
                    Position = new Vector4(radius * (float)Math.Cos(angle), radius * (float)Math.Sin(angle), 0, 0)
                };
                verts.Add(gpc);
            }

            for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
            {
                float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                if (circlePoint > 1)
                    edgeIndices.Add((uint)verts.Count - 1);

                edgeIndices.Add((uint)verts.Count);
                GeomPositionColour gpc = new GeomPositionColour
                {
                    Color = PitchColour,
                    Position = new Vector4(0, radius * (float)Math.Cos(angle), radius * (float)Math.Sin(angle), 0)
                };
                verts.Add(gpc);
            }


        }

        float _lowestWireframeLoop;
        //todo cache


        /// <summary>
        /// Get geometry and colour of various non-instruction edges like highlights and wireframes
        /// </summary>
        /// <param name="edgeIndices">Output list of illustration edge indexes</param>
        /// <returns>Output edge geometry</returns>
        public GeomPositionColour[] GetIllustrationEdges(out List<uint> edgeIndices)
        {

            List<GeomPositionColour> resultList = new List<GeomPositionColour>();
            edgeIndices = new List<uint>();

            //todo: if wireframe enabled

            switch (WireframeStyle())
            {
                case LayoutStyles.Style.CylinderLayout:
                    GenerateCylinderWireframe(ref resultList, ref edgeIndices);
                    break;
                case LayoutStyles.Style.ForceDirected3DNodes:
                case LayoutStyles.Style.ForceDirected3DBlocks:
                    if (rgatUI.ResponsiveKeyHeld)
                    {
                        GenerateRotationWireframe(ref resultList, ref edgeIndices);
                    }
                    break;
                default:
                    break;
            }

            if (AllHighlightedNodes.Count > 0)
            {
                CreateHighlightEdges(edgeIndices, resultList);
            }

            if (Opt_LiveNodeEdgeEnabled && (IsAnimated || !InternalProtoGraph.Terminated))
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
            uint node = LastAnimatedVert;
            if (InternalProtoGraph.HasRecentStep)
            {
                var addrnodes = InternalProtoGraph.ProcessData.GetNodesAtAddress(InternalProtoGraph.RecentStepAddr, InternalProtoGraph.ThreadID);
                if (addrnodes.Count > 0)
                    node = addrnodes[^1];
            }

            //point the active node indicator line to a random busy-region instruction
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


        /// <summary>
        /// The style of wireframe to draw for this graph
        /// </summary>
        /// <returns>Layout style</returns>
        public LayoutStyles.Style WireframeStyle()
        {
            if (LayoutState.ActivatingPreset)
            {
                return LayoutState.PresetStyle;
            }
            else
            {
                return LayoutState.Style;
            }
        }




        //Adapted from analytics textureGenerator.js 
        float[] GenerateCircleLayout()
        {

            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();

            if (InternalProtoGraph.EdgeCount > RenderedEdgeCount)
            {
                Console.WriteLine($"Drawing preset {InternalProtoGraph.EdgeCount }  > {RenderedEdgeCount}  edges with {nodeCount} nodes tex size {textureSize}");
            }
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
            return textureArray;
        }

        /// <summary>
        /// Increase the activity level of a force directed plot
        /// </summary>
        public void IncreaseTemperature()
        {
            Temperature += _graphStructureLinear.Count / 2;
        }

        /// <summary>
        /// Set the temperature of a force directed plot
        /// </summary>
        /// <param name="temp">Activity level</param>
        public void IncreaseTemperature(float temp)
        {
            Temperature = temp;
        }


        unsafe void AddNode(uint nodeIdx, EdgeData? edge = null)
        {

            textureLock.EnterReadLock();


            Debug.Assert(nodeIdx == _graphStructureLinear.Count); //todo, asserting here on load. i dont remember if this is important
            uint futureCount = (uint)_graphStructureLinear.Count + 1;
            var bufferWidth = indexTextureSize((int)futureCount);

            LayoutState.Lock.EnterUpgradeableReadLock();
            LayoutState.AddNode(nodeIdx, futureCount, bufferWidth, edge);
            LayoutState.Lock.ExitUpgradeableReadLock();

            lock (animationLock)
            {
                _graphStructureLinear.Add(new List<int>());
                _graphStructureBalanced.Add(new List<int>());
            }
            textureLock.ExitReadLock();
        }


        /// <summary>
        /// Create an array listing the index of every neighbour of every node
        /// Also initialises the edge strength array, 
        /// </summary>
        /// <returns>If there was data</returns>
        public bool GetEdgeRenderingData(out float[] edgeStrengths, out int[] edgeTargetIndexes, out int[] edgeIndexLookups)
        {
            //var textureSize = indexTextureSize(_graphStructureLinear.Count);
            List<List<int>> targetArray = _graphStructureBalanced;
            var textureSize = (int)countDataArrayItems(targetArray) * 2; //A->B + B->A


            if (textureSize == 0)
            {
                edgeStrengths = new float[] { 0 };
                edgeTargetIndexes = new int[] { 1 };
                edgeIndexLookups = new int[] { 1 };
                return false;
            }

            int nodeCount = InternalProtoGraph.NodeList.Count;
            edgeTargetIndexes = new int[textureSize];
            edgeStrengths = new float[textureSize];

            List<List<int>>? nodeNeighboursArray = null;
            lock (animationLock)
            {
                nodeNeighboursArray = _graphStructureBalanced.ToList();
            }
            var textureSize2 = indexTextureSize(nodeCount * 2);
            edgeIndexLookups = new int[textureSize2 * textureSize2];// * textureSize2 * 2];

            int currentNodeIndex;
            int edgeIndex = 0;
            for (currentNodeIndex = 0; currentNodeIndex < nodeCount; currentNodeIndex++)
            {
                edgeIndexLookups[currentNodeIndex * 2] = edgeIndex;

                List<uint> neigbours = InternalProtoGraph.NodeList[currentNodeIndex].OutgoingNeighboursSet;
                for (var nidx = 0; nidx < neigbours.Count; nidx++)
                {
                    edgeTargetIndexes[edgeIndex] = (int)neigbours[nidx];
                    if (InternalProtoGraph.EdgeExists(new Tuple<uint, uint>((uint)currentNodeIndex, neigbours[nidx]), out EdgeData? edge) && edge is not null)
                    {
                        edgeStrengths[edgeIndex] = GetAttractionForce(edge);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Edge A {currentNodeIndex},{neigbours[nidx]} didn't exist in getEdgeDataints", Logging.LogFilterType.TextAlert);
                        edgeStrengths[edgeIndex] = 0.5f;
                    }
                    edgeIndex++;


                    if (edgeIndex == edgeTargetIndexes.Length)
                    {
                        edgeIndexLookups[currentNodeIndex * 2 + 1] = edgeIndex;
                        return true;
                    }
                }

                neigbours = InternalProtoGraph.NodeList[currentNodeIndex].IncomingNeighboursSet;
                for (var nidx = 0; nidx < neigbours.Count; nidx++)
                {
                    edgeTargetIndexes[edgeIndex] = (int)neigbours[nidx];
                    if (InternalProtoGraph.EdgeExists(new Tuple<uint, uint>(neigbours[nidx], (uint)currentNodeIndex), out EdgeData? edge) && edge is not null)
                    {
                        edgeStrengths[edgeIndex] = GetAttractionForce(edge);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Edge B {neigbours[nidx]},{currentNodeIndex} didn't exist in getEdgeDataints", Logging.LogFilterType.TextAlert);
                        edgeStrengths[edgeIndex] = 0.5f;
                    }
                    edgeIndex++;
                    if (edgeIndex == edgeTargetIndexes.Length)
                    {
                        edgeIndexLookups[currentNodeIndex * 2 + 1] = edgeIndex;
                        return true;
                    }
                }

                edgeIndexLookups[currentNodeIndex * 2 + 1] = edgeIndex;
            }


            for (var i = edgeIndex; i < edgeTargetIndexes.Length; i++)
            {
                //fill unused RGBA slots with -1
                edgeTargetIndexes[i] = -1;
                edgeStrengths[edgeIndex] = -1;
            }

            for (var i = InternalProtoGraph.NodeList.Count * 2; i < edgeIndexLookups.Length; i++)
            {
                //fill unused RGBA slots with -1
                edgeIndexLookups[i] = -1;
            }
            return true;
        }


        /// <summary>
        /// Lists the first and last+1 edge index that this node is connected to
        /// usage:
        ///   selfedgei = edgeindices[index]
        ///   firstedge, endedge = selfedgei.x, selfedgei.y
        ///	  uint neighbour = edgeData[firstedge to endedge-1];
        ///    nodePosition = positions[neighbour];
        /// </summary>
        /// <returns></returns>
        public unsafe int[] GetNodeNeighbourDataOffsets()
        {
            //list of neighbours for each node:
            //eg a graph like 0->1, 0->3, 1->2
            // would result in be
            //   0     1    2   3
            //[[1,3],[0,2],[1],[0]]

            List<List<int>>? nodeNeighboursArray = null;
            lock (animationLock)
            {
                nodeNeighboursArray = _graphStructureBalanced.ToList();
            }

            //create the basic block metadata here for no good reason
            _blockRenderingMetadata = CreateBlockMetadataBuf(Math.Min(nodeNeighboursArray.Count, InternalProtoGraph.NodeList.Count));

            var textureSize = indexTextureSize(nodeNeighboursArray.Count);

            int[] sourceData = new int[textureSize * textureSize * 2];
            int edgeIndex = 0;

            for (var srcNodeIndex = 0; srcNodeIndex < nodeNeighboursArray.Count; srcNodeIndex++)
            {

                //keep track of the beginning of the array for this node
                int start = edgeIndex;

                foreach (int destNodeID in nodeNeighboursArray[srcNodeIndex])
                {
                    edgeIndex++;
                }

                //write the two sets of texture indices out.  We'll fill up an entire pixel on each pass

                if (start != edgeIndex)
                {
                    sourceData[srcNodeIndex * 2] = start;
                    sourceData[srcNodeIndex * 2 + 1] = edgeIndex;
                }
                else
                {

                    sourceData[srcNodeIndex * 2] = -1;
                    sourceData[srcNodeIndex * 2 + 1] = -1;
                }

            }

            for (var i = nodeNeighboursArray.Count * 2; i < sourceData.Length; i++)
            {

                // fill unused RGBA slots with -1
                sourceData[i] = -1;
            }
            //Console.WriteLine($"GetEdgeIndicesInts Returning indexes with {targetArray.Count} filled and {sourceData.Length - targetArray.Count} empty");
            return sourceData;
        }


        int[] _blockRenderingMetadata;

        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        public unsafe int[] GetBlockRenderingMetadata()
        {
            List<List<int>>? nodeNeighboursArray = null;
            lock (animationLock)
            {
                nodeNeighboursArray = _graphStructureBalanced.ToList();
            }
            return CreateBlockMetadataBuf(Math.Min(nodeNeighboursArray.Count, InternalProtoGraph.NodeList.Count));
        }


        /// <summary>
        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        /// item[0] = blockID
        /// item[1] = offsetFromCenter; number of nodes ahead the center node is
        /// item[2] = centerPseudoBlockTopID; top of the block this node is in
        /// item[3] = centerPseudoBlockBaseID; base of the block this node is in
        /// </summary>
        /// <param name="nodecount">Number of nodes to add. This isn't just taken from nodelist because
        /// it may be intended for a texture of a certain size</param>
        int[] CreateBlockMetadataBuf(int nodecount)
        {

            int[] blockDataInts = new int[nodecount * 4];
            Dictionary<int, int> blockMiddles = new Dictionary<int, int>();

            //step 1: find the center node of each block
            //  todo: cache
            for (int blockIdx = 0; blockIdx < InternalProtoGraph.BlocksFirstLastNodeList.Count; blockIdx++)
            {
                var firstIdx_LastIdx = InternalProtoGraph.BlocksFirstLastNodeList[blockIdx];
                if (firstIdx_LastIdx == null) continue;

                if (firstIdx_LastIdx.Item1 == firstIdx_LastIdx.Item2)
                {
                    blockMiddles[blockIdx] = (int)firstIdx_LastIdx.Item1; //1 node block, top/mid/base is the same
                }
                else
                {
                    var block = InternalProtoGraph.ProcessData.BasicBlocksList[blockIdx].Item2;
                    int midIdx = (int)Math.Ceiling((block.Count - 1.0) / 2.0);
                    var middleIns = block[midIdx];
                    if (!middleIns.GetThreadVert(TID, out uint centerNodeID))
                    {
                        blockMiddles[blockIdx] = -1; //instructions sent and not executed? why?
                        //Debug.Assert(false, $"Instruction 0x{middleIns.address:X} not found in thread {tid}");
                    }
                    else
                    {
                        blockMiddles[blockIdx] = (int)centerNodeID;
                    }
                }
            }

            //step 2:
            int externals = 0;
            for (uint nodeIdx = 0; nodeIdx < nodecount; nodeIdx++)
            {
                NodeData? n = InternalProtoGraph.GetNode(nodeIdx);  //todo - this grabs a lot of locks. improve it
                Debug.Assert(n is not null);

                uint blockSize;
                int blockMid;
                int blockID;
                Tuple<uint, uint> FirstLastIdx;
                if (!n.IsExternal)
                {
                    if (n.BlockID >= InternalProtoGraph.BlocksFirstLastNodeList.Count) continue;
                    FirstLastIdx = InternalProtoGraph.BlocksFirstLastNodeList[(int)n.BlockID]; //bug: this can happen before bflnl is filled
                    if (FirstLastIdx == null) continue;

                    blockSize = (FirstLastIdx.Item2 - FirstLastIdx.Item1) + 1;
                    blockID = (int)n.BlockID;
                    if (!blockMiddles.ContainsKey(blockID))
                        continue;
                    blockMid = blockMiddles[blockID];
                }
                else
                {
                    externals += 1;
                    FirstLastIdx = new Tuple<uint, uint>(n.Index, n.Index);
                    blockMid = (int)n.Index;
                    blockSize = 1;
                    //external nodes dont have a block id so just give them a unique one
                    //all that matters in the shader is it's unique
                    blockID = -1 - externals;
                }

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
                    centerPseudoBlockTopID = (int)FirstLastIdx.Item1;
                    centerPseudoBlockBaseID = (int)FirstLastIdx.Item2;
                }

                blockDataInts[nodeIdx * 4] = blockID;
                blockDataInts[nodeIdx * 4 + 1] = offsetFromCenter;
                blockDataInts[nodeIdx * 4 + 2] = centerPseudoBlockTopID;
                blockDataInts[nodeIdx * 4 + 3] = centerPseudoBlockBaseID;
            }

            return blockDataInts;
        }


        /// <summary>
        /// Number of node->node edges that have been rendered
        /// </summary>
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

        /// <summary>
        /// Create a new blank preset layout for this graph
        /// </summary>
        /// <returns>Positions of the preset nodes</returns>
        public float[] CreateBlankPresetLayout()
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
            return presetPositionsArray;
        }

        float[] CreateRandomPresetLayout()
        {

            var bufferWidth = indexTextureSize(_graphStructureLinear.Count);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            float[] positions = new float[bufferFloatCount];

            var bounds = 1000;
            var bounds_half = bounds / 2;
            Random rnd = new Random();
            for (var i = 0; i < positions.Length; i += 4)
            {
                if (i < _graphStructureLinear.Count * 4)
                {
                    positions[i] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positions[i + 1] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positions[i + 2] = ((float)rnd.NextDouble() * bounds) - bounds_half;
                    positions[i + 3] = 1;
                }
                else
                {
                    // fill the remaining pixels with -1, invalid positions
                    // can probably actually only set the .w component to -1, but for now keep it like this for safety
                    positions[i] = -1.0f;
                    positions[i + 1] = -1.0f;
                    positions[i + 2] = -1.0f;
                    positions[i + 3] = -1.0f;
                }

            }
            return positions;
        }

        /// <summary>
        /// Reset the layout state for drawing a new plot
        /// </summary>
        /// <param name="resetStyle">How to distribute the reset nodes</param>
        public void ResetPlot(GraphLayoutState.PositionResetStyle resetStyle)
        {
            LayoutState.Reset(resetStyle);
            BeginNewLayout();
        }

        /// <summary>
        /// Reset the layout tracking statistics and reset the temperature to a high value
        /// </summary>
        public void BeginNewLayout()
        {
            ResetLayoutStats();
            IncreaseTemperature(100f);
        }



        public uint LinearIndexTextureSize() { return indexTextureSize(_graphStructureLinear.Count); }
        public uint NestedIndexTextureSize() { return indexTextureSize(_graphStructureBalanced.Count); }

        public uint EdgeTextureWidth() { return dataTextureSize(countDataArrayItems(_graphStructureBalanced)); }
        public uint EdgeVertsTextureWidth() { return dataTextureSize(InternalProtoGraph.EdgeCount); }


        /// <summary>
        /// Get the colour of the node for the specified rendering style
        /// </summary>
        /// <param name="nodeIndex">Index of the node</param>
        /// <param name="renderingMode">Rendering style</param>
        /// <param name="themeGraphColours">Array of theme colours</param>
        /// <returns>The node colour</returns>
        public WritableRgbaFloat GetNodeColor(int nodeIndex, eRenderingMode renderingMode, WritableRgbaFloat[] themeGraphColours)
        {
            if (nodeIndex >= InternalProtoGraph.NodeList.Count)
            {
                return new WritableRgbaFloat(0, 0, 0, 0);
            }

            NodeData n = InternalProtoGraph.NodeList[nodeIndex];

            if (n.Highlighted)
            {
                return new WritableRgbaFloat(0, 1, 1, 1f);
            }
            switch (renderingMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    return themeGraphColours[(int)n.VertType()];
                case eRenderingMode.eHeatmap:
                    return new WritableRgbaFloat(1, 0, 0, 1);
                case eRenderingMode.eConditionals:
                    {
                        if (n.IsConditional is false)
                        { 
                            return new WritableRgbaFloat(0, 0, 0, 0.7f); 
                        }
                        else
                        {
                            if (n.conditional == ConditionalType.CONDCOMPLETE)
                                return new WritableRgbaFloat(1, 1, 1, .7f);
                            if (((int)n.conditional & (int)ConditionalType.CONDTAKEN) != 0)
                                return new WritableRgbaFloat(0, 1, 0, 0.7f);
                            if (((int)n.conditional & (int)ConditionalType.CONDFELLTHROUGH) != 0)
                                return new WritableRgbaFloat(1, 0, 0, 0.7f);
                        }
                        return new WritableRgbaFloat(Color.Yellow);
                    }
                default:
                    return themeGraphColours[(int)n.VertType()];
            }
        }


        /// <summary>
        /// Get the colour of this edge in the specified mode
        /// </summary>
        /// <param name="edge">The nodeIndex->nodeIndex description of the edge</param>
        /// <param name="renderingMode">The rendering mode</param>
        /// <returns>The colour of the edge</returns>
        public WritableRgbaFloat GetEdgeColor(Tuple<uint, uint> edge, eRenderingMode renderingMode)
        {

            if (!InternalProtoGraph.EdgeExists(edge, out EdgeData? e) || e is null)
            {
                return new WritableRgbaFloat(0f, 0f, 0f, 1);
            }

            switch (renderingMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    return graphColours[(int)e.edgeClass];
                case eRenderingMode.eHeatmap:
                    {
                        Debug.Assert(e.heatRank >= 0 && e.heatRank <= 9);
                        Themes.eThemeColour heatColEnum = (Themes.eThemeColour)((float)Themes.eThemeColour.eHeat0Lowest + e.heatRank);
                        return Themes.GetThemeColourWRF(heatColEnum);
                    }
                case eRenderingMode.eConditionals:
                    return new WritableRgbaFloat(0.8f, 0.8f, 0.8f, 1);

                case eRenderingMode.eDegree:
                    if (InternalProtoGraph.NodeList[(int)edge.Item1].IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                        return Themes.GetThemeColourWRF(Themes.eThemeColour.eGoodStateColour);

                    if (InternalProtoGraph.NodeList[(int)edge.Item1].OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                        return Themes.GetThemeColourWRF(Themes.eThemeColour.eGoodStateColour);

                    if (InternalProtoGraph.NodeList[(int)edge.Item2].IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                        return Themes.GetThemeColourWRF(Themes.eThemeColour.eGoodStateColour);

                    if (InternalProtoGraph.NodeList[(int)edge.Item2].OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                        return Themes.GetThemeColourWRF(Themes.eThemeColour.eGoodStateColour);

                    return Themes.GetThemeColourWRF(Themes.eThemeColour.eBadStateColour);
                default:
                    return graphColours[(int)e.edgeClass];
            }
        }


        Tuple<string?, uint> CreateNodeLabel(int index, eRenderingMode renderingMode, bool forceNew = false)
        {
            NodeData n = InternalProtoGraph.NodeList[index];
            if (n.Label == null || n.Dirty || forceNew)
            {
                n.CreateLabel(this);
            }

            if (n.IsExternal)
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.SymbolText));
            else if (n.HasSymbol)
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.InternalSymbol));
            else
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.InstructionText));
        }

        void RegenerateLabels() => _newLabels = true;
        bool _newLabels;

        eRenderingMode lastRenderingMode = eRenderingMode.eStandardControlFlow;
        /// <summary>
        /// Get the currently selected rendering mode of the graph (heatmap, etc)
        /// </summary>
        public eRenderingMode RenderingMode => lastRenderingMode;

        ulong lastThemeVersion = 0;

        //important todo - cacheing!  once the result is good
        /// <summary>
        /// Get the node drawing data for the preview version of this graph
        /// </summary>
        /// <param name="renderingMode">Rendering mode (heatmap, etc)</param>
        /// <param name="nodeIndices">Output node indexes</param>
        /// <param name="nodePickingColors">Output node mouse hover picking data</param>
        /// <param name="captions">Node caption texts</param>
        /// <returns>Node drawing data</returns>
        public Position2DColour[] GetMaingraphNodeVerts(eRenderingMode renderingMode,
            out List<uint> nodeIndices, out Position2DColour[] nodePickingColors, out List<Tuple<string?, uint>> captions)
        {
            bool createNewLabels = false;
            if (renderingMode != lastRenderingMode || _newLabels)
            {
                createNewLabels = true;
                _newLabels = false;
                lastRenderingMode = renderingMode;
            }

            //theme changed, read in new colours
            ulong themeVersion = Themes.ThemeVersion;
            bool newColours = lastThemeVersion < themeVersion;
            if (newColours)
            {
                InitGraphColours();
                lastThemeVersion = themeVersion;
            }

            uint textureSize = LinearIndexTextureSize();
            Position2DColour[] nodeVerts = new Position2DColour[textureSize * textureSize];

            nodePickingColors = new Position2DColour[textureSize * textureSize];
            captions = new List<Tuple<string?, uint>>();

            nodeIndices = new List<uint>();
            int nodeCount = RenderedNodeCount();


            WritableRgbaFloat[] graphColoursCopy;
            lock (textureLock)
            {
                graphColoursCopy = graphColours.ToArray();
            }

            for (uint index = 0; index < nodeCount; index++)
            {
                float x = index % textureSize;
                float y = index / textureSize;
                Vector2 texturePosition = new Vector2(x, y);

                if (index >= nodeCount || index >= InternalProtoGraph.NodeList.Count) return nodeVerts;

                nodeIndices.Add(index);

                WritableRgbaFloat nodeColour = GetNodeColor((int)index, renderingMode, graphColoursCopy);
                nodeVerts[index] = new Position2DColour
                {
                    Position = texturePosition,
                    Color = nodeColour
                };

                nodePickingColors[index] = new Position2DColour
                {
                    Position = texturePosition,
                    Color = new WritableRgbaFloat(index, 0, 0, 1)
                };

                if (Opt_TextEnabled)
                {
                    if (!IsAnimated || nodeColour.A > 0)
                    {
                        var caption = CreateNodeLabel((int)index, renderingMode, createNewLabels);
                        captions.Add(caption);
                    }
                }
            }
            return nodeVerts;
        }

        void InitGraphColours()
        {
            lock (textureLock)
            {
                graphColours = new WritableRgbaFloat[] {
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeCall),
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeOld),
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeRet),
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeLib),
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeNew),
                Themes.GetThemeColourWRF(Themes.eThemeColour.edgeExcept),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeStd),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeJump),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeCall),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeRet),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeExtern),
                Themes.GetThemeColourWRF(Themes.eThemeColour.nodeExcept)
                };
            };
        }



        /// <summary>
        /// Get the node drawing data for the preview version of this graph
        /// </summary>
        /// <param name="renderingMode">Rendering mode of the preview</param>
        /// <param name="nodeIndices">Output node index list</param>
        /// <returns>Node geometry array</returns>
        public Position2DColour[] GetPreviewgraphNodeVerts(eRenderingMode renderingMode, out List<uint> nodeIndices)
        {
            uint textureSize = LinearIndexTextureSize();
            Position2DColour[] NodeVerts = new Position2DColour[textureSize * textureSize];

            nodeIndices = new List<uint>();
            int nodeCount = RenderedNodeCount();

            WritableRgbaFloat[] graphColoursCopy;
            lock (textureLock)
            {
                graphColoursCopy = graphColours.ToArray();
            }

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
                        Color = GetNodeColor((int)index, renderingMode, graphColoursCopy)
                    };
                }
            }
            return NodeVerts;
        }



        /// <summary>
        /// Get the geometry and colour of every edge
        /// </summary>
        /// <param name="renderingMode">Rendering mode (standard, heatmap, etc)</param>
        /// <param name="edgeIndices">Output list of edge indexes for drawing</param>
        /// <param name="vertCount">Output number of edge vertics to draw</param>
        /// <param name="graphDrawnEdgeCount">The number of edges being drawn</param>
        /// <returns></returns>
        public Position2DColour[] GetEdgeLineVerts(eRenderingMode renderingMode,
            out List<uint> edgeIndices, out int vertCount, out int graphDrawnEdgeCount)
        {
            uint evTexWidth = EdgeVertsTextureWidth();
            Position2DColour[] EdgeLineVerts = new Position2DColour[evTexWidth * evTexWidth * 16];

            vertCount = 0;
            edgeIndices = new List<uint>();
            uint textureSize = LinearIndexTextureSize();

            var edgeList = InternalProtoGraph.GetEdgelistCopy();

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

        /// <summary>
        /// Size of data textures for compute shaders
        /// </summary>
        /// <param name="num">Node count</param>
        /// <returns>Texture size</returns>
        static uint dataTextureSize(int num)
        {
            return indexTextureSize((int)Math.Ceiling((double)num / 4.0));
        }


        static uint indexTextureSize(int nodesEdgesLength)
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
            int nodeCount = dataArray.Count;
            int counter = 0;
            for (var i = 0; i < nodeCount; i++)
            {
                counter += dataArray[i].Count;
            }
            return counter;
        }

        /// <summary>
        /// unused
        /// </summary>
        /// <param name="address">address</param>
        /// <param name="idx">index</param>
        protected void Add_to_callstack(ulong address, uint idx)
        {
            ThreadCallStack.Push(new Tuple<ulong, uint>(address, idx));
        }


        //node+edge col+pos
        bool get_block_nodelist(ulong blockAddr, long blockID, out List<uint>? newnodelist)
        {
            ProcessRecord piddata = InternalProtoGraph.ProcessData;
            ROUTINE_STRUCT? externBlock = new ROUTINE_STRUCT();
            List<InstructionData>? block = piddata.getDisassemblyBlock((uint)blockID, ref externBlock, blockAddr);
            if (block == null && externBlock == null)
            {
                newnodelist = null;
                return false;
            }
            //if (internalProtoGraph.terminationFlag) return false;

            if (externBlock != null)
            {
                bool found = false;
                List<Tuple<uint, uint>>? calls = null;
                while (!found)
                {
                    lock (piddata.ExternCallerLock)
                    {
                        if (externBlock.Value.ThreadCallers == null)
                        {
                            Console.WriteLine($"Error: Extern block thread_callers was null [block 0x{blockAddr:x}]");
                        }
                        else
                        {
                            found = externBlock.Value.ThreadCallers.TryGetValue(TID, out calls);
                        }
                    }
                    if (found) break;
                    Thread.Sleep(200);
                    if (rgatState.ExitToken.IsCancellationRequested)
                    {
                        newnodelist = null;
                        return false;
                    }
                    Console.WriteLine($"[rgat]get_block_nodelist() Fail to find edge for thread {TID} calling extern 0x{blockAddr:x}");
                }



                newnodelist = new List<uint>();
                if (calls is not null)
                {
                    foreach (Tuple<uint, uint> edge in calls) //record each call by caller
                    {
                        if (edge.Item1 == LastAnimatedVert)
                        {
                            newnodelist.Add(edge.Item2);
                        }
                    }
                }

                return true;
            }


            newnodelist = new List<uint>();
            if (block is null) return false;

            lock (InternalProtoGraph.TraceData.DisassemblyData.InstructionsLock)
            {
                foreach (InstructionData ins in block)
                {
                    if (!ins.GetThreadVert(TID, out uint val)) return false;
                    newnodelist.Add(val);
                }
            }

            return true;
        }


        void brighten_next_block_edge(uint blockID, ulong blockAddress)
        {
            ROUTINE_STRUCT? externStr = null;
            List<InstructionData>? nextBlock = InternalProtoGraph.ProcessData.getDisassemblyBlock(blockID, ref externStr, blockAddress);
            if (nextBlock is null) return;

            Tuple<uint, uint>? LinkingPair = null;
            if (externStr != null)
            {
                var callers = externStr.Value.ThreadCallers[InternalProtoGraph.ThreadID];
                var caller = callers.Find(n => n.Item2 == LastAnimatedVert);
                if (caller == null) return;

                uint callerIdx = caller.Item2;
                LinkingPair = new Tuple<uint, uint>(LastAnimatedVert, callerIdx);


            }
            else
            {
                //find vert in internal code
                InstructionData nextIns = nextBlock[0];
                if (nextIns.GetThreadVert(InternalProtoGraph.ThreadID, out uint caller))
                {
                    LinkingPair = new Tuple<uint, uint>(LastAnimatedVert, caller);
                }
                else return;
            }

            /*
            if it doesn't exist then assume it's because the user is skipping around the animation with the slider
            (there are other reasons but it helps me sleep at night)
            */
            if (InternalProtoGraph.EdgeExists(LinkingPair))
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
                if (Opt_TextEnabledLive && listOffset == 0 && InternalProtoGraph.GetNode(nodeIdx)!.HasSymbol)
                {
                    AddRisingSymbol(nodeIdx, (int)entry.count - 1, brightTime);
                }

                if (!(entry.entryType == eTraceUpdateType.eAnimUnchained) && listOffset == 0)
                {
                    Tuple<uint, uint> edge = new Tuple<uint, uint>(LastAnimatedVert, nodeIdx);
                    if (InternalProtoGraph.EdgeExists(edge))
                    {
                        AddPulseActiveNode(edge.Item1);
                    }
                    //if it doesn't exist it may be because user is skipping code with animation slider
                }

                if (brightTime == (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT)
                {
                    AddContinuousActiveNode(nodeIdx);
                }
                else
                {
                    AddPulseActiveNode(nodeIdx);
                }

                LastAnimatedVert = nodeIdx;

                ++listOffset;
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (listOffset == (entry.count + 1))) break;

            }
        }


        void end_unchained(ANIMATIONENTRY entry)
        {

            remove_unchained_from_animation();
            List<InstructionData>? firstChainedBlock = InternalProtoGraph.ProcessData.getDisassemblyBlock(entry.blockID);
            uint vertID = 0;
            bool found = firstChainedBlock is not null && firstChainedBlock[^1].GetThreadVert(TID, out vertID);
            Debug.Assert(found);
            LastAnimatedVert = vertID; //should this be front()?
        }


        /// <summary>
        /// Process more animation updates from a live trace
        /// </summary>
        public void ProcessLiveAnimationUpdates()
        {
            //too many updates at a time damages interactivity
            //too few creates big backlogs which delays the animation (can still see realtime in static mode though)
            int updateLimit = GlobalConfig.LiveAnimationUpdatesPerFrame;
            while (updateProcessingIndex < InternalProtoGraph.SavedAnimationData.Count && (updateLimit-- > 0))
            {
                if (!process_live_update()) break;
            }

        }


        //return false if we need more trace data to do further updates
        bool process_live_update()
        {
            if (InternalProtoGraph.HasRecentStep) return false;

            //todo: eliminate need for competing with the trace handler for the lock using spsc ringbuffer
            //internalProtoGraph.animationListsRWLOCK_.lock_shared();
            ANIMATIONENTRY entry = InternalProtoGraph.SavedAnimationData[updateProcessingIndex];
            //internalProtoGraph.animationListsRWLOCK_.unlock_shared();

            /*
            if (entry.entryType == eTraceUpdateType.eAnimLoopLast)
            {
                Console.WriteLine("Live update: eAnimLoopLast");
                ++updateProcessingIndex;
                return true;
            }*/

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                Logging.RecordLogEvent($"Live update: eAnimUnchainedResults. Block {entry.blockID} executed {entry.count} times",
                    Logging.LogFilterType.BulkDebugLogFile);
                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimReinstrument)
            {
                Logging.RecordLogEvent($"Live update: eAnimReinstrument.", Logging.LogFilterType.BulkDebugLogFile);
                end_unchained(entry);
                ++updateProcessingIndex;
                return true;
            }

            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                string s = "";
                if (get_block_nodelist(0, entry.blockID, out List<uint>? nodeIDListUC) && nodeIDListUC is not null)
                {
                    foreach (int x in nodeIDListUC) s += $"{x},";
                }

                Logging.RecordLogEvent($"Live update: eAnimUnchained block {entry.blockID}: " + s, Logging.LogFilterType.BulkDebugLogFile);
                brightTime = (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT;
            }
            else
                brightTime = GlobalConfig.ExternAnimDisplayFrames;

            //break if block not rendered yet
            if (!get_block_nodelist(entry.blockAddr, entry.blockID, out List<uint>? nodeIDList) || nodeIDList is null)
            {
                //expect to get an incomplete block with exception or animation attempt before static rendering
                if ((entry.entryType == eTraceUpdateType.eAnimExecException))// && (nodeIDList.Count > (int)entry.count))
                    return true;
                return false;
            }

            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            //also add brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
                brighten_next_block_edge(entry.blockID, entry.blockAddr);

            ++updateProcessingIndex;
            return true;
        }


        void process_replay_animation_updates(double optionalStepSize = 0)
        {
            if (InternalProtoGraph.SavedAnimationData.Count == 0)
            {
                Console.WriteLine("Ending animation immediately - no animation data");
                ReplayState = REPLAY_STATE.Ended;
                return;
            }

            double stepSize;
            if (optionalStepSize != 0)
            {
                stepSize = optionalStepSize;
            }
            else
            {
                stepSize = (ReplayState != REPLAY_STATE.Paused) ? AnimationRate : 0;
            }

            double targetAnimIndex = AnimationIndex + stepSize;
            if (targetAnimIndex >= InternalProtoGraph.SavedAnimationData.Count)
                targetAnimIndex = InternalProtoGraph.SavedAnimationData.Count - 1;

            for (; AnimationIndex < targetAnimIndex; AnimationIndex += stepSize)
            {
                Console.WriteLine($"Anim Step {AnimationIndex}");
                int actualIndex = (int)Math.Floor(AnimationIndex);


                if (actualIndex > _lastReplayedIndex)
                {
                    for (var innerReplayIdx = _lastReplayedIndex + 1; innerReplayIdx < actualIndex + 1; innerReplayIdx += 1)
                    {
                        process_replay_update(innerReplayIdx);
                    }
                    _lastReplayedIndex = actualIndex;
                }
            }

            if (AnimationIndex >= InternalProtoGraph.SavedAnimationData.Count - 1)
            {
                ReplayState = REPLAY_STATE.Ended;
            }
        }

        int _lastReplayedIndex = -1;


        void process_replay_update(int replayUpdateIndex)
        {
            bool verbose = true;
            ANIMATIONENTRY entry = InternalProtoGraph.SavedAnimationData[replayUpdateIndex];

            double stepSize = AnimationRate;
            if (stepSize < 1) stepSize = 1;

            //brighten edge between last block and this
            //todo - probably other situations we want to do this apart from a parent exec tag
            if (replayUpdateIndex > 0)
            {
                ANIMATIONENTRY lastentry = InternalProtoGraph.SavedAnimationData[replayUpdateIndex - 1];
                if (lastentry.entryType == eTraceUpdateType.eAnimExecTag)
                {
                    if (verbose) Console.WriteLine($"\tLast entry was block exec - brighten edge to block address 0x{entry.blockAddr:x} ");
                    brighten_next_block_edge(entry.blockID, entry.blockAddr);
                }
            }

            //unchained area finished, stop highlighting it
            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                ProcessRecord piddata = InternalProtoGraph.ProcessData;
                List<InstructionData>? block = piddata.getDisassemblyBlock(entry.blockID);
                Debug.Assert(block is not null);
                unchainedWaitFrames += calculate_wait_frames(entry.count * (ulong)block.Count);

                uint maxWait = (uint)Math.Floor((double)maxWaitFrames / stepSize); //todo test
                if (unchainedWaitFrames > maxWait)
                    unchainedWaitFrames = maxWait;

                if (verbose) Console.WriteLine($"\tUpdate eAnimUnchainedResults block 0x{entry.blockAddr:x} ");


                remove_unchained_from_animation();


                return;
            }

            //all consecutive unchained areas finished, wait until animation paused appropriate frames
            if (entry.entryType == eTraceUpdateType.eAnimReinstrument)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimReinstrument");
                //if (unchainedWaitFrames-- > 1) return;

                remove_unchained_from_animation();
                end_unchained(entry);
                return;
            }


            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained || animBuildingLoop)
            {
                if (verbose) Console.WriteLine($"\tUpdate Replay eAnimUnchained/buildingloop");
                brightTime = (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT;
            }
            else
            {
                brightTime = GlobalConfig.animationLingerFrames;
            }



            if (!get_block_nodelist(entry.blockAddr, (long)entry.blockID, out List<uint>? nodeIDList) &&
                entry.entryType != eTraceUpdateType.eAnimExecException)
            {
                Thread.Sleep(5);
                while (!get_block_nodelist(entry.blockAddr, (long)entry.blockID, out nodeIDList))
                {
                    Thread.Sleep(15);
                    Console.WriteLine($"[rgat] process_replay_update waiting for block 0x{entry.blockAddr:x}");
                    if (rgatState.rgatIsExiting) return;
                }
            }

            Console.WriteLine($"Trace type {entry.entryType} brightening nodes {String.Join(",", nodeIDList.Select(x => x.ToString()))} for time {brightTime}");
            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                if (verbose) Console.WriteLine($"\tUpdate eAnimUnchained");
                brighten_next_block_edge(entry.targetID, entry.targetAddr);
            }

        }


        /*
         Nodes that are continuously lit up due to being blocked or in a busy (unchained) loop
         These pulse
         */
        ulong calculate_wait_frames(ulong executions)
        {
            //assume 10 instructions per step/frame
            ulong stepSize = (ulong)AnimationRate;
            if (stepSize == 0) stepSize = 1;
            ulong frames = (InternalProtoGraph.TotalInstructions / Anim_Constants.ASSUME_INS_PER_BLOCK) / stepSize;

            float proportion = (float)executions / InternalProtoGraph.TotalInstructions;
            ulong waitFrames = (ulong)Math.Floor(proportion * frames);
            return waitFrames;
        }

        /// <summary>
        /// Action the movement of the mousewheel to zoom the graph in or out
        /// </summary>
        /// <param name="delta">How far the mousewheel moved</param>
        public void ApplyMouseWheelDelta(float delta)
        {
            CameraZoom += delta * 120;
        }


        /// <summary>
        /// Move the camera in response to user mouse dragging
        /// </summary>
        /// <param name="delta">How far the mouse was dragged</param>
        public void ApplyMouseDragDelta(Vector2 delta)
        {
            CameraXOffset -= delta.X;
            CameraYOffset += delta.Y;
        }


        /// <summary>
        /// Get the projection matrix of the current camera
        /// </summary>
        /// <param name="aspectRatio">Aspect Ratio</param>
        /// <returns></returns>
        public Matrix4x4 GetProjectionMatrix(float aspectRatio)
        {
            return Matrix4x4.CreatePerspectiveFieldOfView(CameraFieldOfView, aspectRatio, CameraClippingNear, CameraClippingFar);
        }

        /// <summary>
        /// Get the view matrix of the current camera position
        /// </summary>
        /// <returns>View Matrix</returns>
        public Matrix4x4 GetViewMatrix()
        {
            Vector3 translation = new Vector3(CameraXOffset, CameraYOffset, CameraZoom);
            Matrix4x4 viewMatrix = Matrix4x4.CreateTranslation(translation);
            viewMatrix = Matrix4x4.Multiply(viewMatrix, RotationMatrix);
            return viewMatrix;
        }

        /// <summary>
        /// Get the view matrix of the preview camera
        /// </summary>
        /// <returns>View Matrix</returns>
        public Matrix4x4 GetPreviewViewMatrix()
        {
            Vector3 translation = new Vector3(PreviewCameraXOffset, PreviewCameraYOffset, PreviewCameraZoom);
            Matrix4x4 viewMatrix = Matrix4x4.CreateTranslation(translation);
            viewMatrix = Matrix4x4.Multiply(viewMatrix, RotationMatrix);
            return viewMatrix;
        }


        /// <summary>
        /// Create a new preview texture for the graph
        /// </summary>
        /// <param name="size">Size of the texture</param>
        /// <param name="gd">GraphicsDevice for to create the texture on</param>
        public void InitPreviewTexture(Vector2 size, GraphicsDevice gd)
        {
            if (_previewTexture1 != null)
            {
                if (_previewTexture1.Width == size.X && _previewTexture1.Height == size.Y)
                {
                    return;
                }
                _previewFramebuffer1?.Dispose();
                _previewTexture1.Dispose();
                _previewFramebuffer2?.Dispose();
                _previewTexture2.Dispose();
            }

            _previewTexture1 = gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                                width: (uint)size.X, height: (uint)size.Y, mipLevels: 1, arrayLayers: 1,
                                format: PixelFormat.R32_G32_B32_A32_Float, usage: TextureUsage.RenderTarget | TextureUsage.Sampled));
            _previewFramebuffer1 = gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _previewTexture1));
            _previewTexture2 = gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                                width: (uint)size.X, height: (uint)size.Y, mipLevels: 1, arrayLayers: 1,
                                format: PixelFormat.R32_G32_B32_A32_Float, usage: TextureUsage.RenderTarget | TextureUsage.Sampled));
            _previewFramebuffer2 = gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _previewTexture2));
        }


        /// <summary>
        /// Add new edges to the layout buffer
        /// Must have upgradable read lock
        /// </summary>
        /// <param name="edgesCount"></param>
        public void AddNewEdgesToLayoutBuffers(int edgesCount)
        {
            if (edgesCount > RenderedEdgeCount || (new Random()).Next(0, 100) == 1) //todo this is a hack from when things were less reliable. disable and look for issues
            {
                LayoutState.Lock.EnterWriteLock();
                LayoutState.RegenerateEdgeDataBuffers(this);
                RenderedEdgeCount = (uint)edgesCount;
                LayoutState.Lock.ExitWriteLock();
            }

            int graphNodeCount = RenderedNodeCount();
            if (ComputeBufferNodeCount < graphNodeCount)
            {
                LayoutState.AddNewNodesToComputeBuffers(graphNodeCount, this);

                LayoutState.Lock.EnterWriteLock();
                LayoutState.RegenerateEdgeDataBuffers(this); //tod change to upgradread
                LayoutState.Lock.ExitWriteLock();
            }

        }


        /// <summary>
        /// Signals that the user has changed the highlighted nodes
        /// </summary>
        public bool HighlightsChanged;

        readonly Dictionary<int, Vector4> _customHighlightColours = new Dictionary<int, Vector4>();
        /// <summary>
        /// Get the highlight colour of the node
        /// </summary>
        /// <param name="nodeIdx">Index of the node</param>
        /// <returns>Colour of the node, if a custom colour was found, otherwise null</returns>
        public Vector4? GetCustomHighlightColour(int nodeIdx)
        {
            lock (textLock)
            {
                if (_customHighlightColours.TryGetValue(nodeIdx, out Vector4 col)) return col;
                return null;
            }
        }


        /// <summary>
        /// Set a custom colour for the specified node
        /// </summary>
        /// <param name="nodeIdx">Index of the node</param>
        /// <param name="colour">Custom colour</param>
        public void SetCustomHighlightColour(int nodeIdx, Vector4 colour)
        {
            lock (textLock)
            {
                _customHighlightColours[nodeIdx] = colour;
            }
        }


        /// <summary>
        /// Set the list of nodes as highlighted
        /// must hold read lock
        /// </summary>
        /// <param name="newnodeidxs">Nodes to highlight</param>
        /// <param name="highlightType">Type of highlight</param>
        public void AddHighlightedNodes(List<uint> newnodeidxs, HighlightType highlightType)
        {
            lock (textLock)
            {
                switch (highlightType)
                {
                    case HighlightType.Externals:
                        HighlightedSymbolNodes.AddRange(newnodeidxs.Where(n => !HighlightedSymbolNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    case HighlightType.Addresses:
                        HighlightedAddressNodes.AddRange(newnodeidxs.Where(n => !HighlightedAddressNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    case HighlightType.Exceptions:
                        HighlightedExceptionNodes.AddRange(newnodeidxs.Where(n => !HighlightedExceptionNodes.Contains(n)));
                        AllHighlightedNodes.AddRange(newnodeidxs.Where(n => !AllHighlightedNodes.Contains(n)));
                        break;
                    default:
                        Console.WriteLine($"Error: Unknown highlight type: {highlightType}");
                        break;
                }

                foreach (uint nidx in newnodeidxs)
                {
                    InternalProtoGraph.GetNode(nidx)?.SetHighlighted(true);
                    DeletedHighlights.RemoveAll(x => x == nidx);
                }

                NewHighlights.AddRange(newnodeidxs);
                HighlightsChanged = true;
            }
        }

        public long lastRenderTime;
        public uint RenderedEdgeCount; //todo - this is really all we need

        int _computeBufferNodeCount; //this is gross and temporary
        public int ComputeBufferNodeCount
        {
            get => _computeBufferNodeCount;
            set => _computeBufferNodeCount = value;
        }

        //must hold read lock
        public void RemoveHighlightedNodes(List<uint> nodeidxs, float[]? attribsArray, HighlightType highlightType)
        {
            if (attribsArray is null) return;

            List<uint> removedNodes = new List<uint>();
            List<uint> remainingNodes = new List<uint>();
            lock (textLock)
            {
                switch (highlightType)
                {
                    case HighlightType.Externals:
                        HighlightedSymbolNodes = HighlightedSymbolNodes.Except(nodeidxs).ToList();
                        break;
                    case HighlightType.Addresses:
                        HighlightedAddressNodes = HighlightedAddressNodes.Except(nodeidxs).ToList();
                        break;
                    case HighlightType.Exceptions:
                        HighlightedExceptionNodes = HighlightedExceptionNodes.Except(nodeidxs).ToList();
                        break;
                }

                AllHighlightedNodes.Clear();
                AllHighlightedNodes.AddRange(HighlightedSymbolNodes);
                AllHighlightedNodes.AddRange(HighlightedAddressNodes.Where(n => !AllHighlightedNodes.Contains(n)));
                AllHighlightedNodes.AddRange(HighlightedExceptionNodes.Where(n => !AllHighlightedNodes.Contains(n)));
                foreach (uint nidx in nodeidxs)
                {
                    InternalProtoGraph.GetNode(nidx)?.SetHighlighted(false);
                    NewHighlights.RemoveAll(x => x == nidx);
                }
                DeletedHighlights.AddRange(nodeidxs);
            }

            HighlightsChanged = true;
        }

        /// <summary>
        /// Set an address as highlighted on the graph plot
        /// </summary>
        /// <param name="address">The address to highlight</param>
        public void AddHighlightedAddress(ulong address)
        {
            lock (textLock)
            {
                if (!HighlightedAddresses.Contains(address))
                {
                    HighlightedAddresses.Add(address);

                    List<uint> nodes = InternalProtoGraph.ProcessData.GetNodesAtAddress(address, TID);  //todo: external
                    AddHighlightedNodes(nodes, HighlightType.Addresses);
                }
            }
        }

        public void GetHighlightChanges(out List<uint> added, out List<uint> removed)
        {
            lock (textLock)
            {
                added = NewHighlights.ToList();
                NewHighlights.Clear();
                removed = DeletedHighlights.ToList();
                DeletedHighlights.Clear();
                HighlightsChanged = false;
            }
        }


        /// <summary>
        /// Get the indexes of any nodes that have > minimum alpha in animated mode
        /// Pulsed and deactivated nodes will only be fetched once by this call, the rest is handled by the attributes shader
        /// </summary>
        /// <param name="pulseNodes">Nodes which have been temporarily pulsed</param>
        /// <param name="lingerNodes">Nodes which remain brightened until cleared</param>
        /// <param name="deactivatedNodes">Nodes which are no longer active and faded to the base alpha, ready to be cleared from the active list</param>
        public void GetActiveNodeIndexes(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes)
        {
            lock (animationLock)
            {
                pulseNodes = _PulseActiveNodes.ToList();
                _PulseActiveNodes.Clear();

                lingerNodes = _LingeringActiveNodes.ToList();

                deactivatedNodes = _DeactivatedNodes.ToArray();
                _DeactivatedNodes.Clear();
            }
        }


        public void GetActiveExternRisings(out List<Tuple<uint, string>> risingExterns, out List<Tuple<uint, string>> risingLingering)
        {
            lock (animationLock)
            {
                risingExterns = _RisingSymbols.ToList();
                _RisingSymbols.Clear();

                risingLingering = _RisingSymbolsLingering.ToList();
            }
        }


        int _furthestNodeIdx = -1;
        float _furthestNodeDimension = 0;
        /// <summary>
        /// Sets the coordinate of the furthest node from the origin
        /// Used for drawing the force directed layout wireframe, where the distance of this node from the origin is used as the radius
        /// </summary>
        /// <param name="index">Index of the far node</param>
        /// <param name="farDimension">Greatest (absolute) coordinate of any node</param>
        public void SetFurthestNodeDimension(int index, float farDimension)
        {
            _furthestNodeIdx = index;
            _furthestNodeDimension = farDimension;
        }


        public void AddRisingSymbol(uint nodeIdx, int callIndex, int lingerFrames)
        {
            NodeData? n = InternalProtoGraph.GetNode(nodeIdx);
            Debug.Assert(n is not null);
            if (n.Label is null)
            {
                n.CreateLabel(this, callIndex);
                if (n.Label is null) return;
            }
            lock (animationLock)
            {
                if (lingerFrames == (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT)
                {
                    _RisingSymbolsLingering.Add(new Tuple<uint, string>(nodeIdx, n.Label));
                }
                else
                {
                    _RisingSymbols.Add(new Tuple<uint, string>(nodeIdx, n.Label));
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
            lock (animationLock)
            {
                _LingeringActiveNodes.RemoveAll(n => n == nodeIdx);
            }
        }

        void remove_unchained_from_animation()
        {
            lock (animationLock)
            {
                _DeactivatedNodes.AddRange(_LingeringActiveNodes);
                _LingeringActiveNodes.Clear();
                _RisingSymbolsLingering.Clear();
            }
        }

        void ResetAllActiveAnimatedAlphas()
        {
            lock (animationLock)
            {
                _PulseActiveNodes.Clear();
                _LingeringActiveNodes.Clear();
                _DeactivatedNodes.Clear();
            }
        }


        /// <summary>
        /// Change the layout of the graph
        /// </summary>
        /// <param name="newStyle">The style to change it to</param>
        /// <returns></returns>
        public bool SetLayout(LayoutStyles.Style newStyle)
        {
            if (newStyle == ActiveLayoutStyle) return false;
            LayoutState.TriggerLayoutChange(newStyle);
            return true;
        }

        /// <summary>
        /// Indexes of highlighted symbol nodes
        /// </summary>
        public List<uint> HighlightedSymbolNodes = new List<uint>();
        /// <summary>
        /// Indexes of highlighted address nodes
        /// </summary>
        public List<uint> HighlightedAddressNodes = new List<uint>();
        /// <summary>
        /// Highlighted addresses
        /// </summary>
        public List<ulong> HighlightedAddresses = new List<ulong>();
        /// <summary>
        /// Indexes of highlighted exception nodes
        /// </summary>
        public List<uint> HighlightedExceptionNodes = new List<uint>();
        /// <summary>
        /// Indexes of all highlighted nodes
        /// </summary>
        public List<uint> AllHighlightedNodes = new List<uint>();
        /// <summary>
        /// Indexes of nodes to have their highlight removed by the layout engine
        /// </summary>
        public List<uint> DeletedHighlights = new List<uint>();
        /// <summary>
        /// Indexes of nodes which need highlight adding by the layout engine
        /// </summary>
        public List<uint> NewHighlights = new List<uint>();

        bool animBuildingLoop = false;

        /// <summary>
        /// The graph is in an animated (running or replay) state
        /// </summary>
        public bool IsAnimated { get; private set; } = false;
        /// <summary>
        /// Nodes are being drawn
        /// </summary>
        public bool Opt_NodesVisible { get; set; } = true;
        /// <summary>
        /// Edges are being drawn
        /// </summary>
        public bool Opt_EdgesVisible { get; set; } = true;

        bool _textEnabled = true;
        /// <summary>
        /// Text is being drawn
        /// </summary>
        public bool Opt_TextEnabled
        {
            get => _textEnabled;
            set
            {
                _textEnabled = value;
                if (_textEnabled) RegenerateLabels();
            }
        }

        bool _textEnabledIns = true;
        /// <summary>
        /// Instruction text is being drawn
        /// </summary>
        public bool Opt_TextEnabledIns
        {
            get => _textEnabledIns;
            set
            {
                _textEnabledIns = value;
                RegenerateLabels();
            }
        }

        bool _textEnabledSym = true;
        /// <summary>
        /// Symbol text is being drawn
        /// </summary>
        public bool Opt_TextEnabledSym
        {
            get => _textEnabledSym;
            set
            {
                _textEnabledSym = value;
                RegenerateLabels();
            }
        }

        bool _showNodeAdresses = true;
        /// <summary>
        /// The addresses of nodes are added to their label
        /// </summary>
        public bool Opt_ShowNodeAddresses
        {
            get => _showNodeAdresses;
            set
            {
                _showNodeAdresses = value;
                RegenerateLabels();
            }
        }

        bool _showNodeIndexes = true;
        /// <summary>
        /// Whether node labels will include the internal index of the node
        /// </summary>
        public bool Opt_ShowNodeIndexes
        {
            get => _showNodeIndexes;
            set
            {
                _showNodeIndexes = value;
                RegenerateLabels();
            }
        }

        bool _showSymbolModules = true;
        /// <summary>
        /// Whether symbols will show the modules they reside in
        /// </summary>
        public bool Opt_ShowSymbolModules
        {
            get => _showSymbolModules;
            set
            {
                _showSymbolModules = value;
                RegenerateLabels();
            }
        }

        bool _showSymbolModulePaths = true;
        /// <summary>
        /// Whether symbol labels include the full path of the module
        /// </summary>
        public bool Opt_ShowSymbolModulePaths
        {
            get => _showSymbolModulePaths;
            set
            {
                _showSymbolModulePaths = value;
                RegenerateLabels();
            }
        }

        /// <summary>
        /// Enable animated live instruction text
        /// </summary>
        public bool Opt_TextEnabledLive { get; set; } = true;
        /// <summary>
        /// Enable an illustration edge that points to the most recently animated instruction
        /// </summary>
        public bool Opt_LiveNodeEdgeEnabled { get; set; } = true;

        /// <summary>
        /// Estimated world space coordinates for the top left and right of the screen
        /// </summary>
        Vector3 _unprojWorldCoordTL, _unprojWorldCoordBR;


        /// <summary>
        /// Gather values for calculating the camera indicator box in the preview window
        /// </summary>
        /// <param name="graphWidgetSize">Size of the main graph widget</param> // weird parameter?
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

        /// <summary>
        /// Use the values from UpdatePreviewVisibleRegion to work out where to draw the preview camera box
        /// </summary>
        /// <param name="PrevWidgetSize">Size of the preview pane box for the graph</param>
        /// <param name="previewProjection">Projection matrix for the preview graph</param>
        /// <param name="TopLeft">Top left value for the camera</param>
        /// <param name="BaseRight">Base right value for the camera</param>
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
         * I'm not good enough at graphics to work out how far to move the camera in one click. Instead move towards the click location
         * In a few frames it will get there.
         */
        /// <summary>
        /// Move the camera in the main graph widget towards the location clicked in the preview graph widget
        /// </summary>
        /// <param name="pos">Click position</param>
        /// <param name="previewSize">Size of the graph in the preview pane</param>
        /// <param name="mainGraphWidgetSize">Size of the graph in the main pane</param>
        /// <param name="previewProjection">Projection matrix for the preview graph</param>
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

        /// <summary>
        /// This was used to render call/returns in the graph layout
        /// Currently unimplemented but keeping it around
        /// </summary>
        protected Stack<Tuple<ulong, uint>> ThreadCallStack = new Stack<Tuple<ulong, uint>>();

        /// <summary>
        /// The main 'graph' datastore
        /// Stores both the raw trace data for the graph and the processed connections between instructions
        /// The data can be used to plot graphical layouts
        /// </summary>
        public ProtoGraph InternalProtoGraph { get; protected set; }

        /// <summary>
        /// A cache of graph geometry colours for different types of node/edge
        /// </summary>
        protected WritableRgbaFloat[] graphColours;

        /// <summary>
        /// The current layout format of the graph
        /// </summary>
        public LayoutStyles.Style ActiveLayoutStyle => LayoutState.Style;
        /// <summary>
        /// The actual store of graphical data for the graph layout
        /// </summary>
        public GraphLayoutState LayoutState;


        readonly ReaderWriterLockSlim textureLock = new ReaderWriterLockSlim();
        Veldrid.Texture _previewTexture1, _previewTexture2;
        /// <summary>
        /// Framebuffers for the preview texture
        /// </summary>
        public Veldrid.Framebuffer? _previewFramebuffer1, _previewFramebuffer2;

        int latestWrittenTexture = 1;
        /// <summary>
        /// Get the preview framebuffer that is currently being written to for writing
        /// </summary>
        /// <param name="drawtarget">output buffer</param>
        public void GetPreviewFramebuffer(out Framebuffer drawtarget)
        {
            textureLock.EnterWriteLock(); //why write lock?
            if (latestWrittenTexture == 1)
            {
                drawtarget = _previewFramebuffer2!;
            }
            else
            {
                drawtarget = _previewFramebuffer1!;
            }
            textureLock.ExitWriteLock();
        }

        /// <summary>
        /// The framebuffer has been written. Swap it with the other one.
        /// </summary>
        public void ReleasePreviewFramebuffer()
        {
            textureLock.EnterWriteLock();
            latestWrittenTexture = latestWrittenTexture == 1 ? 2 : 1;
            textureLock.ExitWriteLock();
        }

        /// <summary>
        /// Get the main graph texture that is not currently being written to for reading
        /// </summary>
        /// <param name="graphtexture"></param>
        public void GetLatestTexture(out Texture graphtexture)
        {
            textureLock.EnterReadLock();
            if (latestWrittenTexture == 1)
            {
                graphtexture = _previewTexture1;
            }
            else
            {
                graphtexture = _previewTexture2;
            }
            textureLock.ExitReadLock();
        }


        /// <summary>
        /// Update the graph computation time stats
        /// </summary>
        /// <param name="ms">Time taken for the latest round of velocity/position computation in Milliseconds</param>
        public void RecordComputeTime(long ms)
        {
            ComputeLayoutTime += ms;
            ComputeLayoutSteps += 1;
        }

        /// <summary>
        /// Reset the tracking info for layout time/steps
        /// </summary>
        public void ResetLayoutStats()
        {
            ComputeLayoutTime = 0;
            ComputeLayoutSteps = 0;
        }

        /// <summary>
        /// How many MS were spent in compute shaders for this layout
        /// </summary>
        public long ComputeLayoutTime = 0;
        /// <summary>
        /// How many rounds of computation were completed for this layout
        /// </summary>
        public long ComputeLayoutSteps = 0;

        /// <summary>
        /// The current main camera zoom
        /// </summary>
        public float CameraZoom = -5000;
        /// <summary>
        /// Main camera X offset
        /// </summary>
        public float CameraXOffset = 0f;
        /// <summary>
        /// Main camera Y offset
        /// </summary>
        public float CameraYOffset = 0f;

        /// <summary>
        /// The currentt preview camera zoom
        /// </summary>
        public float PreviewCameraXOffset = 0f;
        /// <summary>
        /// The current preview camera X offset
        /// </summary>
        public float PreviewCameraYOffset = 0f;
        /// <summary>
        /// The current preview camera Y offset
        /// </summary>
        public float PreviewCameraZoom = -4000;
        /// <summary>
        /// Field of view value for the main camera
        /// </summary>
        public float CameraFieldOfView = 0.6f;
        /// <summary>
        /// Far clippling limit for the main camera
        /// </summary>
        public float CameraClippingFar = 60000;
        /// <summary>
        /// Near clipping limit for the main camera
        /// </summary>
        public float CameraClippingNear = 1;
        /// <summary>
        /// Rotation matrix for the main camera
        /// </summary>
        public Matrix4x4 RotationMatrix = Matrix4x4.Identity;
        /// <summary>
        /// Process ID of this graph
        /// </summary>
        public uint PID => InternalProtoGraph.TraceData.PID;
        /// <summary>
        /// Thread ID of this graph
        /// </summary>
        public uint TID => InternalProtoGraph.ThreadID;
        /// <summary>
        /// How many trace items are processed per animation replay step
        /// </summary>
        public float AnimationRate { get; set; } = 1;

        /// <summary>
        /// This used to add some delay for unchained areas. Unused at the moment but keeping it around
        /// </summary>
        ulong unchainedWaitFrames = 0;
        readonly uint maxWaitFrames = 20; //limit how long we spend 'executing' busy code in replays

        /// <summary>
        /// Which trace record item the animation is running in
        /// </summary>
        public double AnimationIndex { get; private set; }

        readonly List<uint> _PulseActiveNodes = new List<uint>();
        readonly List<uint> _LingeringActiveNodes = new List<uint>();
        readonly List<Tuple<uint, string>> _RisingSymbols = new List<Tuple<uint, string>>();
        readonly List<Tuple<uint, string>> _RisingSymbolsLingering = new List<Tuple<uint, string>>();
        readonly List<uint> _DeactivatedNodes = new List<uint>();// Array.Empty<uint>();
        private readonly object animationLock = new object();

        /// <summary>
        /// A custom animation position set by the user clicking the replay bar
        /// </summary>
        public int _userSelectedAnimPosition = -1;

        /// <summary>
        /// Animation replay state
        /// </summary>
        public REPLAY_STATE ReplayState = REPLAY_STATE.Ended;
        int updateProcessingIndex = 0;

        /// <summary>
        /// main lock for access to this objects data
        /// </summary>
        protected readonly Object textLock = new Object();

        /// <summary>
        /// Number of nodes recorded in this threads trace
        /// </summary>
        /// <returns>Number of nodes</returns>
        public int GraphNodeCount() { return InternalProtoGraph.NodeList.Count; }
        /// <summary>
        /// Number of nodes drawn on this graph
        /// </summary>
        /// <returns>Number of nodes</returns>
        public int RenderedNodeCount() { return _graphStructureLinear.Count; }

        /*
        Linear   "[[1,4,5,6,7],[0,2,3,8,9],[1],[1],[0],[0],[0],[0],[1],[1]]";
        Balanced "[[1],        [0],        [1],[1],[0],[0],[0],[0],[1],[1]]";
         */
        /// <summary>
        /// The list of nodes and edges where each node connects to its partner and that node connects back
        /// This is used for the attraction velocity computation
        /// </summary>
        ///        
        readonly List<List<int>> _graphStructureBalanced = new List<List<int>>();

        /// <summary>
        /// The raw list of nodes with a one way edge they connect to
        /// This is used for drawing nodes and edges
        /// </summary>
        readonly List<List<int>> _graphStructureLinear = new List<List<int>>();

        /// <summary>
        /// Force-directed layout activity of this graph
        /// </summary>
        public float Temperature = 100f;

    }
}
