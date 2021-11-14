using System;
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
        /// How to center the graph
        /// </summary>
        public enum CenteringMode
        {
            /// <summary>
            /// The graph is not being centered
            /// </summary>
            Inactive,
            /// <summary>
            /// The graph is being centered until it is centered
            /// </summary>
            Centering,
            /// <summary>
            /// The widget will continue centering the graph to lock it in position even as it grows
            /// </summary>
            ContinuousCentering
        };

        /// <summary>
        /// The current centering state for this graph in the main graph renderer
        /// </summary>
        public CenteringMode CenteringInFrame = CenteringMode.Inactive;
        /// <summary>
        /// How many steps the current non-continuous centering operation has taken
        /// </summary>
        public int CenteringSteps = 0;


        /// <summary>
        /// Toggle centering on or off
        /// </summary>
        /// <param name="locked">If toggling on, this will turn on continuous centering</param>
        public void ToggleCentering(bool locked = false)
        {
            if (CenteringInFrame is not CenteringMode.Inactive)
            {
                CenteringInFrame = CenteringMode.Inactive;
                CenteringSteps = 0;
            }
            else
            {
                CenteringInFrame = locked ? CenteringMode.ContinuousCentering : CenteringMode.Centering;
                CenteringSteps = 0;
            }
        }


        private readonly ReaderWriterLockSlim _renderLock = new ReaderWriterLockSlim();

        /// <summary>
        /// Framebuffers for the preview texture
        /// </summary>
        public Veldrid.Framebuffer? _previewFramebuffer1, _previewFramebuffer2;
        private Veldrid.Texture? _previewTexture1, _previewTexture2;


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
        private readonly ReaderWriterLockSlim textureLock = new ReaderWriterLockSlim();
        private int latestWrittenTexture = 1;

        private readonly Random _rng = new Random();



        /// <summary>
        /// Create a plotted graph
        /// </summary>
        /// <param name="protoGraph">ProtoGraph of the thread</param>
        /// <param name="device">GraphicsDevice of the GPU this thread is being rendered on</param>
        public PlottedGraph(ProtoGraph protoGraph, GraphicsDevice device)
        {
            InternalProtoGraph = protoGraph;
            LayoutStyles.Style initialStyle = LayoutStyles.Style.ForceDirected3DNodes;
            LayoutState = new GraphLayoutState(this, device, initialStyle);


            IsAnimated = !InternalProtoGraph.Terminated;

            graphColours = Array.Empty<WritableRgbaFloat>(); //squash "needs value" warning
            InitGraphColours();

            CameraClippingFar = 60000f;
            CameraState.MainCameraZoom = -6000f;
            CameraState.MainCameraXOffset = -400;
            CameraState.MainCameraYOffset = 0;
            CameraState.RotationMatrix = Matrix4x4.Identity;
            CameraState.PreviewCameraZoom = -6000f;

            _layoutCameraStates[initialStyle] = CameraState;
        }


        /// <summary>
        /// Camera position for main and preview cameras
        /// </summary>
        public struct CAMERA_STATE
        {
            /// <summary>
            /// X position of the graph on the main renderer widget
            /// </summary>
            public float MainCameraXOffset;
            /// <summary>
            /// Y position of the graph on the main renderer widget
            /// </summary>
            public float MainCameraYOffset;
            /// <summary>
            /// Z position of the graph on the main renderer widget
            /// </summary>
            public float MainCameraZoom;
            /// <summary>
            /// Main renderer widget graph translation matrix
            /// </summary>
            public Matrix4x4 MainCameraTranslation => Matrix4x4.CreateTranslation(new Vector3(MainCameraXOffset, MainCameraYOffset, MainCameraZoom));

            /// <summary>
            /// Rotation matrix for the main camera
            /// </summary>
            public Matrix4x4 RotationMatrix;

            /// <summary>
            /// X position of the graph on the preview renderer widget
            /// </summary>
            public float PreviewCameraXOffset;
            /// <summary>
            /// Y position of the graph on the preview renderer widget
            /// </summary>
            public float PreviewCameraYOffset;
            /// <summary>
            /// Z position of the graph on the preview renderer widget
            /// </summary>
            public float PreviewCameraZoom;
            /// <summary>
            /// Preview renderer widget graph translation matrix
            /// </summary>
            public Matrix4x4 PreviewCameraTranslation => Matrix4x4.CreateTranslation(new Vector3(PreviewCameraXOffset, PreviewCameraYOffset, PreviewCameraZoom));
        }


        /// <summary>
        /// Camera position for main and preview cameras
        /// </summary>
        public CAMERA_STATE CameraState;
        readonly Dictionary<LayoutStyles.Style, CAMERA_STATE> _layoutCameraStates = new();


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

            int NewPosition = (int)(position * InternalProtoGraph.UpdateCount);
            _userSelectedAnimPosition = NewPosition;
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
            {
                _userSelectedAnimPosition = -1;
            }
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
            if (InternalProtoGraph.TraceData.DiscardTraceData)
            {
                InternalProtoGraph.PurgeSavedAnimationData();
            }

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
            if (InternalProtoGraph.UpdateCount == 0)
            {
                return 0;
            }

            return (float)((float)AnimationIndex / InternalProtoGraph.UpdateCount);
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
                    break;

                case REPLAY_STATE.Playing: //pause it
                    ReplayState = REPLAY_STATE.Paused;
                    break;

                case REPLAY_STATE.Paused: //unpause it
                    ReplayState = REPLAY_STATE.Playing;
                    SetAnimated(true);
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
            int drawCount = endIndex - DrawnEdgesCount;
            if (drawCount <= 0)
            {
                return;
            }

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
                    AddNode(edgeNodes.Item2, edge: e);

                }

                UpdateNodeLinks((int)edgeNodes.Item1, (int)edgeNodes.Item2);
                DrawnEdgesCount++;

                if (rgatState.rgatIsExiting)
                {
                    break;
                }
            }
        }

        private float GetAttractionForce(EdgeData edge)
        {
            if (edge.edgeClass == EdgeNodeType.eEdgeOld) return 0;
            //don't attract node to other nodes with lots of connections.
            //todo: do this at edge creation time, add a flag to the edgedata class
            //GlobalConfig.NodeClumpLimit = 1;
            if (GlobalConfig.NodeClumpLimit > 0)
            {
                InternalProtoGraph.GetEdgeNodes(edge.EdgeListIndex, out NodeData source, out NodeData target);
                if (source.OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                {
                    return GlobalConfig.NodeClumpForce;
                }

                if (target.IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                {
                    return GlobalConfig.NodeClumpForce;
                }

                if (source.IncomingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                {
                    return GlobalConfig.NodeClumpForce;
                }

                if (target.OutgoingNeighboursSet.Count > GlobalConfig.NodeClumpLimit)
                {
                    return GlobalConfig.NodeClumpForce;
                }
            }

            //return 5000;

            float force;
            switch (edge.edgeClass)
            {
                case EdgeNodeType.eEdgeNew:
                    if (edge.sourceNodeType == EdgeNodeType.eNodeJump)
                    {
                        force = GlobalConfig.EdgeStrengthNewJump;
                    }
                    else
                    {
                        force = GlobalConfig.EdgeStrengthNewOther;
                    }

                    break;
                case EdgeNodeType.eEdgeLib:
                    force = GlobalConfig.EdgeStrengthLib;
                    break;
                case EdgeNodeType.eEdgeCall:
                    force = GlobalConfig.EdgeStrengthCall;
                    break;
                case EdgeNodeType.eEdgeOld:
                    force = GlobalConfig.EdgeStrengthOld;
                    break;
                case EdgeNodeType.eEdgeReturn:
                    force = GlobalConfig.EdgeStrengthRet;
                    break;
                case EdgeNodeType.eEdgeException:
                    force = GlobalConfig.EdgeStrengthException;
                    break;
                default:
                    Logging.WriteConsole($"Unhandled edgetype {edge.edgeClass} with edge {edge.EdgeListIndex}");
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
                    return GenerateCylinderLayout();

                case LayoutStyles.Style.Circle:
                    return GenerateCircleLayout();

                default:
                    if (LayoutStyles.IsForceDirected(style))
                    {
                        if (!LayoutState.GetSavedLayout(style, out float[]? layout))
                        {
                            return CreateRandomPresetLayout();
                        }
                        else
                        {
                            return layout;
                        }
                    }
                    else
                    {
                        Logging.WriteConsole("Error: Tried to layout invalid preset style: " + ActiveLayoutStyle.ToString());
                        return null;
                    }
            }
        }


        private float[] GenerateCylinderLayout()
        {

            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();
            var textureArray = new float[textureSize * textureSize * 4];
            float a = 0;
            float b = 0;
            float radius = OPT_CYLINDER_RADIUS;

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
                NodeData? firstParent = InternalProtoGraph.GetNode(n.ParentIdx);
                Debug.Assert(firstParent is not null);

                if (n.IsExternal)
                {
                    //todo - test multiple extern calls from same node
                    a = a + (-0.5f) - 1f * firstParent.Childexterns;
                    b = b + (0.5f) + 0.7f * firstParent.Childexterns;
                }
                else
                {
                    switch (firstParent.VertType())
                    {
                        case EdgeNodeType.eNodeNonFlow:
                            b += B_BETWEEN_BLOCKNODES;
                            break;

                        case EdgeNodeType.eNodeJump:

                            if (firstParent.IsConditional && n.Address == firstParent.ins!.condDropAddress)
                            {
                                b += B_BETWEEN_BLOCKNODES;
                                break;
                            }
                            a += JUMPA;
                            b += JUMPB;
                            break;


                        case EdgeNodeType.eNodeException:
                            a += JUMPA;
                            b += JUMPB;
                            break;

                        case EdgeNodeType.eNodeCall:
                            a += CALLA;
                            if (b < callCeiling)
                            {
                                b = callCeiling;
                            }

                            b += CALLB;
                            break;

                        case EdgeNodeType.eNodeReturn:
                        case EdgeNodeType.eNodeExternal: //treat all externs as if they end in a return

                            Tuple<float, float>? callerPos = null;
                            for (var stackI = callStack.Count - 1; stackI >= 0; stackI--)
                            {
                                if (callStack[stackI].Item2 == n.Address)
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
                if (n.VertType() == EdgeNodeType.eNodeCall)
                {
                    callStack.Add(new Tuple<Tuple<float, float>, ulong>(new Tuple<float, float>(a, b), n.Address + (ulong)n.ins!.NumBytes));
                }

                //if returning from a function, limit drawing any new functions to below this one
                if (n.VertType() == EdgeNodeType.eNodeReturn)
                {
                    callCeiling = b + 8;
                }

                //used to work out how far down to draw the wireframe
                if (b > _lowestWireframeLoop)
                {
                    _lowestWireframeLoop = b;
                }

                double aPix = -1 * a * OPT_CYLINDER_PIXELS_PER_A;
                float x = (float)(radius * Math.Cos((aPix * Math.PI) / radius));
                float y = -1 * OPT_CYLINDER_PIXELS_PER_B * b;
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

        /// <summary>
        /// Size of a cylinder plot
        /// </summary>
        public float OPT_CYLINDER_RADIUS = 20000f;
        /// <summary>
        /// Vertical separation of nodes on a cylinder plot
        /// </summary>
        public float OPT_CYLINDER_PIXELS_PER_B = 30f;
        /// <summary>
        /// Horizonal separation of nodes on a cylinder plot
        /// </summary>
        public float OPT_CYLINDER_PIXELS_PER_A = 160f;
        /// <summary>
        /// Alpha value of plot wireframes
        /// </summary>
        public float OPT_WIREFRAME_ALPHA = 0.3f;
        /// <summary>
        /// If set then the temperature will not decrease
        /// </summary>
        public bool OPT_LOCK_TEMPERATURE = false;

        private void GenerateCylinderWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            float alpha = OPT_WIREFRAME_ALPHA * 255f;
            if (alpha is 0) return;
            int CYLINDER_PIXELS_PER_ROW = 500;
            float WF_POINTSPERLINE = 50f;

            int wireframe_loop_count = (int)Math.Ceiling((_lowestWireframeLoop * OPT_CYLINDER_PIXELS_PER_B) / CYLINDER_PIXELS_PER_ROW) + 1;
            if(wireframe_loop_count  > 100)
            {
                wireframe_loop_count = 100;
                CYLINDER_PIXELS_PER_ROW = (int)(_lowestWireframeLoop / (float)(wireframe_loop_count/OPT_CYLINDER_PIXELS_PER_B));
            }
            float radius = OPT_CYLINDER_RADIUS;

            WritableRgbaFloat wireframeColour = new WritableRgbaFloat(Themes.GetThemeColourWRF(Themes.eThemeColour.WireFrame).ToUint((uint)alpha));
            for (int rowY = 0; rowY < wireframe_loop_count; rowY++)
            {
                int rowYcoord = -rowY * CYLINDER_PIXELS_PER_ROW;
                for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
                {
                    float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                    if (circlePoint > 1)
                    {
                        edgeIndices.Add((uint)verts.Count - 1);
                    }

                    edgeIndices.Add((uint)verts.Count);
                    GeomPositionColour gpc = new GeomPositionColour
                    {
                        Color = wireframeColour,
                        Position = new Vector4(radius * (float)Math.Cos(angle), rowYcoord, radius * (float)Math.Sin(angle), 0)
                    };
                    verts.Add(gpc);
                }

            }
        }

        private void GenerateRotationWireframe(ref List<GeomPositionColour> verts, ref List<uint> edgeIndices)
        {
            float WF_POINTSPERLINE = 50f;
            float radius = FurthestNodeDimension;

            WritableRgbaFloat YawColour = new WritableRgbaFloat(0xFFE69F00);
            WritableRgbaFloat RollColour = new WritableRgbaFloat(0xFF56B4E9);
            WritableRgbaFloat PitchColour = new WritableRgbaFloat(0xFF009E73);

            for (float circlePoint = 0; circlePoint < WF_POINTSPERLINE + 1; ++circlePoint)
            {
                float angle = (2f * (float)Math.PI * circlePoint) / WF_POINTSPERLINE;

                if (circlePoint > 1)
                {
                    edgeIndices.Add((uint)verts.Count - 1);
                }

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
                {
                    edgeIndices.Add((uint)verts.Count - 1);
                }

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
                {
                    edgeIndices.Add((uint)verts.Count - 1);
                }

                edgeIndices.Add((uint)verts.Count);
                GeomPositionColour gpc = new GeomPositionColour
                {
                    Color = PitchColour,
                    Position = new Vector4(0, radius * (float)Math.Cos(angle), radius * (float)Math.Sin(angle), 0)
                };
                verts.Add(gpc);
            }


        }

        private float _lowestWireframeLoop;


        List<uint> _wireframeCache = new();


        /// <summary>
        /// Get geometry and colour of various non-instruction edges like highlights and wireframes
        /// </summary>
        /// <param name="edgeIndices">Output list of illustration edge indexes</param>
        /// <returns>Output edge geometry</returns>
        public GeomPositionColour[] GetIllustrationEdges(out List<uint> edgeIndices)
        {
            List<GeomPositionColour> resultList = new List<GeomPositionColour>();
            edgeIndices = new List<uint>();

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

        private void CreateHighlightEdges(List<uint> edgeIndices, List<GeomPositionColour> resultList)
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
                    {
                        edgeColour = new WritableRgbaFloat(customColour.Value);
                    }
                    else
                    {
                        edgeColour = defaultColour;
                    }
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

        private void CreateLiveNodeEdge(List<uint> edgeIndices, List<GeomPositionColour> resultList)
        {
            uint node = LastAnimatedVert;
            if (InternalProtoGraph.HasRecentStep)
            {
                var addrnodes = InternalProtoGraph.ProcessData.GetNodesAtAddress(InternalProtoGraph.RecentStepAddr, InternalProtoGraph.ThreadID);
                if (addrnodes.Count > 0)
                {
                    node = addrnodes[^1];
                }
            }

            //point the active node indicator line to a random busy-region instruction
            lock (animationLock)
            {
                if (_LingeringActiveNodes.Count > 0)
                {
                    node = _LingeringActiveNodes[_rng.Next(0, _LingeringActiveNodes.Count)];
                }
                else
                {
                    if (_PulseActiveNodes.Count > 0)
                    {
                        node = _PulseActiveNodes[_rng.Next(0, _PulseActiveNodes.Count)];
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
        private float[] GenerateCircleLayout()
        {

            int nodeCount = _graphStructureLinear.Count;
            uint textureSize = LinearIndexTextureSize();
            float increase = ((float)Math.PI * 2.0f) / _graphStructureLinear.Count;
            float angle = 0;
            float radius = nodeCount * CONSTANTS.Layout_Constants.CircleLayoutRadiusMultiplier;

            var textureArray = new float[textureSize * textureSize * 4];

            for (var i = 0; i < textureArray.Length; i += 4)
            {

                if (i < nodeCount * 4)
                {
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
            if (OPT_LOCK_TEMPERATURE is false)
            {
                Temperature += _graphStructureLinear.Count / 2;
                Temperature = Math.Min(Temperature, GlobalConfig.TemperatureLimit);
            }
        }

        /// <summary>
        /// Set the temperature of a force directed plot
        /// </summary>
        /// <param name="temp">Activity level</param>
        public void IncreaseTemperature(float temp)
        {
            if (OPT_LOCK_TEMPERATURE is false)
            {
                Temperature = temp;
                Temperature = Math.Min(Temperature, GlobalConfig.TemperatureLimit);
            }
        }

        private unsafe void AddNode(uint nodeIdx, EdgeData? edge = null)
        {

            textureLock.EnterReadLock();

            //todo, asserting here on load. i dont remember if this is important
            //if it happens it means an edge is going to a from a node that didn't exist at the time it was created
            Debug.Assert(nodeIdx == _graphStructureLinear.Count);
            uint futureCount = (uint)_graphStructureLinear.Count + 1;
            var bufferWidth = powerOfTwoContaining((int)futureCount);

            LayoutState.Lock.EnterUpgradeableReadLock();
            LayoutState.AddNode(nodeIdx, futureCount, bufferWidth, edge: edge);
            LayoutState.Lock.ExitUpgradeableReadLock();

            lock (animationLock)
            {
                _graphStructureLinear.Add(new List<int>());
                _graphStructureBalanced.Add(new List<int>());
            }

            Temperature += 0.3f;
            textureLock.ExitReadLock();
        }

        /// <summary>
        /// A descriptor for edges in shader edge buffers
        /// </summary>
        public struct EDGE_INDEX_FIRSTLAST
        {
            /// <summary>
            /// The index of the first edge for this node in the edge list
            /// </summary>
            public int FirstEdgeIndex;

            /// <summary>
            /// The index of the final edge for this node in the edge list
            /// </summary>
            public int LastEdgeIndex;

            /// <summary>
            /// The raw size of this structure
            /// </summary>
            public const uint SizeInBytes = 8;
        }


        /// <summary>
        /// Create an array listing the index of every neighbour of every node
        /// Also initialises the edge strength array, 
        /// </summary>
        /// <returns>If there was data</returns>
        public bool GetEdgeRenderingData(out float[] edgeStrengths, out int[] edgeTargetIndexes, out EDGE_INDEX_FIRSTLAST[] edgeIndexLookups)
        {
            //var textureSize = indexTextureSize(_graphStructureLinear.Count);
            List<List<int>> targetArray = _graphStructureBalanced;
            var textureSize = countDataArrayItems(targetArray) * 2; //A->B + B->A


            if (textureSize == 0)
            {
                edgeStrengths = new float[] { 0 };
                edgeTargetIndexes = new int[] { 1 };
                edgeIndexLookups = new EDGE_INDEX_FIRSTLAST[] { new EDGE_INDEX_FIRSTLAST() };
                return false;
            }

            long v1 = 0, v2 = 0, v3 = 0, v4 = 0;
            Stopwatch st = new();

            st.Start();
            int nodeCount = InternalProtoGraph.NodeCount;
            edgeTargetIndexes = new int[textureSize];
            edgeStrengths = new float[textureSize];


            List<List<int>>? nodeNeighboursArray = null;
            lock (animationLock)
            {
                nodeNeighboursArray = _graphStructureBalanced.ToList();
            }
            var textureSize2 = powerOfTwoContaining(nodeCount * 2);
            edgeIndexLookups = new EDGE_INDEX_FIRSTLAST[(int)(textureSize2 * textureSize2 * 0.5f)];// * textureSize2 * 2];

            st.Stop(); v1 = st.ElapsedMilliseconds; st.Restart();

            int currentNodeIndex;
            int edgeIndex = 0;
            for (currentNodeIndex = 0; currentNodeIndex < nodeCount; currentNodeIndex++)
            {
                edgeIndexLookups[currentNodeIndex].FirstEdgeIndex = edgeIndex; //first edge

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
                        Logging.RecordLogEvent($"Edge A {currentNodeIndex},{neigbours[nidx]} didn't exist in getEdgeDataints", Logging.LogFilterType.Debug);
                        edgeStrengths[edgeIndex] = 1;// 0.5f;
                    }
                    edgeIndex++;


                    if (edgeIndex == edgeTargetIndexes.Length)
                    {
                        edgeIndexLookups[currentNodeIndex].LastEdgeIndex = edgeIndex; //last edge
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
                        Logging.RecordLogEvent($"Edge B {neigbours[nidx]},{currentNodeIndex} didn't exist in getEdgeDataints", Logging.LogFilterType.Alert);
                        edgeStrengths[edgeIndex] = 1;// 0.5f;
                    }
                    edgeIndex++;
                    if (edgeIndex == edgeTargetIndexes.Length)
                    {
                        edgeIndexLookups[currentNodeIndex].LastEdgeIndex = edgeIndex;
                        return true;
                    }
                }

                edgeIndexLookups[currentNodeIndex].LastEdgeIndex = edgeIndex;
            }

            st.Stop(); v2 = st.ElapsedMilliseconds; st.Restart();

            for (var i = edgeIndex; i < edgeTargetIndexes.Length; i++)
            {
                //fill unused RGBA slots with -1
                edgeTargetIndexes[i] = -1;
                edgeStrengths[edgeIndex] = -1;
            }
            st.Stop(); v3 = st.ElapsedMilliseconds; st.Restart();


            for (var i = InternalProtoGraph.NodeList.Count; i < edgeIndexLookups.Length; i++)
            {
                //fill unused RGBA slots with -1
                edgeIndexLookups[i].FirstEdgeIndex = -1;
                edgeIndexLookups[i].LastEdgeIndex = -1;
            }
            st.Stop(); v4 = st.ElapsedMilliseconds; st.Restart();

            if (v4 > 80)
                Console.WriteLine($"GetEdgeRenderingData: v1:{v1}, v2:{v2}, v3:{v3}, v4:{v4}");

            return true;
        }

        /// <summary>
        /// Get the list of node neighbours for use in a compute shader
        /// </summary>
        /// <returns></returns>
        public List<int>[] GetNodeNeighboursArray()
        {
            lock (animationLock)
            {
                return _graphStructureBalanced.ToArray();
            }
        }





        /// <summary>
        /// Number of node->node edges that have been rendered
        /// </summary>
        public int DrawnEdgesCount = 0;

        private void UpdateNodeLinks(int srcNodeIdx, int destNodeIdx)
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
            var bufferWidth = powerOfTwoContaining(_graphStructureLinear.Count);
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

        private float[] CreateRandomPresetLayout()
        {

            var bufferWidth = powerOfTwoContaining(_graphStructureLinear.Count);
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            float[] positions = new float[bufferFloatCount];

            var bounds = 1000;
            var bounds_half = bounds / 2;
            for (var i = 0; i < positions.Length; i += 4)
            {
                if (i < _graphStructureLinear.Count * 4)
                {
                    positions[i] = ((float)_rng.NextDouble() * bounds) - bounds_half;
                    positions[i + 1] = ((float)_rng.NextDouble() * bounds) - bounds_half;
                    positions[i + 2] = ((float)_rng.NextDouble() * bounds) - bounds_half;
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
        /// Reset the layout tracking statistics and reset the temperature to a high value
        /// </summary>
        /// <param name="keepCamera">If set to true then the camera will not be reset</param>
        public void BeginNewLayout(bool keepCamera = false)
        {
            RegenerateEdges();
            lock (_renderLock)
            {
                if (_layoutCameraStates.TryGetValue(this.LayoutState.PresetStyle, out CAMERA_STATE savedState))
                {
                    this.CameraState = savedState;
                }
                else
                {
                    if (keepCamera is false)
                    {
                        this.CameraState = new CAMERA_STATE();
                        this.CameraState.RotationMatrix = Matrix4x4.Identity;

                        if (this.LayoutState.PresetStyle is LayoutStyles.Style.CylinderLayout)
                        {
                            this.CameraState.MainCameraZoom = -1 * OPT_CYLINDER_RADIUS;
                            this.CameraState.MainCameraZoom -= 10000;
                            this.CameraState.MainCameraYOffset += 1500;

                            Matrix4x4 pitch = Matrix4x4.CreateFromAxisAngle(Vector3.UnitX, 0);
                            Matrix4x4 yaw = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, -1.574f); //face the camera
                            Matrix4x4 roll = Matrix4x4.CreateFromAxisAngle(Vector3.UnitZ, 0);
                            Matrix4x4 offsetRotation = pitch * yaw * roll;
                            this.CameraState.RotationMatrix = Matrix4x4.Identity * offsetRotation;
                        }
                        else
                        {

                            this.CameraState.MainCameraZoom = -100 * InternalProtoGraph.NodeCount;
                        }
                    }
                }
            }
            ResetLayoutStats();
            IncreaseTemperature(100f);
        }


        /// <summary>
        /// Power of 2 buffer size to fit the uint graph node indexes
        /// </summary>
        /// <returns></returns>
        public uint LinearIndexTextureSize() { return powerOfTwoContaining(_graphStructureLinear.Count); }

        /// <summary>
        /// Size of the buffer to hold edge verts
        /// </summary>
        /// <returns></returns>
        public uint EdgeVertsBufferSize(int longSize, int shortSize, out int vertexCount, out int edgeCount)
        {
            var edgeCounts = InternalProtoGraph.GetEdgeTypeCounts();
            vertexCount = 0;
            edgeCount = 0;
            foreach (KeyValuePair<EdgeNodeType, int> count in edgeCounts)
            {
                edgeCount += count.Value;
                switch (count.Key)
                {
                    case EdgeNodeType.eEdgeOld:
                    case EdgeNodeType.eEdgeReturn:
                        vertexCount += longSize * count.Value;
                        break;
                    default:
                        vertexCount += shortSize * count.Value;
                        break;
                }
            }

            //originally this was to have a square texture, now it just gives us slack space to put more verts to space out resizes
            uint width = powerOfTwoContaining((int)(vertexCount * Position1DColourMultiVert.SizeInBytes));
            uint itemCount = (uint)Math.Floor(((double)(width * width) / (double)Position1DColourMultiVert.SizeInBytes));
            return itemCount;
        }

        /// <summary>
        /// Power of 2 buffer size to fit the uint graph edge indexes
        /// </summary>
        /// <returns></returns>
        public uint NestedIndexTextureSize() { return powerOfTwoContaining(_graphStructureBalanced.Count); }

        /// <summary>
        /// Power of 2 buffer size to fit the vector4 graph edges
        /// </summary>
        /// <returns></returns>
        public uint EdgeTextureWidth() { return dataTextureSize(countDataArrayItems(_graphStructureBalanced)); }


        /// <summary>
        /// Get the colour of the node for the specified rendering style
        /// </summary>
        /// <param name="nodeIndex">Index of the node</param>
        /// <param name="renderingMode">Rendering style</param>
        /// <param name="themeGraphColours">Array of theme colours</param>
        /// <returns>The node colour</returns>
        public WritableRgbaFloat GetNodeColor(int nodeIndex, eRenderingMode renderingMode, WritableRgbaFloat[] themeGraphColours)
        {
            if (nodeIndex >= InternalProtoGraph.NodeCount)
            {
                return new WritableRgbaFloat(0, 0, 0, 0);
            }

            NodeData n = InternalProtoGraph.NodeList[nodeIndex];

            if (n is null || n.Highlighted)
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
                            return new WritableRgbaFloat(0, 0, 0, 0f);
                        }
                        else
                        {
                            if (n.conditional == ConditionalType.CONDCOMPLETE)
                            {
                                return new WritableRgbaFloat(1, 1, 1, 1f);
                            }

                            if (((int)n.conditional & (int)ConditionalType.CONDTAKEN) != 0)
                            {
                                return new WritableRgbaFloat(0, 1, 0, 0.7f);
                            }

                            if (((int)n.conditional & (int)ConditionalType.CONDFELLTHROUGH) != 0)
                            {
                                return new WritableRgbaFloat(1, 0, 0, 0.7f);
                            }
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
        /// <param name="nodePair">The nodeIndex->nodeIndex description of the edge</param>
        /// <param name="e">The EdgeData edge object</param>
        /// <param name="renderingMode">The rendering mode</param>
        /// <returns>The colour of the edge</returns>
        public WritableRgbaFloat GetEdgeColor(Tuple<uint, uint> nodePair, EdgeData e, eRenderingMode renderingMode)
        {
            switch (renderingMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    return graphColours[(int)e.edgeClass];
                case eRenderingMode.eHeatmap:
                    {
                        Debug.Assert(e.heatRank >= 0 && e.heatRank <= 9);
                        Themes.eThemeColour heatColEnum = (Themes.eThemeColour)((float)Themes.eThemeColour.Heat0Lowest + e.heatRank);
                        return Themes.GetThemeColourWRF(heatColEnum);
                    }
                case eRenderingMode.eConditionals:
                    return new WritableRgbaFloat(0.8f, 0.8f, 0.8f, 1);

                case eRenderingMode.eDegree:
                    //todo 

                    int degree1 = InternalProtoGraph.NodeList[(int)nodePair.Item1].IncomingNeighboursSet.Count +
                        InternalProtoGraph.NodeList[(int)nodePair.Item1].OutgoingNeighboursSet.Count;
                    int degree2 = InternalProtoGraph.NodeList[(int)nodePair.Item2].IncomingNeighboursSet.Count +
                        InternalProtoGraph.NodeList[(int)nodePair.Item2].OutgoingNeighboursSet.Count;
                    int highestDegree = Math.Max(degree1, degree2);
                    if (highestDegree > GlobalConfig.NodeClumpLimit)
                    {
                        return Themes.GetThemeColourWRF(Themes.eThemeColour.Emphasis2);
                    }

                    float heatProportion = 10 * ((float)highestDegree / (float)InternalProtoGraph.MostConnections);
                    Debug.Assert(heatProportion >= 0 && heatProportion <= 10);
                    int colourIndex = (int)Math.Floor(heatProportion) + (int)Themes.eThemeColour.Heat0Lowest;
                    return Themes.GetThemeColourWRF((Themes.eThemeColour)colourIndex);
                default:
                    return graphColours[(int)e.edgeClass];
            }
        }

        private Tuple<string?, uint> CreateNodeLabel(int index, eRenderingMode renderingMode, bool forceNew = false)
        {
            NodeData n = InternalProtoGraph.NodeList[index];
            if (n.Label == null || n.Dirty || forceNew)
            {
                n.CreateLabel(this);
            }

            if (n.IsExternal)
            {
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.SymbolText));
            }
            else if (n.HasSymbol)
            {
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.InternalSymbol));
            }
            else
            {
                return new Tuple<string?, uint>(n.Label!, Themes.GetThemeColourUINT(Themes.eThemeColour.InstructionText));
            }
        }

        /// <summary>
        /// Force the generation of new labels instead of using cached versions
        /// Usually because label settings/values/colours have changed
        /// </summary>
        private void RegenerateLabels() => _newLabels = true;
        private bool _newLabels;

        /// <summary>
        /// Get the currently selected rendering mode of the graph (heatmap, etc)
        /// </summary>
        public eRenderingMode RenderingMode => lastRenderingMode;
        private eRenderingMode lastRenderingMode = eRenderingMode.eStandardControlFlow;


        private ulong lastThemeVersion = 0;

        Position1DColour[] _cachedMainNodeVerts = Array.Empty<Position1DColour>();
        Position1DColour[] _cachedMainNodePickingVerts = Array.Empty<Position1DColour>();
        int _cachedMainNodeVertCount = 0;


        /// <summary>
        /// Get the node drawing data for the preview version of this graph
        /// </summary>
        /// <param name="renderingMode">Rendering mode (heatmap, etc)</param>
        /// <param name="textureWidth">Float width of the square vertex texture</param>
        /// <param name="nodePickingColors">Output node mouse hover picking data</param>
        /// <param name="captions">Node caption texts</param>
        /// <param name="nodeCount">Number of nodes in the output buffers</param>
        /// <returns>Node drawing data</returns>
        public Position1DColour[] GetMaingraphNodeVerts(eRenderingMode renderingMode, int textureWidth,
            out Position1DColour[] nodePickingColors, out List<Tuple<string?, uint>> captions, out int nodeCount)
        {
            bool createNewLabels = false;
            if (renderingMode != lastRenderingMode || _newLabels)
            {
                createNewLabels = true;
                _newLabels = false;
                lastRenderingMode = renderingMode;
                ResetCachedRender();
            }

            nodeCount = RenderedNodeCount();

            //theme changed, read in new colours
            ulong themeVariant = Themes.ThemeVariant;
            bool newColours = lastThemeVersion < themeVariant;
            if (newColours)
            {
                _cachedMainNodeVertCount = 0;
                InitGraphColours();
                lastThemeVersion = themeVariant;
                _mainEdgesCache.RegenerationRequired = true;
            }

            int textureSize = textureWidth * textureWidth;
            if (textureSize > _cachedMainNodeVerts.Length)
            {
                Position1DColour[] NodeVerts = new Position1DColour[textureSize];
                _cachedMainNodeVerts = NodeVerts;

                Position1DColour[] NodePickingVerts = new Position1DColour[textureSize];
                _cachedMainNodePickingVerts = NodePickingVerts;
                _cachedMainNodeVertCount = 0;
                _mainEdgesCache.RegenerationRequired = true;
            }
            if (_mainEdgesCache.cachedRenderMode != renderingMode)
            {
                _mainEdgesCache.RegenerationRequired = true;
            }


            nodePickingColors = _cachedMainNodePickingVerts;
            captions = new List<Tuple<string?, uint>>();

            WritableRgbaFloat[] graphColoursCopy;
            lock (textureLock)
            {
                graphColoursCopy = graphColours.ToArray();
            }

            for (int index = _cachedMainNodeVertCount; index < _cachedMainNodeVerts.Length; index++)
            {
                if (index >= _cachedMainNodeVerts.Length || index >= InternalProtoGraph.NodeCount)
                {
                    nodeCount = _cachedMainNodeVertCount;
                    break;
                }

                _cachedMainNodeVertCount += 1;
                WritableRgbaFloat nodeColour = GetNodeColor(index, renderingMode, graphColoursCopy);
                _cachedMainNodeVerts[index] = new Position1DColour
                {
                    PositionIndex = index,
                    Color = nodeColour
                };

                _cachedMainNodePickingVerts[index] = new Position1DColour
                {
                    PositionIndex = index,
                    Color = new WritableRgbaFloat(Rf: index, Gf: 0, Bf: 0, Af: 1)
                };
            }


            if (Opt_TextEnabled)
            {
                for (int index = 0; index < nodeCount; index++)
                {
                    if (!IsAnimated || _cachedMainNodeVerts[index].Color.A > 0)
                    {
                        var caption = CreateNodeLabel(index, renderingMode, createNewLabels);
                        captions.Add(caption);
                    }
                }
            }

            nodeCount = _cachedMainNodeVertCount;
            return _cachedMainNodeVerts;
        }

        private void InitGraphColours()
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





        Position1DColour[] _cachedPreviewNodeVerts = Array.Empty<Position1DColour>();
        readonly Position1DColour[] _cachedPreviewNodePickingVerts = Array.Empty<Position1DColour>();
        readonly uint[] _cachedPreviewNodeIndexes = Array.Empty<uint>();
        int _cachedPreviewNodeVertCount = 0;

        /// <summary>
        /// Get the node drawing data for the preview version of this graph
        /// </summary>
        /// <param name="renderingMode">Rendering mode of the preview</param>
        /// <param name="nodeCount">Number of nodes rendered</param>
        /// <returns>Node geometry array</returns>
        public Position1DColour[] GetPreviewgraphNodeVerts(eRenderingMode renderingMode, out int nodeCount)
        {

            int maxNodes = InternalProtoGraph.NodeCount;
            int textureWidth = (int)LinearIndexTextureSize();
            int textureSize = textureWidth * textureWidth * 4;

            if (textureSize > _cachedPreviewNodeVerts.Length)
            {
                _cachedPreviewNodeVerts = new Position1DColour[textureSize];
                _mainEdgesCache.RegenerationRequired = true;
                _cachedPreviewNodeVertCount = 0;
            }


            WritableRgbaFloat[] graphColoursCopy;
            lock (textureLock)
            {
                graphColoursCopy = graphColours.ToArray();
            }


            for (int index = _cachedPreviewNodeVertCount; index < _cachedPreviewNodeVerts.Length; index++)
            {
                //float x = index % textureWidth;
                //float y = index / textureWidth;
                //Vector2 texturePosition = new Vector2(x, y);

                if (index >= maxNodes)
                {
                    nodeCount = _cachedPreviewNodeVertCount;
                    Debug.Assert(nodeCount <= _cachedPreviewNodeVerts.Length);
                    return _cachedPreviewNodeVerts;
                }

                _cachedPreviewNodeVertCount += 1;
                _cachedPreviewNodeVerts[index] = new Position1DColour
                {
                    PositionIndex = index,//new Vector2(x, y),
                    Color = GetNodeColor(index, renderingMode, graphColoursCopy)
                };

            }
            nodeCount = _cachedPreviewNodeVertCount;
            Debug.Assert(nodeCount <= _cachedPreviewNodeVerts.Length);
            return _cachedPreviewNodeVerts;
        }


        /// <summary>
        /// Cause the main graph to be rerendered from scratch 
        /// Usually due to edge colour changes
        /// </summary>
        public void ResetCachedRender()
        {
            _mainEdgesCache.ELVertIndex = 0;
            _cachedMainNodeVertCount = 0;
            _mainEdgesCache.EdgesRendered = 0;
        }


        class CACHED_EDGE_SET
        {
            public int ELVertIndex = 0;
            public int EdgesRendered = 0;
            public Position1DColourMultiVert[] EdgeLineVerts = Array.Empty<Position1DColourMultiVert>();
            public bool RegenerationRequired = false;
            public eRenderingMode cachedRenderMode;
        }

        readonly CACHED_EDGE_SET _previewEdgesCache = new CACHED_EDGE_SET();
        readonly CACHED_EDGE_SET _mainEdgesCache = new CACHED_EDGE_SET();


        /// <summary>
        /// Get the geometry and colour of every edge
        /// </summary>
        /// <param name="renderingMode">Rendering mode (standard, heatmap, etc)</param>
        /// <param name="vertCount">Output number of edge vertics to draw</param>
        /// <param name="preview">Use the preview data. If false - use the main node data</param>
        /// <returns>Position/Colour geometry of the edges</returns>
        public Position1DColourMultiVert[] GetEdgeLineVerts(eRenderingMode renderingMode, out int vertCount, bool preview = false)
        {
            CACHED_EDGE_SET cache = preview ? _previewEdgesCache : _mainEdgesCache;

            uint evTexSize = EdgeVertsBufferSize(18, 2, out vertCount, out int edgeCount);
            if (InternalProtoGraph.EdgeCount > cache.EdgesRendered || cache.RegenerationRequired)
            {
                if (evTexSize > cache.EdgeLineVerts.Length)
                {
                    cache.EdgeLineVerts = new Position1DColourMultiVert[evTexSize];
                }
                Logging.RecordLogEvent($"Graph {PID}:{TID} has {edgeCount} edges with {vertCount} verts ({vertCount * Position1DColourMultiVert.SizeInBytes} bytes) -" +
                    $" Buffer allocated for it is {evTexSize} verts - {evTexSize * Position1DColourMultiVert.SizeInBytes} bytes", Logging.LogFilterType.Debug);
                cache.EdgeLineVerts = new Position1DColourMultiVert[evTexSize];
                cache.ELVertIndex = 0;
                cache.EdgesRendered = 0;
                cache.RegenerationRequired = false;
                cache.cachedRenderMode = renderingMode;
            }

            Stopwatch sw = new();
            sw.Start();

            //var edgeList = InternalProtoGraph.GetEdgelistCopy();
            InternalProtoGraph.GetEdgelistSpans(out Span<Tuple<uint, uint>> nodePairs, out Span<EdgeData> edges);
            int vertI = cache.ELVertIndex;
            for (var edgeI = cache.EdgesRendered; edgeI < edgeCount; edgeI++)
            {
                Tuple<uint, uint> edgeNodes = nodePairs[edgeI];

                int srcNodeIdx = (int)edgeNodes.Item1;
                int destNodeIdx = (int)edgeNodes.Item2;
                EdgeData edge = edges[edgeI];
                WritableRgbaFloat ecol = GetEdgeColor(edgeNodes, edge, renderingMode);
                if (edge.edgeClass == EdgeNodeType.eEdgeOld || edge.edgeClass == EdgeNodeType.eEdgeReturn)
                {
                    cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                        {
                            SrcPositionIndex = srcNodeIdx,
                            DestPositionIndex = destNodeIdx,
                            EdgeProgress = 0,
                            Color = ecol
                        };

                    const float arcInnerVertCount = 8;
                    for (var arcI = 0; arcI < arcInnerVertCount; arcI++)
                    {
                        cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                        {
                            SrcPositionIndex = srcNodeIdx,
                            DestPositionIndex = destNodeIdx,
                            EdgeProgress = ((float)(arcI + 1)) / (arcInnerVertCount),
                            Color = ecol
                        };

                        cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                        {
                            SrcPositionIndex = srcNodeIdx,
                            DestPositionIndex = destNodeIdx,
                            EdgeProgress = ((float)(arcI + 1)) / (arcInnerVertCount),
                            Color = ecol
                        };
                    }


                    cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                    {
                        SrcPositionIndex = srcNodeIdx,
                        DestPositionIndex = destNodeIdx,
                        EdgeProgress = 1,
                        Color = ecol
                    };
                }
                else
                {
                    cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                    {
                        SrcPositionIndex = srcNodeIdx,
                        DestPositionIndex = destNodeIdx,
                        EdgeProgress = 0,
                        Color = ecol
                    };

                    cache.EdgeLineVerts[vertI++] = new Position1DColourMultiVert
                    {
                        SrcPositionIndex = srcNodeIdx,
                        DestPositionIndex = destNodeIdx,
                        EdgeProgress = 1,
                        Color = ecol
                    };
                }
                cache.EdgesRendered += 1;
            }
            Debug.Assert(cache.EdgesRendered == edgeCount);
            cache.ELVertIndex = vertI;

            sw.Stop();
            if (sw.ElapsedMilliseconds > 150 && vertI > 0)
                Logging.RecordLogEvent($"GetEdgeLineVertsloop took {sw.ElapsedMilliseconds}ms over {vertCount} verts ({sw.ElapsedMilliseconds / vertI} avg)", Logging.LogFilterType.Debug);
            return cache.EdgeLineVerts;
        }



        /// <summary>
        /// Size of data textures for compute shaders, input is number of vector 4 entries the buffer is expected to hold
        /// Output is the lowest power of two size that will hold it
        /// </summary>
        /// <param name="num">Node count</param>
        /// <returns>Texture size</returns>
        private static uint dataTextureSize(int num)
        {
            return powerOfTwoContaining((int)Math.Ceiling(num / 4.0));
        }

        private static uint powerOfTwoContaining(int nodesEdgesLength)
        {
            var power = 1;
            while (power * power < nodesEdgesLength)
            {
                power *= 2;
            }
            return power / 2 > 1 ? (uint)power : 2;
        }


        //todo: linq
        private static int countDataArrayItems(List<List<int>> dataArray)
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



        /// <summary>
        /// Get the nodes of a block
        /// </summary>
        /// <param name="externBlockAddr"></param>
        /// <param name="blockID"></param>
        /// <param name="newnodelist"></param>
        /// <returns></returns>
        private bool get_block_nodelist(ulong externBlockAddr, long blockID, out List<uint>? newnodelist)
        {
            ProcessRecord piddata = InternalProtoGraph.ProcessData;
            ROUTINE_STRUCT? externBlock = new ROUTINE_STRUCT();
            List<InstructionData>? block = piddata.GetDisassemblyBlock((uint)blockID, ref externBlock, externBlockAddr);
            if (block == null && externBlock == null)
            {
                newnodelist = null;
                return false;
            }

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
                            Logging.WriteConsole($"Error: Extern block thread_callers was null [block 0x{externBlockAddr:x}]");
                        }
                        else
                        {
                            found = externBlock.Value.ThreadCallers.TryGetValue(TID, out calls);
                        }
                    }
                    if (found)
                    {
                        break;
                    }

                    Thread.Sleep(200);
                    if (rgatState.ExitToken.IsCancellationRequested)
                    {
                        newnodelist = null;
                        return false;
                    }
                    Logging.RecordError($"[rgat]get_block_nodelist() Fail to find edge for thread {TID} calling extern 0x{externBlockAddr:x}");
                    newnodelist = null;
                    return false;
                }



                newnodelist = new List<uint>();
                if (calls is not null)
                {
                    lock (piddata.ExternCallerLock)
                    {
                        foreach (Tuple<uint, uint> edge in calls) //record each call by caller 
                        {
                            if (edge.Item1 == LastAnimatedVert)
                            {
                                newnodelist.Add(edge.Item2);
                            }
                        }
                    }
                }

                return true;
            }


            newnodelist = new List<uint>();
            if (block is null)
            {
                return false;
            }

            lock (InternalProtoGraph.TraceData.DisassemblyData._instructionsLock)
            {
                foreach (InstructionData ins in block)
                {
                    if (!ins.GetThreadVert(TID, out uint val))
                    {
                        return false;
                    }

                    newnodelist.Add(val);
                }
            }

            return true;
        }

        private void brighten_next_block_edge(uint blockID, ulong blockAddress)
        {
            ROUTINE_STRUCT? externStr = null;
            List<InstructionData>? nextBlock = InternalProtoGraph.ProcessData.GetDisassemblyBlock(blockID, ref externStr, blockAddress);
            if (nextBlock is null)
            {
                return;
            }

            Tuple<uint, uint>? LinkingPair = null;
            if (externStr != null)
            {
                var callers = externStr.Value.ThreadCallers[InternalProtoGraph.ThreadID];
                var caller = callers.Find(n => n.Item2 == LastAnimatedVert);
                if (caller == null)
                {
                    return;
                }

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
                else
                {
                    return;
                }
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




        private void brighten_node_list(ANIMATIONENTRY entry, int brightTime, List<uint> nodeIDList)
        {
            ulong listOffset = 0;

            foreach (uint nodeIdx in nodeIDList)
            {
                if (Opt_TextEnabledLive && listOffset == 0 && InternalProtoGraph.GetNode(nodeIdx)!.HasSymbol)
                {
                    AddRisingSymbol(nodeIdx, (int)entry.Count - 1, brightTime);
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
                if ((entry.entryType == eTraceUpdateType.eAnimExecException) && (listOffset == (entry.Count + 1)))
                {
                    break;
                }
            }
        }

        private void end_unchained(ANIMATIONENTRY entry)
        {

            remove_unchained_from_animation();
            List<InstructionData>? firstChainedBlock = InternalProtoGraph.ProcessData.getDisassemblyBlock(entry.BlockID);
            uint vertID = 0;
            bool found = firstChainedBlock is not null && firstChainedBlock[^1].GetThreadVert(TID, out vertID);
            Debug.Assert(found);
            LastAnimatedVert = vertID; //should this be front()?
        }


        /// <summary>
        /// Process more animation updates from a live trace
        /// </summary>
        public void ProcessLiveAnimationUpdates(out int processedCount)
        {
            //too many updates at a time damages interactivity
            //too few creates big backlogs which delays the animation (can still see realtime in static mode though)
            int updateLimit = GlobalConfig.LiveAnimationUpdatesPerFrame;
            processedCount = 0;
            Stopwatch sw = new();
            var animationData = InternalProtoGraph.GetSavedAnimationDataReference();
            while (updateProcessingIndex < animationData.Count && (updateLimit-- > 0))
            {
                sw.Restart();
                ANIMATIONENTRY entry = animationData[updateProcessingIndex];
                if (!process_live_update(entry))
                {
                    break;
                }
                sw.Stop();
                if (sw.ElapsedMilliseconds > 150)
                    Logging.RecordLogEvent($"ProcessLiveAnimationUpdates took {sw.ElapsedMilliseconds}ms with entry type {entry.entryType}", Logging.LogFilterType.Debug);
                processedCount += 1;
            }
            InternalProtoGraph.ReleaseSavedAnimationDataReference();

            if (InternalProtoGraph.TraceData.DiscardTraceData)
            {
                updateProcessingIndex = InternalProtoGraph.PurgeAnimationEntries(updateProcessingIndex);
                //GC.Collect();
            }

        }


        //return false if we need more trace data to do further updates
        private bool process_live_update(ANIMATIONENTRY entry)
        {
            if (InternalProtoGraph.HasRecentStep)
            {
                return false;
            }

            // Stopwatch sw = new Stopwatch();

            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                //sw.Start();
                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Live update: eAnimUnchainedResults. Block {entry.BlockID} executed {entry.Count} times",
                    Logging.LogFilterType.BulkDebugLogFile);
                ++updateProcessingIndex;
                return true;
            }

            if (entry.entryType == eTraceUpdateType.eAnimReinstrument)
            {
                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Live update: eAnimReinstrument.", Logging.LogFilterType.BulkDebugLogFile);
                end_unchained(entry);
                ++updateProcessingIndex;
                return true;
            }

            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                string s = "";
                if (get_block_nodelist(0, entry.BlockID, out List<uint>? nodeIDListUC) && nodeIDListUC is not null)
                {
                    foreach (int x in nodeIDListUC)
                    {
                        s += $"{x},";
                    }
                }

                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Live update: eAnimUnchained block {entry.BlockID}: " + s, Logging.LogFilterType.BulkDebugLogFile);
                brightTime = (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT;
            }
            else
            {
                brightTime = GlobalConfig.ExternAnimDisplayFrames;
            }

            //break if block not rendered yet
            if (!get_block_nodelist(entry.Address, entry.BlockID, out List<uint>? nodeIDList) || nodeIDList is null)
            {
                //expect to get an incomplete block with exception or animation attempt before static rendering
                if ((entry.entryType == eTraceUpdateType.eAnimExecException))// && (nodeIDList.Count > (int)entry.count))
                {
                    return true;
                }

                return false;
            }

            //add all the nodes+edges in the block to the brightening list
            brighten_node_list(entry, brightTime, nodeIDList);

            //also add brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                brighten_next_block_edge(entry.BlockID, entry.Address);
            }

            ++updateProcessingIndex;

            return true;
        }

        private void process_replay_animation_updates(double optionalStepSize = 0)
        {

            var animationData = InternalProtoGraph.GetSavedAnimationDataReference();
            if (animationData.Count == 0)
            {
                InternalProtoGraph.ReleaseSavedAnimationDataReference();
                Logging.WriteConsole("Ending animation immediately - no animation data");
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
            if (targetAnimIndex >= InternalProtoGraph.UpdateCount)
            {
                targetAnimIndex = InternalProtoGraph.UpdateCount - 1;
            }

            for (; AnimationIndex < targetAnimIndex; AnimationIndex += stepSize)
            {
                int actualIndex = (int)Math.Floor(AnimationIndex);


                if (actualIndex > _lastReplayedIndex)
                {
                    for (var innerReplayIdx = _lastReplayedIndex + 1; innerReplayIdx < actualIndex + 1; innerReplayIdx += 1)
                    {
                        process_replay_update(innerReplayIdx, animationData);
                    }
                    _lastReplayedIndex = actualIndex;
                }
                if (actualIndex >= animationData.Count) break;
            }

            if (AnimationIndex >= animationData.Count - 1)
            {
                ReplayState = REPLAY_STATE.Ended;
            }
        }

        private int _lastReplayedIndex = -1;

        private void process_replay_update(int replayUpdateIndex, List<ANIMATIONENTRY> animationDataList)
        {
            if (replayUpdateIndex >= animationDataList.Count) return;
            ANIMATIONENTRY entry = animationDataList[replayUpdateIndex];

            double stepSize = AnimationRate;
            if (stepSize < 1)
            {
                stepSize = 1;
            }

            //brighten edge between last block and this
            //todo - probably other situations we want to do this apart from a parent exec tag
            if (replayUpdateIndex > 0)
            {
                ANIMATIONENTRY lastentry = animationDataList[replayUpdateIndex - 1];
                if (lastentry.entryType == eTraceUpdateType.eAnimExecTag &&
                    _expectingThunk is false // if an API thunk is being called then this edge will be wrong
                    )
                {
                    brighten_next_block_edge(entry.BlockID, entry.Address);
                }
            }

            //unchained area finished, stop highlighting it
            if (entry.entryType == eTraceUpdateType.eAnimUnchainedResults)
            {
                ProcessRecord piddata = InternalProtoGraph.ProcessData;
                List<InstructionData>? block = piddata.getDisassemblyBlock(entry.BlockID);
                Debug.Assert(block is not null);
                unchainedWaitFrames += calculate_wait_frames(entry.Count * (ulong)block.Count);

                uint maxWait = (uint)Math.Floor(maxWaitFrames / stepSize); //todo test
                if (unchainedWaitFrames > maxWait)
                {
                    unchainedWaitFrames = maxWait;
                }
                remove_unchained_from_animation();


                return;
            }

            //all consecutive unchained areas finished, wait until animation paused appropriate frames
            if (entry.entryType == eTraceUpdateType.eAnimReinstrument)
            {
                remove_unchained_from_animation();
                end_unchained(entry);
                return;
            }


            int brightTime;
            if (entry.entryType == eTraceUpdateType.eAnimUnchained || animBuildingLoop)
            {
                brightTime = (int)Anim_Constants.BRIGHTNESS.KEEP_BRIGHT;
            }
            else
            {
                brightTime = GlobalConfig.AnimationLingerFrames;
            }



            if (!get_block_nodelist(entry.Address, entry.BlockID, out List<uint>? nodeIDList) &&
                entry.entryType != eTraceUpdateType.eAnimExecException)
            {
                if (this.InternalProtoGraph.Terminated)
                {
                    return;
                }
                int sleepTime = 5;
                Thread.Sleep(sleepTime);
                while (!get_block_nodelist(entry.Address, entry.BlockID, out nodeIDList))
                {
                    sleepTime += 10;
                    Thread.Sleep(sleepTime);
                    Logging.WriteConsole($"[rgat] process_replay_update waiting for block 0x{entry.Address:x}");
                    if (rgatState.rgatIsExiting || this.InternalProtoGraph.Terminated)
                    {
                        return;
                    }
                }
            }

            if (nodeIDList is not null && nodeIDList.Any())
            {

                if (InternalProtoGraph.TraceData.HideAPIThunks)
                {
                    if (InternalProtoGraph.NodeList[(int)nodeIDList[^1]].ThunkCaller is true)
                    {
                        brighten_node_list(entry, brightTime, nodeIDList);
                        _expectingThunk = true;
                    }
                    else
                    {
                        if (_expectingThunk && replayUpdateIndex < (animationDataList.Count - 1))
                        {
                            ANIMATIONENTRY nextAnim = animationDataList[replayUpdateIndex + 1];
                            if (nextAnim.edgeCounts?.Count == 1 && nextAnim.BlockID == uint.MaxValue)
                            {
                                brighten_node_list(entry, brightTime, new List<uint>() { (uint)nextAnim.edgeCounts[0].Item2 });
                            }
                            _expectingThunk = false;
                        }
                        else
                        {
                            brighten_node_list(entry, brightTime, nodeIDList);
                        }
                    }
                }
                else
                {
                    //add all the nodes+edges in the block to the brightening list
                    brighten_node_list(entry, brightTime, nodeIDList);
                }
            }

            //brighten edge to next unchained block
            if (entry.entryType == eTraceUpdateType.eAnimUnchained)
            {
                //todo target edges
                //brighten_next_block_edge(entry.blockID, entry.blockAddr);
            }

        }

        bool _expectingThunk = false;


        /*
         Nodes that are continuously lit up due to being blocked or in a busy (unchained) loop
         These pulse
         */
        private ulong calculate_wait_frames(ulong executions)
        {
            //assume 10 instructions per step/frame
            ulong stepSize = (ulong)AnimationRate;
            if (stepSize == 0)
            {
                stepSize = 1;
            }

            ulong frames = (InternalProtoGraph.TotalInstructions / Anim_Constants.ASSUME_INS_PER_BLOCK) / stepSize;

            float proportion = (float)executions / InternalProtoGraph.TotalInstructions;
            ulong waitFrames = (ulong)Math.Floor(proportion * frames);
            return waitFrames;
        }


        /// <summary>
        /// Action the movement of the mousewheel to zoom the graph in or out
        /// </summary>
        /// <param name="delta">How far to zoom the camera</param>
        public void ApplyMouseWheelDelta(float delta)
        {
            CameraState.MainCameraZoom += delta;
        }


        /// <summary>
        /// Move the camera in response to user mouse dragging
        /// </summary>
        /// <param name="delta">How far the mouse was dragged</param>
        public void ApplyMouseDragDelta(Vector2 delta)
        {
            CameraState.MainCameraXOffset -= delta.X;
            CameraState.MainCameraYOffset += delta.Y;
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
        public Matrix4x4 GetViewMatrix() => Matrix4x4.Multiply(CameraState.MainCameraTranslation, CameraState.RotationMatrix);


        /// <summary>
        /// Get the view matrix of the preview camera
        /// </summary>
        /// <returns>View Matrix</returns>
        public Matrix4x4 GetPreviewViewMatrix()
        {
            Vector3 translation = new Vector3(CameraState.PreviewCameraXOffset, CameraState.PreviewCameraYOffset, CameraState.PreviewCameraZoom);
            Matrix4x4 viewMatrix = Matrix4x4.CreateTranslation(translation);
            viewMatrix = Matrix4x4.Multiply(viewMatrix, CameraState.RotationMatrix);
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
                _previewTexture1?.Dispose();
                _previewFramebuffer2?.Dispose();
                _previewTexture2?.Dispose();
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
            Stopwatch st = new();
            bool doneRegen = false;
            if (edgesCount > RenderedEdgeCount || StaleEdgeData)
            {
                StaleEdgeData = false;

                st.Start();
                LayoutState.Lock.EnterWriteLock();
                try
                {
                    LayoutState.RegenerateEdgeDataBuffers(this);
                    RenderedEdgeCount = (uint)edgesCount;
                }
                catch (Exception e)
                {
                    Logging.RecordException($"Exception regenerating edge buffers: {e.Message}", e);
                }
                finally
                {
                    LayoutState.Lock.ExitWriteLock();
                }
                st.Stop();
                doneRegen = true;
            }

            int graphNodeCount = RenderedNodeCount();
            if (ComputeBufferNodeCount < graphNodeCount)
            {
                st.Restart();
                LayoutState.AddNewNodesToComputeBuffers(graphNodeCount, this);
                st.Stop();

                if (!doneRegen)
                {
                    st.Restart();
                    LayoutState.Lock.EnterWriteLock();
                    LayoutState.RegenerateEdgeDataBuffers(this); //todo change to upgradread
                    LayoutState.Lock.ExitWriteLock();
                    st.Stop();
                }
            }
            //Console.WriteLine($"Addnewedgestolayout took regen1: {v1}, addnodes:{v2} regen2:{v3}");

        }


        /// <summary>
        /// Signals that the user has changed the highlighted nodes
        /// </summary>
        public bool HighlightsChanged;
        private readonly Dictionary<int, Vector4> _customHighlightColours = new Dictionary<int, Vector4>();
        /// <summary>
        /// Get the highlight colour of the node
        /// </summary>
        /// <param name="nodeIdx">Index of the node</param>
        /// <returns>Colour of the node, if a custom colour was found, otherwise null</returns>
        public Vector4? GetCustomHighlightColour(int nodeIdx)
        {
            lock (textLock)
            {
                if (_customHighlightColours.TryGetValue(nodeIdx, out Vector4 col))
                {
                    return col;
                }

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
                        Logging.WriteConsole($"Error: Unknown highlight type: {highlightType}");
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

        /// <summary>
        /// When the last compute cycle was done on this graph
        /// </summary>
        public long LastComputeTime;
        private int _computeBufferNodeCount;
        /// <summary>
        /// Number of nodes added to the compute buffer
        /// </summary>
        public int ComputeBufferNodeCount
        {
            get => _computeBufferNodeCount;
            set => _computeBufferNodeCount = value;
        }

        /// <summary>
        /// How many edges have been added to compute buffers
        /// </summary>
        public uint RenderedEdgeCount; 

        private bool StaleEdgeData = false;

        /// <summary>
        /// The edges have changed or their plot datastructures need regenerating
        /// </summary>
        public void RegenerateEdges() => StaleEdgeData = true;

        //must hold read lock
        /// <summary>
        /// Unhighlight nodes
        /// </summary>
        /// <param name="nodeidxs">The nodes to unhighlight</param>
        /// <param name="highlightType">The type of highlight being removed</param>
        public void RemoveHighlightedNodes(List<uint> nodeidxs, HighlightType highlightType)
        {
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


        /// <summary>
        /// fetch changes to highlights that need to be applied to the attributes buffers
        /// </summary>
        /// <param name="added">new node highlight indexes</param>
        /// <param name="removed">removed node highlight indexes</param>
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


        /// <summary>
        /// Get recent extens being animated
        /// </summary>
        /// <param name="risingExterns">List of node index/strings of rising labels</param>
        /// <param name="risingLingering">List of node index/strings of lingering labels</param>
        public void GetActiveExternRisings(out List<Tuple<uint, string>> risingExterns, out List<Tuple<uint, string>> risingLingering)
        {
            lock (animationLock)
            {
                risingExterns = _RisingSymbols.ToList();
                _RisingSymbols.Clear();

                risingLingering = _RisingSymbolsLingering.ToList();
            }
        }

        private int _furthestNodeIdx = -1;
        /// <summary>
        /// The absolute largest dimension of any node on the graph
        /// Use as a rough guide to the scale of the current plot 
        /// </summary>
        public float FurthestNodeDimension { get; private set; } = 0;

        /// <summary>
        /// Sets the coordinate of the furthest node from the origin
        /// Used for drawing the force directed layout wireframe, where the distance of this node from the origin is used as the radius
        /// </summary>
        /// <param name="index">Index of the far node</param>
        /// <param name="farDimension">Greatest (absolute) coordinate of any node</param>
        public void SetFurthestNodeDimension(int index, float farDimension)
        {
            _furthestNodeIdx = index;
            FurthestNodeDimension = farDimension;
        }

        private void AddRisingSymbol(uint nodeIdx, int callIndex, int lingerFrames)
        {
            NodeData? n = InternalProtoGraph.GetNode(nodeIdx);
            Debug.Assert(n is not null);
            if (n.Label is null)
            {
                n.CreateLabel(this, callIndex);
                if (n.Label is null)
                {
                    return;
                }
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
        private void AddPulseActiveNode(uint nodeIdx)
        {
            lock (animationLock)
            {
                if (!_PulseActiveNodes.Contains(nodeIdx))
                {
                    _PulseActiveNodes.Add(nodeIdx);
                }
            }
        }


        /// <summary>
        /// this node is active in a loop or blocking, keep it lit up until deactivated
        /// </summary>
        /// <param name="nodeIdx">node index</param>
        private void AddContinuousActiveNode(uint nodeIdx)
        {
            lock (animationLock)
            {
                if (!_LingeringActiveNodes.Contains(nodeIdx))
                {
                    _LingeringActiveNodes.Add(nodeIdx);
                }
            }
        }

        private void RemoveContinuousActiveNode(uint nodeIdx)
        {
            lock (animationLock)
            {
                _LingeringActiveNodes.RemoveAll(n => n == nodeIdx);
            }
        }

        private void remove_unchained_from_animation()
        {
            lock (animationLock)
            {
                _DeactivatedNodes.AddRange(_LingeringActiveNodes);
                _LingeringActiveNodes.Clear();
                _RisingSymbolsLingering.Clear();
            }
        }

        private void ResetAllActiveAnimatedAlphas()
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
            if (newStyle == ActiveLayoutStyle)
            {
                return false;
            }

            lock (_renderLock)
            {
                _layoutCameraStates[LayoutState.Style] = CameraState;
            }
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
        private bool animBuildingLoop = false;

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


        private bool _textEnabled = false;
        /// <summary>
        /// Text is being drawn
        /// </summary>
        public bool Opt_TextEnabled
        {
            get => _textEnabled;
            set
            {
                _textEnabled = value;
                if (_textEnabled)
                {
                    RegenerateLabels();
                }
            }
        }

        private bool _textEnabledIns = true;
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

        private bool _textEnabledSym = true;
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
        private bool _showNodeAdresses = false;


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
        private bool _showNodeIndexes = false;

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
        private bool _showSymbolModules = false;

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
        private bool _showSymbolModulePaths = false;

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
        private Vector3 _unprojWorldCoordTL, _unprojWorldCoordBR;


        /// <summary>
        /// Gather values for calculating the camera indicator box in the preview window
        /// </summary>
        /// <param name="graphWidgetSize">Size of the main graph widget</param> // weird parameter?
        public void UpdatePreviewVisibleRegion(Vector2 graphWidgetSize)
        {

            Matrix4x4 proj = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, graphWidgetSize.X / graphWidgetSize.Y, CameraClippingNear, CameraClippingFar);
            Matrix4x4 world = CameraState.RotationMatrix;

            Matrix4x4.Invert(proj, out Matrix4x4 invProj);
            Matrix4x4.Invert(world * CameraState.MainCameraTranslation, out Matrix4x4 invWV);

            Vector4 ClipAfterProj = Vector4.Transform(new Vector3(0, 0, CameraState.MainCameraZoom), proj);
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

            Matrix4x4 worldP = CameraState.RotationMatrix;
            Matrix4x4 worldviewP = worldP * CameraState.PreviewCameraTranslation;

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
            Vector4 ClipAfterProj = Vector4.Transform(new Vector3(0, 0, CameraState.PreviewCameraZoom), previewProjection);
            Vector3 NDC = Vector3.Divide(new Vector3(ClipAfterProj.X, ClipAfterProj.Y, ClipAfterProj.Z), ClipAfterProj.W);

            Matrix4x4 worldP = CameraState.RotationMatrix;
            Matrix4x4 viewP = CameraState.PreviewCameraTranslation;
            Matrix4x4.Invert(worldP * viewP, out Matrix4x4 invVWP);
            Matrix4x4.Invert(previewProjection, out Matrix4x4 invPrevProj);

            Matrix4x4 projMain = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, mainGraphWidgetSize.X / mainGraphWidgetSize.Y, CameraClippingNear, CameraClippingFar);
            Matrix4x4 worldMain = CameraState.RotationMatrix;
            Matrix4x4 viewMain = CameraState.MainCameraTranslation;

            Vector3 clickWorldCoord = GraphicsMaths.ScreenToWorldCoord(pos, NDC.Z, ClipAfterProj.W, invVWP, invPrevProj, previewSize);
            Vector2 clickMainViewCoord = GraphicsMaths.WorldToScreenCoord(clickWorldCoord, worldMain * viewMain, projMain, mainGraphWidgetSize);

            float XDiff = (mainGraphWidgetSize.X / 2f) - clickMainViewCoord.X;
            float YDiff = (mainGraphWidgetSize.Y / 2f) - clickMainViewCoord.Y;
            float ZoomMultiplier = 1 + Math.Abs(CameraState.MainCameraZoom / 50000);
            CameraState.MainCameraXOffset += (XDiff * ZoomMultiplier);
            CameraState.MainCameraYOffset += (YDiff * ZoomMultiplier);
        }

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
                graphtexture = _previewTexture1!;
            }
            else
            {
                graphtexture = _previewTexture2!;
            }
            textureLock.ExitReadLock();
        }


        /// <summary>
        /// Update the graph computation time stats
        /// </summary>
        /// <param name="stepMSTotal">Time taken for the latest round of GPU computation in Milliseconds</param>
        /// <param name="positionSetupTime">Time taken setting up the latest round of position computation in Milliseconds, or null if not performed</param>
        /// <param name="positionShaderTime">Time taken for the latest round of position computation in Milliseconds, or null if not performed</param>
        /// <param name="velocitySetupTime">Time taken setting up the latest round of velocity computation in Milliseconds, or null if not performed</param>
        /// <param name="velocityShaderTime">Time taken for the latest round of velocity computation in Milliseconds, or null if not performed</param>
        /// <param name="attributeSetupTime">Time taken setting the latest round of attribute computation in Milliseconds, or null if not performed</param>
        /// <param name="attributeShaderTime">Time taken for the latest round of attribute computation in Milliseconds, or null if not performed</param>
        public void RecordComputeTime(double stepMSTotal,
            double? positionSetupTime, double? positionShaderTime,
            double? velocitySetupTime, double? velocityShaderTime,
            double? attributeSetupTime, double? attributeShaderTime)
        {
            //Debug.Assert(stepMSTotal >= (positionSetupTime + positionShaderTime + velocitySetupTime + velocityShaderTime + attributeSetupTime + attributeShaderTime));
            ComputeLayoutTime += stepMSTotal;
            ComputeLayoutSteps += 1;

            if (positionShaderTime is not null)
            {
                PositionSetupTime += positionSetupTime!.Value;
                PositionShaderTime += positionShaderTime.Value;
                PositionSteps += 1;
                PositionNodes += this._computeBufferNodeCount;
            }

            if (velocityShaderTime is not null)
            {
                VelocitySetupTime += velocitySetupTime!.Value;
                VelocityShaderTime += velocityShaderTime.Value;
                VelocitySteps += 1;
                VelocityNodes += this._computeBufferNodeCount;
            }

            if (attributeShaderTime is not null)
            {
                AttributeSetupTime += attributeSetupTime!.Value;
                AttributeShaderTime += attributeShaderTime.Value;
                AttributeSteps += 1;
                AttributeNodes += this._computeBufferNodeCount;
            }

        }

        /// <summary>
        /// Reset the tracking info for layout time/steps
        /// </summary>
        public void ResetLayoutStats()
        {
            ComputeLayoutTime = 0.1;
            ComputeLayoutSteps = 0;
            VelocitySetupTime = 0;
            VelocityShaderTime = 0;
            VelocitySteps = 0;
            VelocityNodes = 0;
            PositionSetupTime = 0;
            PositionShaderTime = 0;
            PositionSteps = 0;
            PositionNodes = 0;
            AttributeSetupTime = 0;
            AttributeShaderTime = 0;
            AttributeSteps = 0;
            AttributeNodes = 0;
        }

        /// <summary>
        /// How many MS were spent in compute shaders for this layout
        /// </summary>
        public double ComputeLayoutTime { get; private set; } = 0.1;
        /// <summary>
        /// How many rounds of computation were completed for this layout
        /// </summary>
        public long ComputeLayoutSteps { get; private set; } = 0;

        /// <summary>
        /// Time spent preparing buffers for the velocity shader for this layout
        /// </summary>
        public double VelocitySetupTime { get; private set; } = 0;
        /// <summary>
        /// Time spent in the velocity shader for this layout
        /// </summary>
        public double VelocityShaderTime { get; private set; } = 0;
        /// <summary>
        /// Velocity shader passes for this layout
        /// </summary>
        public uint VelocitySteps { get; private set; } = 0;
        /// <summary>
        /// Total nodes the velocity shader has been run on
        /// </summary>
        public long VelocityNodes { get; private set; } = 0;


        /// <summary>
        /// Time spent preparing buffers for the position shader for this layout
        /// </summary>
        public double PositionSetupTime { get; private set; } = 0;
        /// <summary>
        /// Time spent in the position shader for this layout
        /// </summary>
        public double PositionShaderTime { get; private set; } = 0;
        /// <summary>
        /// Position shader passes for this layout
        /// </summary>
        public uint PositionSteps { get; private set; } = 0;
        /// <summary>
        /// Total nodes the position shader has been run on
        /// </summary>
        public long PositionNodes { get; private set; } = 0;



        /// <summary>
        /// Time spent preparing buffers for the attribute shader for this layout
        /// </summary>
        public double AttributeSetupTime { get; private set; } = 0;
        /// <summary>
        /// Time spent in the attribute shader for this layout
        /// </summary>
        public double AttributeShaderTime { get; private set; } = 0;
        /// <summary>
        /// Attribute shader passes for this layout
        /// </summary>
        public uint AttributeSteps { get; private set; } = 0;
        /// <summary>
        /// Total nodes the attribute shader has been run on
        /// </summary>
        public long AttributeNodes { get; private set; } = 0;


        /*
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
        */
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
        private ulong unchainedWaitFrames = 0;
        private readonly uint maxWaitFrames = 20; //limit how long we spend 'executing' busy code in replays

        /// <summary>
        /// Which trace record item the animation is running in
        /// </summary>
        public double AnimationIndex { get; private set; }

        private readonly List<uint> _PulseActiveNodes = new List<uint>();
        private readonly List<uint> _LingeringActiveNodes = new List<uint>();
        private readonly List<Tuple<uint, string>> _RisingSymbols = new List<Tuple<uint, string>>();
        private readonly List<Tuple<uint, string>> _RisingSymbolsLingering = new List<Tuple<uint, string>>();
        private readonly List<uint> _DeactivatedNodes = new List<uint>();// Array.Empty<uint>();
        private readonly object animationLock = new object();

        /// <summary>
        /// A custom animation position set by the user clicking the replay bar
        /// </summary>
        public int _userSelectedAnimPosition = -1;

        /// <summary>
        /// Animation replay state
        /// </summary>
        public REPLAY_STATE ReplayState = REPLAY_STATE.Ended;
        private int updateProcessingIndex = 0;

        /// <summary>
        /// main lock for access to this objects data
        /// </summary>
        protected readonly object textLock = new object();

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
        private readonly List<List<int>> _graphStructureBalanced = new List<List<int>>();

        /// <summary>
        /// The raw list of nodes with a one way edge they connect to
        /// This is used for drawing nodes and edges
        /// </summary>
        private readonly List<List<int>> _graphStructureLinear = new List<List<int>>();

        /// <summary>
        /// Force-directed layout activity of this graph
        /// </summary>
        public float Temperature = 100f;

    }
}
