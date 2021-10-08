using ImGuiNET;
using rgat.Shaders.SPIR_V;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.VeldridGraphBuffers;

namespace rgat
{
    /// <summary>
    /// A widget for displaying a rendered graph plot
    /// </summary>
    internal class GraphPlotWidget : IDisposable
    {
        public PlottedGraph? ActiveGraph { get; private set; }

        private readonly QuickMenu _QuickMenu;
        private readonly ImGuiController _controller;
        private readonly GraphLayoutEngine _layoutEngine;
        private readonly rgatState _clientState;

        public GraphLayoutEngine LayoutEngine => _layoutEngine;
        public bool Exiting = false;
        private GraphicsDevice? _gd;
        private ResourceFactory? _factory;
        public Vector2 WidgetSize { get; private set; }

        private TextureView? _imageTextureView;
        private readonly ReaderWriterLockSlim _graphLock = new ReaderWriterLockSlim();
        private Framebuffer? _outputFramebuffer1, _outputFramebuffer2, _pickingFrameBuffer;
        private bool _processingAnimatedGraph;

        /// <summary>
        /// Edges pipeline = line list or line strp
        /// Points pipeline = visible nodes where we draw sphere/etc texture
        /// Picking pipleine = same as points but different data, not drawn to screen. Seperate shaders to reduce branching
        /// Font pipeline = triangles
        /// </summary>
        private Pipeline? _edgesPipelineRelative, _edgesPipelineRaw, _pointsPipeline, _pickingPipeline, _fontPipeline;
        private ResourceLayout? _coreRsrcLayout, _nodesEdgesRsrclayout, _fontRsrcLayout;
        private Texture? _outputTexture1, _outputTexture2, _testPickingTexture, _pickingStagingTexture;

        //vert/frag rendering buffers
        private ResourceSet? _crs_font;
        private DeviceBuffer? _EdgeVertBuffer, _EdgeIndexBuffer;
        private DeviceBuffer? _RawEdgeVertBuffer, _RawEdgeIndexBuffer;
        private DeviceBuffer? _NodeVertexBuffer, _NodePickingBuffer, _NodeIndexBuffer;
        private DeviceBuffer? _FontVertBuffer, _FontIndexBufferAll;
        private DeviceBuffer? _paramsBuffer;
        private int latestWrittenTexture = 1;

        public Vector2 WidgetPos { get; private set; }

        private Vector2 _MousePos;

        public int MouseoverNodeID { get; private set; } = -1;


        /// <summary>
        /// A widget for displaying a rendered graph plot
        /// </summary>
        /// <param name="clientState">The rgat clientstate</param>
        /// <param name="controller">The ImGui controller</param>
        /// <param name="initialSize">The initial size of the widget</param>
        public GraphPlotWidget(rgatState clientState, ImGuiController controller, Vector2? initialSize = null)
        {
            _clientState = clientState;
            _controller = controller;
            _QuickMenu = new QuickMenu(_controller);

            WidgetSize = initialSize ?? new Vector2(400, 400);
            _layoutEngine = new GraphLayoutEngine("Main");
        }


        /// <summary>
        /// Init the graphics device controller
        /// </summary>
        /// <param name="gdev">A Veldrid GraphicsDevice</param>
        public void Init(GraphicsDevice gdev)
        {
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            _layoutEngine.Init(gdev);
            _QuickMenu.Init(_gd);
            _imageTextureView = _controller.IconTexturesView;  //todo crash if closed early in load
            SetupRenderingResources();
        }


        /// <summary>
        /// Called whenever the widget opens/closes an inner dialog
        /// </summary>
        /// <param name="action">Function to call when dialog is opened/closed. Param is open/closed state.</param>
        public void SetStateChangeCallback(Action<bool> action)
        {
            _dialogStateChangeCallback = action;
            _QuickMenu.SetStateChangeCallback(action);
        }

        private Action<bool>? _dialogStateChangeCallback = null;

        public void Dispose()
        {
            Exiting = true;
        }

        /// <summary>
        /// Apply a delta to the main camera zoom
        /// If shift is held, multiply by the shift modifier
        /// If control is held, multiply by the control modifier
        /// These modifiers are multiplicative
        /// </summary>
        /// <param name="wheelClicks">Zoom delta (expressed as mousewheel roll units)</param>
        public void ApplyZoom(float wheelClicks)
        {
            ActiveGraph?.ApplyMouseWheelDelta(wheelClicks * CONSTANTS.UI.GRAPH_ZOOM_MOUSEWHEEL_MULTIPLIER);
        }

        private bool _isInputTarget = false;
        public void ApplyMouseDrag(Vector2 delta)
        {
            if (_isInputTarget)
            {
                ActiveGraph?.ApplyMouseDragDelta(delta);
            }
        }
        public void ApplyMouseRotate(Vector2 delta)
        {
            if (ActiveGraph != null)
            {
                _yawDelta -= delta.X * 0.03f;
                _pitchDelta -= delta.Y * 0.03f;
            }
        }


        public bool MouseInWidget()
        {
            Vector2 MousePos = ImGui.GetMousePos();
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();

            if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + WidgetSize.X))
            {
                if (MousePos.Y >= WidgetPos.Y && MousePos.Y < (WidgetPos.Y + WidgetSize.Y))
                {
                    return true;
                }
            }
            return false;
        }


        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// Must have read lock to call
        /// </summary>
        private bool CenterGraphInFrameStep(Matrix4x4 worldView, out float MaxRemaining)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null || graph.LayoutState.Initialised is false)
            {
                MaxRemaining = 0;
                return false;
            }
            if (graph.CenteringInFrame == PlottedGraph.CenteringMode.Centering)
            {
                graph.CenteringSteps += 1;
            }

            if (float.IsInfinity(graph.CameraState.MainCameraZoom))
            {
                graph.CameraState.MainCameraZoom = 0;
                graph.CameraState.MainCameraXOffset = 0;
                graph.CameraState.MainCameraYOffset = 0;
            }

            GraphLayoutEngine.GetWidgetFitOffsets(WidgetSize, graph, false, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets);
            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 80, targYpadding = 35;
            float tolerance = (float)Math.Exp(Math.Log(graph.CenteringSteps));

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < graphDepth)
            {
                delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                float maxdelta = Math.Max(delta, 35);
                graph.CameraState.MainCameraZoom -= maxdelta;
                MaxRemaining = maxdelta;
                return false;
            }

            //too zoomed in, zoom out
            if ((xoffsets.X < targXpadding && xoffsets.Y < targXpadding) || (yoffsets.X < targYpadding && yoffsets.Y < targYpadding))
            {
                if (xoffsets.X < targXpadding)
                {
                    delta = Math.Min(targXpadding / 2, (targXpadding - xoffsets.X) / 3f);
                }
                else
                {
                    delta = Math.Min(targYpadding / 2, (targYpadding - yoffsets.Y) / 1.3f);
                }
                delta += tolerance;

                if (delta > 50)
                {
                    graph.CameraState.MainCameraZoom -= delta;// tolerance);
                    MaxRemaining = Math.Abs(delta);
                    return false;
                }
                else
                {
                    zdelta = -1 * delta;
                }
            }

            //too zoomed out, zoom in
            if ((xoffsets.X > targXpadding && xoffsets.Y > targXpadding) && (yoffsets.X > targYpadding && yoffsets.Y > targYpadding))
            {
                if (zoffsets.X > graphDepth)
                {
                    zdelta += (zoffsets.X - graphDepth + tolerance) / 8;
                }
            }

            //too far left, move right
            if (xoffsets.X < (targXpadding - tolerance))
            {
                float diff = targXpadding - xoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta += delta + tolerance;
            }

            //too far right, move left
            if (xoffsets.Y < (targXpadding - tolerance))
            {
                float diff = targXpadding - xoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta -= delta + tolerance;
            }

            //off center, center it
            float XDiff = xoffsets.X - xoffsets.Y;
            if (Math.Abs(XDiff) > (40 + tolerance))
            {
                delta = Math.Max(Math.Abs(XDiff / 2), 15);
                if (XDiff > 0)
                {
                    xdelta -= delta + tolerance;
                }
                else
                {
                    xdelta += delta + tolerance;
                }
            }


            if (yoffsets.X < (targYpadding - tolerance))
            {
                float diff = targYpadding - yoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta += delta + tolerance;
            }

            if (yoffsets.Y < (targYpadding - tolerance))
            {
                float diff = targYpadding - yoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta -= delta + tolerance;
            }

            float YDiff = yoffsets.X - yoffsets.Y;
            if (Math.Abs(YDiff) > (40 + tolerance))
            {
                delta = Math.Max(Math.Abs(YDiff / 2), 15);
                if (YDiff > 0)
                {
                    ydelta -= delta + tolerance;
                }
                else
                {
                    ydelta += delta + tolerance;
                }
            }


            float actualXdelta = Math.Abs(xdelta);
            if (xdelta > 0)
            {
                graph.CameraState.MainCameraXOffset += actualXdelta;
            }
            else
            {
                graph.CameraState.MainCameraXOffset -= actualXdelta;
            }

            float actualYdelta = Math.Abs(ydelta);
            if (ydelta > 0)
            {
                graph.CameraState.MainCameraYOffset += actualYdelta;
            }
            else
            {
                graph.CameraState.MainCameraYOffset -= actualYdelta;
            }

            float actualZdelta = Math.Abs(zdelta);
            if (zdelta > 0)
            {
                graph.CameraState.MainCameraZoom += actualZdelta;
            }
            else
            {
                if (zdelta < 0)
                {
                    actualZdelta *= 10;
                }

                graph.CameraState.MainCameraZoom -= actualZdelta;
            }

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));

            int acceptableDifference = 10 + graph.CenteringSteps;
            bool isAcceptable = Math.Abs(xdelta) < acceptableDifference && Math.Abs(ydelta) < acceptableDifference && Math.Abs(zdelta) < acceptableDifference;

            //Now the big changes are done and it's pretty good, run again with low tolerances for finer adjustments
            if (isAcceptable && graph.CenteringSteps > 10)
            {
                graph.CenteringSteps = 5;
                isAcceptable = false;
            }

            if (isAcceptable)
                graph.CenteringSteps = 0;
            return isAcceptable;
        }

        public bool QuickMenuActive => _QuickMenu.Expanded == true;

        public bool AlertRawKeyPress(Tuple<Key, ModifierKeys> keyModTuple)
        {
            if (_QuickMenu.Expanded)
            {
                bool swallowKeypress = _QuickMenu.KeyPressed(keyModTuple, out Tuple<string, string>? ActivatedShortcut);
                if (ActivatedShortcut != null)
                {
                    DisplayShortcutActivation(shortcut: ActivatedShortcut.Item1, action: ActivatedShortcut.Item2);
                }
                return swallowKeypress;
            }

            return false;
        }

        private struct KEYPRESS_CAPTION
        {
            public string message;
            public Key key;
            public ModifierKeys modifiers;
            public long startedMS;
            public long repeats;
            public string MenuShortut;
        }

        private List<KEYPRESS_CAPTION> _keypressCaptions = new List<KEYPRESS_CAPTION>();

        private void DisplayShortcutActivation(string shortcut, string action)
        {
            //replace the keypress that activated the menu with the shortcut
            if (_keypressCaptions.Any() && (_keypressCaptions[^1].key.ToString()[0] == shortcut[0]))
            {
                _keypressCaptions.RemoveAt(_keypressCaptions.Count - 1);
            }
            _keypressCaptions.Add(new KEYPRESS_CAPTION()
            {
                message = action,
                startedMS = DateTimeOffset.Now.ToUnixTimeMilliseconds(),
                repeats = 1,
                MenuShortut = shortcut
            });
        }

        private void DisplayKeyPress(Tuple<Key, ModifierKeys> keyPressed, string messageCaption)
        {
            if (_keypressCaptions.Count > 0 && _keypressCaptions[^1].message == messageCaption)
            {
                var lastPress = _keypressCaptions[^1];
                lastPress.repeats += 1;
                lastPress.startedMS = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            }
            else
            {
                _keypressCaptions.Add(new KEYPRESS_CAPTION()
                {
                    message = messageCaption,
                    key = keyPressed.Item1,
                    modifiers = keyPressed.Item2,
                    startedMS = DateTimeOffset.Now.ToUnixTimeMilliseconds(),
                    repeats = 1
                });
            }
        }


        public void AlertKeybindPressed(Tuple<Key, ModifierKeys>? keyPressed, KeybindAction boundAction)
        {
            _graphLock.EnterReadLock();

            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                _graphLock.ExitReadLock();
                return;
            }

            string? resultText = null;
            float shiftModifier = ImGui.GetIO().KeyShift ? 1 : 0;
            switch (boundAction)
            {
                case KeybindAction.ToggleHeatmap:
                    ToggleRenderingMode(eRenderingMode.eHeatmap);
                    resultText = _renderingMode == eRenderingMode.eHeatmap ? "Activated" : "Deactivated";
                    break;

                case KeybindAction.ToggleConditionals:
                    ToggleRenderingMode(eRenderingMode.eConditionals);
                    resultText = _renderingMode == eRenderingMode.eConditionals ? "Activated" : "Deactivated";
                    break;

                case KeybindAction.MoveUp:

                    float delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraState.MainCameraYOffset += delta;
                    break;

                case KeybindAction.MoveDown:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraState.MainCameraYOffset -= delta;
                    break;

                case KeybindAction.MoveLeft:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraState.MainCameraXOffset -= delta;
                    break;

                case KeybindAction.MoveRight:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraState.MainCameraXOffset += delta;
                    break;

                case KeybindAction.RollGraphZAnti:
                    {
                        delta = 0.07f;
                        delta += (shiftModifier * 0.13f);
                        _rollDelta += delta;
                        break;
                    }

                case KeybindAction.RollGraphZClock:
                    {
                        delta = 0.07f;
                        delta += (shiftModifier * 0.13f);
                        _rollDelta += -1 * delta;
                        break;
                    }

                case KeybindAction.YawYRight:
                    {
                        _yawDelta += 0.04f + (shiftModifier * 0.13f);
                        break;
                    }

                case KeybindAction.YawYLeft:
                    {
                        _yawDelta += -1 * (0.04f + (shiftModifier * 0.13f));
                        break;
                    }

                case KeybindAction.PitchXBack:
                    {
                        _pitchDelta += 0.06f + (shiftModifier * 0.13f);
                        break;
                    }
                case KeybindAction.PitchXFwd:
                    {
                        _pitchDelta += -1 * (0.06f + (shiftModifier * 0.13f));
                        break;
                    }

                case KeybindAction.CenterFrame:
                    graph.ToggleCentering(false);
                    resultText = graph.CenteringInFrame is not PlottedGraph.CenteringMode.Inactive ? "Activated" : "Deactivated";
                    break;

                case KeybindAction.LockCenterFrame:
                    graph.ToggleCentering(true);
                    resultText = graph.CenteringInFrame is not PlottedGraph.CenteringMode.Inactive ? "Activated" : "Deactivated";
                    break;

                case KeybindAction.RaiseForceTemperature:
                    graph.IncreaseTemperature();
                    break;

                case KeybindAction.ToggleAllText:
                    graph.Opt_TextEnabled = !graph.Opt_TextEnabled;
                    resultText = graph.Opt_TextEnabled ? "Visible" : "Hidden";
                    break;

                case KeybindAction.ToggleInsText:
                    graph.Opt_TextEnabledIns = !graph.Opt_TextEnabledIns;
                    resultText = graph.Opt_TextEnabledIns ? "Visible" : "Hidden";
                    break;

                case KeybindAction.ToggleLiveText:
                    graph.Opt_TextEnabledLive = !graph.Opt_TextEnabledLive;
                    resultText = graph.Opt_TextEnabledLive ? "Visible" : "Hidden";
                    break;

                case KeybindAction.Cancel:
                    _QuickMenu.CancelPressed();
                    break;

                case KeybindAction.QuickMenu:
                    {
                        _QuickMenu.MenuPressed();
                        break;
                    }
                default:
                    break;
            }

            if (GlobalConfig.ShowKeystrokes)
            {
                string caption = boundAction.ToString();
                if (resultText != null)
                {
                    caption += $": {resultText}";
                }

                if (keyPressed is not null)
                    DisplayKeyPress(keyPressed, caption);
            }

            _graphLock.ExitReadLock();
        }




        private float _pitchDelta, _yawDelta, _rollDelta = 0;

        /// <summary>
        /// Must hold read lock
        /// </summary>
        /// <param name="proj"></param>
        /// <param name="view"></param>
        /// <param name="world"></param>
        private void UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                proj = Matrix4x4.Identity;
                view = Matrix4x4.Identity;
                world = Matrix4x4.Identity;
                return;
            }

            if (graph.CameraClippingFar <= graph.CameraClippingNear)
            {
                graph.CameraClippingFar = graph.CameraClippingNear + 1;
            }

            proj = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, WidgetSize.X / WidgetSize.Y, graph.CameraClippingNear, graph.CameraClippingFar);

            Matrix4x4 pitch = Matrix4x4.CreateFromAxisAngle(Vector3.UnitX, _pitchDelta);
            Matrix4x4 yaw = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, _yawDelta);
            Matrix4x4 roll = Matrix4x4.CreateFromAxisAngle(Vector3.UnitZ, _rollDelta);
            _pitchDelta = 0; _yawDelta = 0f; _rollDelta = 0;

            Matrix4x4 offsetRotation = pitch * yaw * roll;

            world = graph.CameraState.RotationMatrix * offsetRotation;

            view = graph.CameraState.MainCameraTranslation;
            graph.CameraState.RotationMatrix = world;
        }

        Stopwatch st = new();

        /// <summary>
        /// Write the rendered graph/HUD items to the draw list
        /// </summary>
        /// <param name="graphSize">Size of the graph area being drawn</param>
        /// <param name="graph">The graph being drawn</param>
        public void Draw(Vector2 graphSize, PlottedGraph? graph)
        {
            st.Restart();
            _graphLock.EnterReadLock();
            st.Stop();
            if (st.ElapsedMilliseconds > 5)
                Console.WriteLine($"gpw:Draw _graphLock contended for {st.ElapsedMilliseconds} ms");


            if (graph != ActiveGraph)
            {
                ActiveGraph = graph;
            }

            if (ActiveGraph != null)
            {
                st.Restart();
                DrawGraphImage();
                st.Stop();
                if (st.ElapsedMilliseconds > 5)
                    Console.WriteLine($"drawgraphimage took {st.ElapsedMilliseconds} ms");
            }

            st.Restart();
            DrawHUD(graphSize, ActiveGraph);
            st.Stop();
            if (st.ElapsedMilliseconds > 5)
                Console.WriteLine($"DrawHUD took {st.ElapsedMilliseconds} ms");
            _graphLock.ExitReadLock();
        }


        /// <summary>
        /// Get a framebuffer we can safely draw to
        /// Must hold upgradable read lock
        /// </summary>
        /// <param name="drawtarget"></param>
        private void GetOutputFramebuffer(out Framebuffer drawtarget)
        {
            _graphLock.EnterWriteLock();
            if (latestWrittenTexture == 1)
            {
                if (GlobalConfig.BulkLog) Logging.RecordLogEvent($"GetLatestTexture setting draw target to texture 2 --->", Logging.LogFilterType.BulkDebugLogFile);
                drawtarget = _outputFramebuffer2!;
            }
            else
            {
                if (GlobalConfig.BulkLog) Logging.RecordLogEvent("GetLatestTexture setting draw target to texture 1 --->", Logging.LogFilterType.BulkDebugLogFile);
                drawtarget = _outputFramebuffer1!;
            }
            _graphLock.ExitWriteLock();
        }


        /// <summary>
        /// Drawing is complete. Release the write lock so it can be displayed on the screen
        /// The other framebuffer will become locked for writing
        /// </summary>
        private void ReleaseOutputFramebuffer()
        {
            _graphLock.EnterWriteLock();
            latestWrittenTexture = (latestWrittenTexture == 1) ? 2 : 1;
            if (GlobalConfig.BulkLog) Logging.RecordLogEvent($"ReleaseOutputFramebuffer set latest written graph texture to {latestWrittenTexture} <----", Logging.LogFilterType.BulkDebugLogFile);

            _graphLock.ExitWriteLock();
        }


        /// <summary>
        /// Get the most recently drawn framebuffer for displaying to the user
        /// </summary>
        /// <param name="graphtexture">Texture of the framebuffer contents</param>
        private void GetLatestTexture(out Texture graphtexture)
        {
            if (latestWrittenTexture == 1)
            {
                if (GlobalConfig.BulkLog) Logging.RecordLogEvent($"GetLatestTexture {ActiveGraph?.TID}  Returning latest written graph texture 1", Logging.LogFilterType.BulkDebugLogFile);
                graphtexture = _outputTexture1!;
            }
            else
            {
                if (GlobalConfig.BulkLog) Logging.RecordLogEvent($"GetLatestTexture {ActiveGraph?.TID}  Returning latest written graph texture 2", Logging.LogFilterType.BulkDebugLogFile);
                graphtexture = _outputTexture2!;
            }
        }


        /// <summary>
        /// Initialise graphics resources
        /// </summary>
        private unsafe void SetupRenderingResources()
        {
            Debug.Assert(_gd is not null, "Init not called");
            ResourceFactory factory = _gd.ResourceFactory;
            _paramsBuffer = TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<GraphShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "GraphPlotparamsBuffer");

            _coreRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));

            _nodesEdgesRsrclayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeTextures", ResourceKind.TextureReadOnly, ShaderStages.Fragment)));


            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription
            {
                BlendState = BlendStateDescription.SingleAlphaBlend,
                DepthStencilState = DepthStencilStateDescription.DepthOnlyLessEqual,
                RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: false,
                scissorTestEnabled: false),
                ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout },
                ShaderSet = SPIRVShaders.CreateNodeShaders(_gd, out _NodeVertexBuffer, out _NodeIndexBuffer)
            };

            Debug.Assert(_outputTexture1 is null && _outputFramebuffer1 is null);
            Debug.Assert(_outputTexture2 is null && _outputFramebuffer2 is null);

            RecreateOutputTextures();

            Debug.Assert(_outputTexture1 is not null && _outputFramebuffer1 is not null);
            Debug.Assert(_outputTexture2 is not null && _outputFramebuffer2 is not null);

            pipelineDescription.Outputs = _outputFramebuffer1.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodePickingShaders(_gd, out _NodePickingBuffer);
            _pickingPipeline = factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gd, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRelative = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRawShaders(_gd, out _RawEdgeVertBuffer, out _RawEdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRaw = factory.CreateGraphicsPipeline(pipelineDescription);



            //font -----------------------

            _fontRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            ResourceSetDescription crs_font_rsd = new ResourceSetDescription(_fontRsrcLayout, _controller._fontTextureView);
            _crs_font = factory.CreateResourceSet(crs_font_rsd);

            ShaderSetDescription fontshader = SPIRVShaders.CreateFontShaders(_gd, out _FontVertBuffer, out _FontIndexBufferAll);

            GraphicsPipelineDescription fontpd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                DepthStencilStateDescription.DepthOnlyLessEqual,
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, true, true),
                PrimitiveTopology.TriangleList, fontshader,
                new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer1.OutputDescription);
            _fontPipeline = factory.CreateGraphicsPipeline(fontpd);
        }


        /// <summary>
        /// Re-initialise graphics resources, for use when the size of the widget has changed
        /// </summary>
        private void RecreateOutputTextures()
        {
            Debug.Assert(_gd is not null, "Init not called");
            ResourceFactory factory = _gd.ResourceFactory;

            if (GlobalConfig.BulkLog) Logging.RecordLogEvent("RecreateOutputTextures DISPOSING ALL", Logging.LogFilterType.BulkDebugLogFile);
            _graphLock.EnterWriteLock();
            VeldridGraphBuffers.DoDispose(_outputTexture1);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer1);
            VeldridGraphBuffers.DoDispose(_outputTexture2);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer2);
            VeldridGraphBuffers.DoDispose(_testPickingTexture);
            VeldridGraphBuffers.DoDispose(_pickingFrameBuffer);
            VeldridGraphBuffers.DoDispose(_pickingStagingTexture);

            _outputTexture1 = factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture1.Name = "OutputTexture1" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer1 = factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture1));
            _outputFramebuffer1.Name = $"OPFB1_" + _outputTexture1.Name;

            _outputTexture2 = factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture2.Name = "OutputTexture2" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer2 = factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture2));
            _outputFramebuffer2.Name = $"OPFB2_" + _outputTexture2.Name;

            _testPickingTexture = factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                    Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _pickingFrameBuffer = factory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));

            _pickingStagingTexture = factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                    Veldrid.PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.Staging));
            _graphLock.ExitWriteLock();
            if (GlobalConfig.BulkLog) Logging.RecordLogEvent("RecreateOutputTextures recreated", Logging.LogFilterType.BulkDebugLogFile);
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct fontStruc
        {
            public uint nodeIdx;
            public Vector3 screenCoord;
            public Vector2 fontCoord;
            public float yOffset;
            public WritableRgbaFloat fontColour;
            public const uint SizeInBytes = 44;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct GraphShaderParams
        {
            ///public Matrix4x4 rotatedView;
            public Matrix4x4 proj;
            public Matrix4x4 view;
            public Matrix4x4 world;
            public Matrix4x4 nonRotatedView;
            public uint TexWidth;
            public int pickingNode;
            public bool isAnimated;
            //must be multiple of 16

            private readonly ulong _padding1;
            private readonly bool _padding3c;
        }

        private eRenderingMode _renderingMode = eRenderingMode.eStandardControlFlow;

        /// <summary>
        ///  Sets rendering mode to the specified mode
        ///  If already using that mode, returns the mode to standard trace display
        /// </summary>
        /// <param name="newMode">Mode to toggle</param>
        public void ToggleRenderingMode(eRenderingMode newMode)
        {
            if (newMode == _renderingMode && _renderingMode != eRenderingMode.eStandardControlFlow)
            {
                SetRenderingMode(eRenderingMode.eStandardControlFlow);
            }
            else
            {
                SetRenderingMode(newMode);
            }
        }


        /// <summary>
        /// Set the rendering mode to the specified mode
        /// </summary>
        /// <param name="newMode">Mode to activate</param>
        private void SetRenderingMode(eRenderingMode newMode)
        {
            _renderingMode = newMode;
        }

        private static readonly Dictionary<string, fontStruc[]> _cachedStrings = new();


        /// <summary>
        /// Convert a string to a List of fontStrucs describing the font glyphs to display the string
        /// The output is cached so this is not performed every frame
        /// </summary>
        /// <param name="inputString">Text to display</param>
        /// <param name="nodeIdx">Node associated with the text - used for positioning</param>
        /// <param name="fontScale">Text scaling factor</param>
        /// <param name="font">Font glyphs to use</param>
        /// <param name="stringVerts">Working list of glyph descriptors to add the generated fontStrucs to</param>
        /// <param name="colour">Text colour</param>
        /// <param name="yOff">Vertical offset for the glyphs</param> //todo think caching wrecks this
        private static void RenderString(string inputString, uint nodeIdx, float fontScale, ImFontPtr font, List<fontStruc> stringVerts, uint colour, float yOff = 0)
        {
            if (_cachedStrings.TryGetValue(inputString, out fontStruc[]? cached) && cached is not null)
            {
                stringVerts.AddRange(cached);
                return;
            }

            float xPos = 0;
            float yPos = 50;
            float glyphYClip = 10;
            WritableRgbaFloat fcolour = new WritableRgbaFloat(colour);
            fontStruc[] result = new fontStruc[6 * inputString.Length];
            for (var i = 0; i < inputString.Length; i++)
            {
                ImFontGlyphPtr glyph = font.FindGlyph(inputString[i]);
                float charWidth = glyph.AdvanceX * fontScale;
                float charHeight = fontScale * (glyph.Y1 - glyph.Y0);


                float xEnd = xPos + charWidth;
                float yBase = yPos + (glyphYClip - glyph.Y1) * fontScale;
                float yTop = yBase + charHeight;

                Vector2 uv0 = new Vector2(glyph.U0, glyph.V0);
                Vector2 uv1 = new Vector2(glyph.U1, glyph.V1);
                Vector3 topLeft = new Vector3(xPos, yTop, 0);
                Vector3 baseRight = new Vector3(xEnd, yBase, 0);
                result[i * 6] = new fontStruc { nodeIdx = nodeIdx, screenCoord = topLeft, fontCoord = uv0, yOffset = yOff, fontColour = fcolour };
                result[i * 6 + 1] = new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1), yOffset = yOff, fontColour = fcolour };
                result[i * 6 + 2] = new fontStruc { nodeIdx = nodeIdx, screenCoord = baseRight, fontCoord = uv1, yOffset = yOff, fontColour = fcolour };
                result[i * 6 + 3] = new fontStruc { nodeIdx = nodeIdx, screenCoord = topLeft, fontCoord = uv0, yOffset = yOff, fontColour = fcolour };
                result[i * 6 + 4] = new fontStruc { nodeIdx = nodeIdx, screenCoord = baseRight, fontCoord = uv1, yOffset = yOff, fontColour = fcolour };
                result[i * 6 + 5] = new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0), yOffset = yOff, fontColour = fcolour };
                xPos += charWidth;
            }
            _cachedStrings.Add(inputString, result);
            stringVerts.AddRange(result);
        }


        /// <summary>
        /// Convert a string to a List of fontStrucs describing the font glyphs to display the string
        /// The output is cached so this is not performed every frame
        /// </summary>
        /// <param name="inputString">Text to display</param>
        /// <param name="nodeIdx">Node associated with the text - used for positioning</param>
        /// <param name="arrayIdx">Where in the glyphs array to insert this string</param>
        /// <param name="fontScale">Text scaling factor</param>
        /// <param name="font">Font glyphs to use</param>
        /// <param name="stringVerts">Working list of glyph descriptors to add the generated fontStrucs to</param>
        /// <param name="colour">Text colour</param>
        /// <param name="yOff">Vertical offset for the glyphs</param> //todo think caching wrecks this
        private static void RenderStringToArray(string inputString, uint nodeIdx, int arrayIdx, float fontScale, ImFontPtr font, fontStruc[] stringVerts, uint colour, float yOff = 0)
        {
            if (!_cachedStrings.TryGetValue(inputString, out fontStruc[]? cached) || cached is null)
            {
                cached = new fontStruc[inputString.Length * 6];

                float xPos = 0;
                float yPos = 50;
                float glyphYClip = 10;
                WritableRgbaFloat fcolour = new WritableRgbaFloat(colour);
                for (var i = 0; i < inputString.Length; i++)
                {
                    ImFontGlyphPtr glyph = font.FindGlyph(inputString[i]);
                    float charWidth = glyph.AdvanceX * fontScale;
                    float charHeight = fontScale * (glyph.Y1 - glyph.Y0);


                    float xEnd = xPos + charWidth;
                    float yBase = yPos + (glyphYClip - glyph.Y1) * fontScale;
                    float yTop = yBase + charHeight;

                    Vector2 uv0 = new Vector2(glyph.U0, glyph.V0);
                    Vector2 uv1 = new Vector2(glyph.U1, glyph.V1);
                    Vector3 topLeft = new Vector3(xPos, yTop, 0);
                    Vector3 baseRight = new Vector3(xEnd, yBase, 0);
                    cached[i * 6] = new fontStruc { nodeIdx = nodeIdx, screenCoord = topLeft, fontCoord = uv0, yOffset = yOff, fontColour = fcolour };
                    cached[i * 6 + 1] = new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1), yOffset = yOff, fontColour = fcolour };
                    cached[i * 6 + 2] = new fontStruc { nodeIdx = nodeIdx, screenCoord = baseRight, fontCoord = uv1, yOffset = yOff, fontColour = fcolour };
                    cached[i * 6 + 3] = new fontStruc { nodeIdx = nodeIdx, screenCoord = topLeft, fontCoord = uv0, yOffset = yOff, fontColour = fcolour };
                    cached[i * 6 + 4] = new fontStruc { nodeIdx = nodeIdx, screenCoord = baseRight, fontCoord = uv1, yOffset = yOff, fontColour = fcolour };
                    cached[i * 6 + 5] = new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0), yOffset = yOff, fontColour = fcolour };
                    xPos += charWidth;
                }
                _cachedStrings.Add(inputString, cached);
            }

            for (var i = 0; i < cached.Length; i++)
            {
                stringVerts[arrayIdx + i] = cached[i];
            }
        }


        /// <summary>
        /// Update graph drawing parameters used by the shaders
        /// </summary>
        /// <param name="graph">The graph being drawn</param>
        /// <param name="textureSize"></param>
        /// <param name="projection"></param>
        /// <param name="view"></param>
        /// <param name="world"></param>
        /// <param name="cl"></param>
        /// <returns></returns>
        private GraphShaderParams updateShaderParams(PlottedGraph graph, uint textureSize, Matrix4x4 projection, Matrix4x4 view, Matrix4x4 world, CommandList cl)
        {
            GraphShaderParams shaderParams = new GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = MouseoverNodeID,
                isAnimated = graph.IsAnimated
            };

            shaderParams.proj = projection;
            shaderParams.view = view;
            shaderParams.world = world;
            shaderParams.nonRotatedView = Matrix4x4.Multiply(Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0), graph.CameraState.MainCameraTranslation);

            cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);

            return shaderParams;
        }


        private class RISINGEXTTXT
        {
            public RISINGEXTTXT(string label) { text = label; }
            public int nodeIdx;
            public float currentY;
            public string text;
            public int remainingFrames;
        }


        private readonly List<RISINGEXTTXT> _activeRisings = new List<RISINGEXTTXT>();

        private void UploadFontVerts(fontStruc[] stringVerts1, fontStruc[] stringVerts2, CommandList cl)
        {
            Debug.Assert(_gd is not null);
            int vertsCount = stringVerts1.Length + stringVerts2.Length;
            uint[] charIndexes = Enumerable.Range(0, vertsCount).Select(i => (uint)i).ToArray();

            if (vertsCount * fontStruc.SizeInBytes > _FontVertBuffer!.SizeInBytes)
            {
                VeldridGraphBuffers.VRAMDispose(_FontVertBuffer);
                _FontVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)vertsCount * fontStruc.SizeInBytes, BufferUsage.VertexBuffer, name: _FontVertBuffer.Name);
                VeldridGraphBuffers.VRAMDispose(_FontIndexBufferAll);
                _FontIndexBufferAll = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)charIndexes.Length * sizeof(uint), BufferUsage.IndexBuffer, name: _FontIndexBufferAll!.Name);
            }

            if (stringVerts1.Any())
                cl.UpdateBuffer(_FontVertBuffer, 0, stringVerts1);
            if (stringVerts2.Any())
                cl.UpdateBuffer(_FontVertBuffer, (uint)(stringVerts1.Length * fontStruc.SizeInBytes), stringVerts2);
            cl.UpdateBuffer(_FontIndexBufferAll, 0, charIndexes);
        }

        private fontStruc[] RenderHighlightedNodeText(List<Tuple<string?, uint>> captions, int nodeIdx = -1)
        {
            const float fontScale = 8f;
            fontStruc[] higlightNodeVerts = Array.Empty<fontStruc>();

            if (captions.Count > nodeIdx)
            {

                var caption = captions[nodeIdx];
                if (caption != null && caption.Item1 is not null)
                {
                    higlightNodeVerts = new fontStruc[(int)(caption.Item1.Length * fontStruc.SizeInBytes)];
                    RenderStringToArray(caption.Item1, (uint)nodeIdx, 0, fontScale, _controller._unicodeFont, stringVerts: higlightNodeVerts, colour: caption.Item2);
                }
            }

            return higlightNodeVerts;
        }

        private void MaintainRisingTexts(float fontScale, ref List<fontStruc> stringVerts)
        {
            _activeRisings.RemoveAll(x => x.remainingFrames == 0);
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                return;
            }

            graph.GetActiveExternRisings(out List<Tuple<uint, string>> newRisingExterns,
                out List<Tuple<uint, string>> currentLingeringExternLabels);

            //remove any lingering (ie - no expiry time) rising labvels which are no longer current
            List<int> latestLingeringApiCaptionNodes = currentLingeringExternLabels.Select(x => (int)x.Item1).ToList();
            if (_activeRisings.Count > 0)
            {
                var expiredCaptions = _activeRisings
                    .Where(x => (x.remainingFrames == -1) && !latestLingeringApiCaptionNodes.Contains(x.nodeIdx))
                    .Select(x => x.nodeIdx);

                if (expiredCaptions.Any())
                {
                    _activeRisings.RemoveAll(x => x.remainingFrames == -1 && expiredCaptions.Contains(x.nodeIdx));
                }
            }

            //find any lingering labels in the new list which are not in the current list, render them
            if (currentLingeringExternLabels.Count > 0)
            {
                var currentLingeringCaptionNodes = _activeRisings.Where(x => x.remainingFrames == -1).Select(x => x.nodeIdx);

                var newLingeringCaptions = currentLingeringExternLabels
                    .Where(x => !currentLingeringCaptionNodes.Contains((int)x.Item1));

                foreach (var nodeString in newLingeringCaptions)
                {
                    RISINGEXTTXT newriser = new RISINGEXTTXT(label: nodeString.Item2)
                    {
                        currentY = 25.0f,
                        nodeIdx = (int)nodeString.Item1,
                        remainingFrames = -1
                    };
                    _activeRisings.Add(newriser);
                }
            }


            //add any new rising extern labels
            if (newRisingExterns.Count > 0)
            {
                foreach (var risingLabel in newRisingExterns)
                {
                    RISINGEXTTXT newriser = new RISINGEXTTXT(label: risingLabel.Item2)
                    {
                        currentY = 25.0f,
                        nodeIdx = (int)risingLabel.Item1,
                        text = risingLabel.Item2,
                        remainingFrames = GlobalConfig.ExternAnimDisplayFrames
                    };
                    _activeRisings.Add(newriser);
                }
            }


            //maintain each label by counting them down, raising them and rendering them
            uint risingSymColour = Themes.GetThemeColourUINT(Themes.eThemeColour.SymbolRising);
            for (int idx = 0; idx < _activeRisings.Count; idx++)
            {
                var ar = _activeRisings[idx];
                if (ar.remainingFrames != -1)
                {
                    ar.currentY += GlobalConfig.ExternAnimRisePerFrame;
                    ar.remainingFrames -= 1;
                }
                //Logging.WriteConsole($"Drawing '{ar.text}' at y {ar.currentY}");
                RenderString(ar.text, (uint)ar.nodeIdx, fontScale, _controller._unicodeFont, stringVerts, risingSymColour, yOff: ar.currentY);
            }
        }

        private fontStruc[] renderGraphText(List<Tuple<string?, uint>> captions, float scale)
        {
            List<fontStruc> stringVerts = new List<fontStruc>();
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                return Array.Empty<fontStruc>();
            }

            if (!graph.Opt_TextEnabled)
            {
                return Array.Empty<fontStruc>();
            }

            int charCount = 0;
            for (int nodeIdx = 0; nodeIdx < captions.Count; nodeIdx++)
            {
                var caption = captions[nodeIdx];
                if (caption is not null && caption.Item1 is not null)
                {
                    charCount += caption.Item1.Length;
                }
            }

            fontStruc[] glyphVerts = new fontStruc[6 * charCount];
            int glyphIndex = 0;
            for (int nodeIdx = 0; nodeIdx < captions.Count; nodeIdx++)
            {
                var caption = captions[nodeIdx];
                if (caption is not null && caption.Item1 is not null)
                {
                    RenderStringToArray(caption.Item1, (uint)nodeIdx, glyphIndex, scale, _controller._unicodeFont, glyphVerts, captions[nodeIdx].Item2);
                    glyphIndex += 6 * caption.Item1.Length;
                }
            }


            return glyphVerts;
        }


        private ulong _lastThemeVersion = 0;

        /// <summary>
        /// Draws the various nodes, edges, captions and illustrations to the framebuffer for display
        /// </summary>
        /// <param name="cl">A veldrid commandlist, for use by this thread only</param>
        /// <param name="graph">The PlottedGraph to draw</param>
        public unsafe void DrawGraph(CommandList cl, PlottedGraph graph)
        {
            Stopwatch st = new();
            st.Start();
            Position2DColour[] EdgeLineVerts = graph.GetEdgeLineVerts(_renderingMode, out uint[] edgeDrawIndexes, out int edgeVertCount);
            if (graph.LayoutState.Initialised is false || edgeVertCount == 0 || Exiting)
            {
                return;
            }
            st.Stop();
            if (st.ElapsedMilliseconds > 100)
                Console.WriteLine($"DGGetEdgeLineVerts took {st.ElapsedMilliseconds}");

            Debug.Assert(_gd is not null);
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("rendergraph start", filter: Logging.LogFilterType.BulkDebugLogFile);

            //theme changed, purged cached text in case its colour changed
            ulong themeVersion = Themes.ThemeVariant;
            bool newColours = _lastThemeVersion < themeVersion;
            if (newColours)
            {
                _cachedStrings.Clear();
                _lastThemeVersion = themeVersion;
            }

            cl.Begin();

            st.Restart();
            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _imageTextureView);

            ResourceSet crs_nodesEdges = _factory!.CreateResourceSet(crs_nodesEdges_rsd);

            //rotval += 0.01f; //autorotate
            var textureSize = graph.LinearIndexTextureSize();

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            updateShaderParams(graph, textureSize, proj, view, world, cl);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer,
                _gd.PointSampler, graph.LayoutState.PositionsVRAM1, graph.LayoutState.AttributesVRAM1);
            ResourceSet crs_core = _factory.CreateResourceSet(crs_core_rsd);

            Position2DColour[] NodeVerts = graph.GetMaingraphNodeVerts(_renderingMode, (int)textureSize,
            out uint[] nodeIndices, out Position2DColour[] nodePickingColors,
            out List<Tuple<string?, uint>> captions, out int nodeCount);

            st.Stop();
            if (st.ElapsedMilliseconds > 100)
                Console.WriteLine($"DGGetMaingraphNodeVerts took {st.ElapsedMilliseconds}");

            //_layoutEngine.GetScreenFitOffsets(WidgetSize, out _furthestX, out _furthestY, out _furthestZ);

            if (_NodeVertexBuffer!.SizeInBytes < NodeVerts.Length * Position2DColour.SizeInBytes ||
                (_NodeIndexBuffer!.SizeInBytes < nodeIndices.Length * sizeof(uint)))
            {
                VRAMDispose(_NodeVertexBuffer);
                VRAMDispose(_NodePickingBuffer);
                VRAMDispose(_NodeIndexBuffer);

                _NodeVertexBuffer = TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "NodeVertexBuffer");
                _NodePickingBuffer = TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "NodePickingVertexBuffer");
                _NodeIndexBuffer = TrackedVRAMAlloc(_gd, (uint)nodeIndices.Length * sizeof(uint), BufferUsage.IndexBuffer, name: "NodeIndexBuffer");
            }


            //todo - only do this on changes

            fixed (Position2DColour* vertsPtr = NodeVerts, pickingVertsPtr = nodePickingColors)
            {
                if ((uint)nodeCount * Position2DColour.SizeInBytes > _NodeVertexBuffer.SizeInBytes) Console.WriteLine("PROBLEM1");
                if ((uint)nodeCount * Position2DColour.SizeInBytes > _NodePickingBuffer!.SizeInBytes) Console.WriteLine("PROBLE2");
                cl.UpdateBuffer(_NodeVertexBuffer, 0, (IntPtr)vertsPtr, (uint)nodeCount * Position2DColour.SizeInBytes);
                cl.UpdateBuffer(_NodePickingBuffer, 0, (IntPtr)pickingVertsPtr, (uint)nodeCount * Position2DColour.SizeInBytes);
            }


            fixed (uint* indxPtr = nodeIndices)
            {
                if ((uint)nodeCount * sizeof(uint) > _NodeIndexBuffer.SizeInBytes) Console.WriteLine("PROBLEM3");
                cl.UpdateBuffer(_NodeIndexBuffer, 0, (IntPtr)indxPtr, (uint)nodeCount * sizeof(uint));
            }


            int edgeIndexBufSize = edgeDrawIndexes.Length;
            if (((EdgeLineVerts.Length * Position2DColour.SizeInBytes) > _EdgeVertBuffer!.SizeInBytes) ||
                (edgeIndexBufSize * sizeof(uint)) > _EdgeIndexBuffer!.SizeInBytes)
            {
                VRAMDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = TrackedVRAMAlloc(_gd, (uint)EdgeLineVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "EdgeVertexBuffer");
                VRAMDispose(_EdgeIndexBuffer);
                _EdgeIndexBuffer = TrackedVRAMAlloc(_gd, (uint)edgeIndexBufSize * sizeof(uint), BufferUsage.IndexBuffer, name: "EdgeIndexBuffer");
            }

            ReadOnlySpan<Position2DColour> elvSpan = new ReadOnlySpan<Position2DColour>(EdgeLineVerts, 0, edgeVertCount);
            fixed (Position2DColour* vertsPtr = elvSpan)
            {
                if ((uint)(elvSpan.Length * Position2DColour.SizeInBytes) > _EdgeVertBuffer.SizeInBytes) Console.WriteLine("PROBLEM4");
                cl.UpdateBuffer(_EdgeVertBuffer, 0, (IntPtr)vertsPtr, (uint)(edgeVertCount * Position2DColour.SizeInBytes));
            }

            ReadOnlySpan<uint> eidxsSpan = new ReadOnlySpan<uint>(edgeDrawIndexes, 0, edgeIndexBufSize);
            fixed (uint* eindexPtr = eidxsSpan)
            {
                if ((uint)eidxsSpan.Length * sizeof(uint) > _EdgeIndexBuffer!.SizeInBytes) Console.WriteLine("PROBLEM5");
                cl.UpdateBuffer(_EdgeIndexBuffer, 0, (IntPtr)eindexPtr, (uint)(edgeIndexBufSize * sizeof(uint)));
            }

            st.Restart();
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("render graph 4", filter: Logging.LogFilterType.BulkDebugLogFile);
            fontStruc[] stringVerts;
            if (MouseoverNodeID == -1)
            {
                stringVerts = renderGraphText(captions, GlobalConfig.InsTextScale);
            }
            else
            {
                stringVerts = RenderHighlightedNodeText(captions, MouseoverNodeID).ToArray();
            }


            List<fontStruc> risingTextVerts = new List<fontStruc>();
            MaintainRisingTexts(GlobalConfig.InsTextScale, ref risingTextVerts);
            UploadFontVerts(stringVerts, risingTextVerts.ToArray(), cl);


            st.Stop();
            if (st.ElapsedMilliseconds > 100)
                Console.WriteLine($"DGtexts took {st.ElapsedMilliseconds}");


            Debug.Assert(nodeIndices.Length <= (_NodeIndexBuffer.SizeInBytes / 4));
            int nodesToDraw = Math.Min(nodeIndices.Length, (int)(_NodeIndexBuffer.SizeInBytes / 4));

            GetOutputFramebuffer(out Framebuffer drawtarget);
       
            //draw nodes and edges
            cl.SetFramebuffer(drawtarget);
            cl.ClearColorTarget(0, Themes.GetThemeColourWRF(Themes.eThemeColour.GraphBackground).ToRgbaFloat());

            if (graph.Opt_NodesVisible)
            {
                cl.SetPipeline(_pointsPipeline);
                cl.SetGraphicsResourceSet(0, crs_core);
                cl.SetGraphicsResourceSet(1, crs_nodesEdges);
                cl.SetVertexBuffer(0, _NodeVertexBuffer);
                cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
                cl.DrawIndexed(indexCount: (uint)nodesToDraw, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }

            if (graph.Opt_EdgesVisible)
            {
                cl.SetPipeline(_edgesPipelineRelative);
                cl.SetGraphicsResourceSet(0, crs_core);
                cl.SetGraphicsResourceSet(1, crs_nodesEdges);
                cl.SetVertexBuffer(0, _EdgeVertBuffer);
                cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
                cl.DrawIndexed(indexCount: (uint)edgeVertCount, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }

            GeomPositionColour[] IllustrationEdges = graph.GetIllustrationEdges(out List<uint> illusEdgeDrawIndexes);

            if (IllustrationEdges.Length > 0)
            {

                if (_RawEdgeIndexBuffer is null || ((IllustrationEdges.Length * GeomPositionColour.SizeInBytes) > _RawEdgeIndexBuffer.SizeInBytes))
                {
                    VRAMDispose(_RawEdgeVertBuffer);
                    _RawEdgeVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)IllustrationEdges.Length * GeomPositionColour.SizeInBytes * 4, BufferUsage.VertexBuffer, name: "IllustrateVertexBuffer");
                    VRAMDispose(_RawEdgeIndexBuffer);
                    _RawEdgeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)illusEdgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "IllustrateIndexBuffer");
                }

                //todo - only do this on changes
                cl.UpdateBuffer(_RawEdgeVertBuffer, 0, IllustrationEdges);
                cl.UpdateBuffer(_RawEdgeIndexBuffer, 0, illusEdgeDrawIndexes.ToArray());

                cl.SetPipeline(_edgesPipelineRaw);
                cl.SetGraphicsResourceSet(0, crs_core);
                cl.SetVertexBuffer(0, _RawEdgeVertBuffer);
                cl.SetIndexBuffer(_RawEdgeIndexBuffer, IndexFormat.UInt32);
                cl.DrawIndexed(indexCount: (uint)illusEdgeDrawIndexes.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }


            //draw text            
            if (graph.Opt_TextEnabled)
            {
                cl.SetViewport(0, new Viewport(0, 0, WidgetSize.X, WidgetSize.Y, -2200, 1000));

                cl.SetPipeline(_fontPipeline);
                cl.SetVertexBuffer(0, _FontVertBuffer);
                cl.SetIndexBuffer(_FontIndexBufferAll, IndexFormat.UInt32);
                cl.SetGraphicsResourceSet(0, crs_core);
                cl.SetGraphicsResourceSet(1, _crs_font);

                cl.DrawIndexed(indexCount: (uint)(stringVerts.Length + risingTextVerts.Count), instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }



            //update the picking framebuffer 
            //todo - not every frame?
            cl.SetPipeline(_pickingPipeline);
            cl.SetGraphicsResourceSet(0, crs_core);
            cl.SetGraphicsResourceSet(1, crs_nodesEdges);
            cl.SetVertexBuffer(0, _NodePickingBuffer);
            cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            cl.SetFramebuffer(_pickingFrameBuffer);

            cl.ClearColorTarget(0, new RgbaFloat(0f, 0f, 0f, 0f));
            cl.SetViewport(0, new Viewport(0, 0, WidgetSize.X, WidgetSize.Y, -2200, 1000));
            cl.DrawIndexed(indexCount: (uint)nodeIndices.Length, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            cl.CopyTexture(_testPickingTexture, _pickingStagingTexture);
            st.Restart();

            cl.End();
            _gd.SubmitCommands(cl); //had a same key error here
            _gd.WaitForIdle();

          st.Stop();
          if (st.ElapsedMilliseconds > 100)
              Console.WriteLine($"DG WaitForIdle took {st.ElapsedMilliseconds}");

          ReleaseOutputFramebuffer();

          crs_core.Dispose();
          crs_nodesEdges.Dispose();
          if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("rendergraph end", filter: Logging.LogFilterType.BulkDebugLogFile);

        }


        /// <summary>
        /// Add the most recently drawn framebuffer to the drawlist
        /// </summary>
        /// <returns>The texture for the drawn framebuffer. Useful for screenshots/videos</returns>
        public Texture DrawGraphImage()
        {

            Stopwatch sw = new();
            sw.Start();
            Vector2 currentRegionSize = ImGui.GetContentRegionAvail();
            if (currentRegionSize != WidgetSize)
            {
                if (_newGraphSize == null || _newGraphSize != currentRegionSize)
                {
                    _newGraphSize = currentRegionSize;
                }
            }

            WidgetPos = ImGui.GetCursorScreenPos();
            _MousePos = ImGui.GetMousePos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            sw.Stop();
            if (sw.ElapsedMilliseconds > 40)
                Console.WriteLine($"DGI W?HAT 1 {sw.ElapsedMilliseconds}");

            sw.Restart();
            GetLatestTexture(out Texture outputTexture);

            sw.Stop();
            if (sw.ElapsedMilliseconds > 40)
                Console.WriteLine($"DGI W?HAT 2 {sw.ElapsedMilliseconds}");

            sw.Restart();
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd!.ResourceFactory, outputTexture, "GraphMainPlot" + outputTexture.Name);

            sw.Stop();
            if (sw.ElapsedMilliseconds > 40)
                Console.WriteLine($"DGI W?HAT 3 {sw.ElapsedMilliseconds}");

            sw.Restart();
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: WidgetPos,
                p_max: new Vector2(WidgetPos.X + outputTexture.Width, WidgetPos.Y + outputTexture.Height),
                uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));

            _isInputTarget = ImGui.IsItemActive();

            sw.Stop();
            if (sw.ElapsedMilliseconds > 40)
                Console.WriteLine($"DGI W?HAT 4 {sw.ElapsedMilliseconds}");
            return outputTexture;
        }

        /// <summary>
        /// Get the current text colour as a Vector4
        /// Wrapper for the memory unsafe ImGui API 
        /// </summary>
        /// <returns>A Vector4 describing the current text colour</returns>
        private static unsafe Vector4 GetTextColour() => *ImGui.GetStyleColorVec4(ImGuiCol.Text);


        /// <summary>
        /// Draw the latest keyboard shortcut activations to the screen
        /// </summary>
        /// <param name="topLeft">Location on the screen to draw to</param>
        private void DrawKeystrokes(Vector2 topLeft)
        {
            long timeNowMS = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            long removeLimit = timeNowMS - GlobalConfig.KeystrokeDisplayMS;
            long fadeLimit = timeNowMS - (GlobalConfig.KeystrokeDisplayMS - GlobalConfig.KeystrokeStartFadeMS);
            long fadeWindow = fadeLimit - removeLimit;
            Vector4 textCol = GetTextColour();

            _keypressCaptions = _keypressCaptions
                .Skip(Math.Max(0, _keypressCaptions.Count - GlobalConfig.KeystrokeDisplayMaxCount))
                .Where(k => k.startedMS > removeLimit)
                .ToList();

            int maxKeystrokes = Math.Min(GlobalConfig.KeystrokeDisplayMaxCount, _keypressCaptions.Count);
            float depth = topLeft.Y + 80;
            for (var i = _keypressCaptions.Count - 1; i >= 0; i--)
            {
                KEYPRESS_CAPTION keycaption = _keypressCaptions[i];
                float newPos = depth - (15 * (maxKeystrokes - i));
                ImGui.SetCursorScreenPos(new Vector2(topLeft.X + 4, newPos));

                string keystroke;
                if (keycaption.MenuShortut != null)
                {
                    keystroke = keycaption.MenuShortut;
                }
                else
                {
                    keystroke = keycaption.key.ToString();
                    if (keycaption.modifiers.HasFlag(ModifierKeys.Control))
                    {
                        keystroke = "Ctrl+" + keystroke;
                    }

                    if (keycaption.modifiers.HasFlag(ModifierKeys.Alt))
                    {
                        keystroke = "Alt+" + keystroke;
                    }

                    if (keycaption.modifiers.HasFlag(ModifierKeys.Shift))
                    {
                        keystroke = "Shift+" + keystroke;
                    }
                }

                string msg = $"[{keystroke}] -> {keycaption.message}";
                if (keycaption.repeats > 1)
                {
                    msg += $" x{keycaption.repeats}";
                }

                float alpha = i == (_keypressCaptions.Count - 1) ? 255 : 220;
                if (keycaption.startedMS < fadeLimit)
                {
                    double fadetime = fadeLimit - keycaption.startedMS;
                    alpha *= (float)(1 - (fadetime / fadeWindow));
                }

                ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(textCol).ToUint((uint)alpha));
                ImGui.Text(msg);
                ImGui.PopStyleColor();
            }
        }



        struct EVTLABEL
        {
            public string text;
            public System.Drawing.Color colour;
            public double alpha;
            public float height;
        }

        /// <summary>
        /// Display trace events (process/thread stop/start) in the visualiser widget which are
        /// important but not important enough to be an application alert
        /// May also want to add certain APIs, especially network related
        /// </summary>
        /// <param name="pos">Position to draw to</param>
        public void DisplayEventMessages(Vector2 pos)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                return;
            }

            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            float depth = 20;//todo based on count 
            float maxWidth = 200;

            TraceRecord trace = graph.InternalProtoGraph.TraceData;
            Stopwatch st = new Stopwatch();
            st.Start();
            Logging.TIMELINE_EVENT[] evts = trace.GetTimeLineEntries(oldest: timenow - GlobalConfig.VisMessageMaxLingerTime, max: 5);
            st.Stop(); if (st.ElapsedMilliseconds > 60) Console.WriteLine($"Get tlentres ({evts.Length}) took {st.ElapsedMilliseconds} ms");

            List<EVTLABEL> events = new();

            for (var i = 0; i < evts.Length; i++)
            {
                Logging.TIMELINE_EVENT evt = evts[i];
                long displayTimeRemaining = GlobalConfig.VisMessageMaxLingerTime - (timenow - evt.EventTimeMS);

                ImGui.SetCursorPosX(pos.X - maxWidth);

                double alpha = i == (evts.Length - 1) ? 255 : 220;
                if (displayTimeRemaining <= GlobalConfig.VisMessageFadeStartTime)
                {
                    double fadetime = GlobalConfig.VisMessageFadeStartTime - displayTimeRemaining;
                    alpha *= 1.0 - (fadetime / GlobalConfig.VisMessageFadeStartTime);
                }


                System.Drawing.Color textCol;
                string msg;
                switch (evt.TimelineEventType)
                {
                    case Logging.eTimelineEvent.ProcessStart:
                        textCol = System.Drawing.Color.LightGreen;
                        msg = $"Process {evt.ID} started";
                        break;
                    case Logging.eTimelineEvent.ProcessEnd:
                        textCol = System.Drawing.Color.OrangeRed;
                        msg = $"Process {evt.ID} ended";
                        break;
                    case Logging.eTimelineEvent.ThreadStart:
                        textCol = System.Drawing.Color.LightGreen;
                        msg = $"Thread {evt.ID} started";
                        break;
                    case Logging.eTimelineEvent.ThreadEnd:
                        textCol = System.Drawing.Color.OrangeRed;
                        msg = $"Thread {evt.ID} ended";
                        break;
                    case Logging.eTimelineEvent.APICall:
                        textCol = System.Drawing.Color.White;
                        Logging.APICALL item = ((Logging.APICALL)evt.Item);
                        if (item.APIDetails.HasValue)
                        {
                            msg = $"API: {item.APIDetails.Value.ModuleName}::{item.APIDetails.Value.Symbol}";
                        }
                        else
                            continue;
                        break;
                    default:
                        textCol = System.Drawing.Color.Gray;
                        msg = "Unknown Timeline event" + evt.TimelineEventType.ToString();
                        break;

                }
                Vector2 textSz = ImGui.CalcTextSize(msg);
                if (textSz.X > maxWidth) maxWidth = textSz.X;
                events.Add(new EVTLABEL() { text = msg, colour = textCol, alpha = alpha, height = textSz.Y });

            }

            float currentY = depth;
            foreach (var eventLabel in events)
            {
                ImGui.SetCursorScreenPos(new Vector2((pos.X - maxWidth) - 6, currentY));
                ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(eventLabel.colour).ToUint((uint)eventLabel.alpha));
                ImGui.TextWrapped(eventLabel.text);
                ImGui.PopStyleColor();
                currentY += eventLabel.height + 4;
            }

        }


        /// <summary>
        /// Draw in-widget buttons such as the layout selector, keybind activations and the quickmenu
        /// </summary>
        /// <param name="widgetSize"></param>
        /// <param name="activeGraph"></param>
        private void DrawHUD(Vector2 widgetSize, PlottedGraph? activeGraph)
        {
            string msg;
            Vector2 topLeft = ImGui.GetCursorScreenPos();
            Vector2 bottomLeft = new Vector2(topLeft.X, topLeft.Y + widgetSize.Y);

            if (activeGraph != null)
            {
                Vector2 bottomRight = new Vector2(bottomLeft.X + widgetSize.X - 8, bottomLeft.Y);
                DrawLayoutSelector(activeGraph, bottomRight, 0.25f, activeGraph.ActiveLayoutStyle);
            }
            else
            {
                msg = "No active graph to display";
                Vector2 screenMiddle = new Vector2(bottomLeft.X + ((widgetSize.X / 2) - (ImGui.CalcTextSize(msg).X / 2)), bottomLeft.Y - (widgetSize.Y / 2));
                ImGui.SetCursorScreenPos(screenMiddle);
                ImGui.Text(msg);
                return;
            }

            if (GlobalConfig.ShowKeystrokes)
            {
                DrawKeystrokes(topLeft);
            }

            _QuickMenu.Draw(bottomLeft, 0.25f, activeGraph);


            //Vector2 midRight = new Vector2(bottomLeft.X + widgetSize.X, bottomLeft.Y - widgetSize.Y / 2);
            //DrawDisasmPreview(graph, midRight);
        }

        private bool _showLayoutSelectorPopup;

        private IntPtr GetLayoutIcon(LayoutStyles.Style layout)
        {
            Texture? iconTex;
            switch (layout)
            {
                case LayoutStyles.Style.ForceDirected3DBlocks:
                case LayoutStyles.Style.ForceDirected3DNodes:
                    iconTex = _controller.GetImage("Force3D");
                    break;
                case LayoutStyles.Style.Circle:
                    iconTex = _controller.GetImage("Circle");
                    break;
                case LayoutStyles.Style.CylinderLayout:
                    iconTex = _controller.GetImage("Cylinder");
                    break;
                default:
                    Logging.WriteConsole($"ERROR: no icond for layout {layout}");
                    iconTex = _controller.GetImage("Force3D");
                    break;
            }

            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd!.ResourceFactory, iconTex, "LayoutIcon");
            return CPUframeBufferTextureId;
        }

        private void DrawLayoutSelector(PlottedGraph graph, Vector2 position, float scale, LayoutStyles.Style layout)
        {
            Vector2 iconSize = new Vector2(128 * scale, 128 * scale);
            float padding = 6f;
            Vector2 pmin = new Vector2((position.X - iconSize.X) - padding, ((position.Y - iconSize.Y) - 4) - padding);


            ImGui.SetCursorScreenPos(pmin);

            ImGui.PushStyleColor(ImGuiCol.Button, 0x11000000);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0x11000000);
            ImGui.ImageButton(GetLayoutIcon(layout), iconSize);
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();

            bool buttonHover = ImGui.IsItemHovered(flags: ImGuiHoveredFlags.AllowWhenBlockedByPopup);

            if (!_showLayoutSelectorPopup && buttonHover)
            {
                _showLayoutSelectorPopup = true;
            }

            int buttonCount = 3;
            float offsetFromBase = 0.0f;

            if (_showLayoutSelectorPopup)
            {
                ImGui.SetNextWindowPos(new Vector2(pmin.X - 4, pmin.Y - iconSize.Y * (buttonCount + offsetFromBase)));
                ImGui.OpenPopup("layout select popup");
            }

            bool snappingToPreset = graph.LayoutState.ActivatingPreset;
            if (snappingToPreset) { ImGui.PushStyleColor(ImGuiCol.Border, 0xff4400ff); }

            if (ImGui.BeginPopup("layout select popup"))
            {

                DrawLayoutSelectorIcons(iconSize, snappingToPreset);

                if (!ImGui.IsWindowHovered(flags: ImGuiHoveredFlags.RootAndChildWindows
                        | ImGuiHoveredFlags.AllowWhenBlockedByPopup
                        | ImGuiHoveredFlags.AllowWhenBlockedByActiveItem) && !buttonHover)
                {
                    _showLayoutSelectorPopup = false;
                    ImGui.CloseCurrentPopup();
                }
                ImGui.EndPopup();
            }
            if (snappingToPreset) { ImGui.PopStyleColor(); }
        }

        private void DrawLayoutSelectorIcons(Vector2 iconSize, bool snappingToPreset)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                return;
            }

            float buttonWidth = 150f;

            if (SmallWidgets.ImageCaptionButton(GetLayoutIcon(LayoutStyles.Style.ForceDirected3DNodes),
                iconSize, buttonWidth, "Force Directed Nodes", graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DNodes))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.ForceDirected3DNodes)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(GetLayoutIcon(LayoutStyles.Style.ForceDirected3DBlocks),
                iconSize, buttonWidth, "Force Directed Blocks", graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DBlocks))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.ForceDirected3DBlocks)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(GetLayoutIcon(LayoutStyles.Style.CylinderLayout),
                iconSize, buttonWidth, "Cylinder", graph.ActiveLayoutStyle == LayoutStyles.Style.CylinderLayout))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.CylinderLayout)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(GetLayoutIcon(LayoutStyles.Style.Circle),
                iconSize, buttonWidth, "Circle", graph.ActiveLayoutStyle == LayoutStyles.Style.Circle))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.Circle)) { graph.BeginNewLayout(); }
            }
        }

        private Vector2? _newGraphSize = null;



        /// <summary>
        /// Converts the node/edge positions computed by the layout engine into a rendered image of points and lines
        /// </summary>
        public unsafe void GenerateMainGraph(CommandList cl)
        {
            _graphLock.EnterUpgradeableReadLock();

            PlottedGraph? graph = ActiveGraph;
            if (graph == null || Exiting)
            {
                _graphLock.ExitUpgradeableReadLock();
                return;
            }

            Stopwatch st = new Stopwatch();
            long v1 = 0, v2 = 0, v3 = 0, v4 = 0;

            st.Start();
            HandleGraphUpdates();
            st.Stop(); v1 = st.ElapsedMilliseconds; st.Restart();

            try
            {
                _layoutEngine.Compute(cl, graph, MouseoverNodeID, graph.IsAnimated);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Maingraph Compute error: {e.Message}");
                return;
            }

            st.Stop(); v2 = st.ElapsedMilliseconds; st.Restart();

            if (_controller.DialogOpen is false)
            {
                DoMouseNodePicking(_gd!);
                st.Stop(); v3 = st.ElapsedMilliseconds; st.Restart();
            }

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            Matrix4x4 worldView = world * view;
            if (graph.CenteringInFrame is not PlottedGraph.CenteringMode.Inactive && graph.LayoutState.Initialised)
            {

                //todo - increase stopping threshold as step count increases
                bool done = CenterGraphInFrameStep(worldView, out float remaining);
                if (!done && remaining > 200)
                {
                    int steps = (int)Math.Min(6, remaining / 200);
                    for (int i = 0; i < steps && !done; i++)
                    {
                        done = CenterGraphInFrameStep(worldView, out remaining);
                    }
                }
                if (done && graph.CenteringInFrame is not PlottedGraph.CenteringMode.ContinuousCentering)
                {
                    Logging.WriteConsole($"Centering done after {graph.CenteringSteps} steps");
                    graph.ToggleCentering();
                }
                else
                {
                    if (graph.CenteringInFrame is PlottedGraph.CenteringMode.Centering && graph.CenteringSteps > 1000)
                    {
                        Logging.WriteConsole($"Warning: centering has taken {graph.CenteringSteps } steps so far, abandoning");
                        graph.ToggleCentering();
                    }
                }
            }


            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positionBuf));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, attribBuf));

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("GenerateMainGraph Starting rendergraph", filter: Logging.LogFilterType.BulkDebugLogFile);

            DrawGraph(cl, graph);

            st.Stop(); v4 = st.ElapsedMilliseconds; st.Restart();

            if (v4 > 200)
                Console.WriteLine($"---------\n-----------\nGMG: v1:{v1}, v1:{v2}, v3:{v3}, DrawGraph:{v4}\n--------------\n---------------");

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("GenerateMainGraph upd then done", filter: Logging.LogFilterType.BulkDebugLogFile);
            graph.UpdatePreviewVisibleRegion(WidgetSize);
            _graphLock.ExitUpgradeableReadLock();
        }

        private readonly object _lock = new object();
        private readonly Queue<System.Drawing.Bitmap> frames = new Queue<System.Drawing.Bitmap>();
        public List<System.Drawing.Bitmap> GetLatestFrames()
        {
            lock (_lock)
            {
                List<System.Drawing.Bitmap> result = new List<System.Drawing.Bitmap>(frames);
                frames.Clear();
                return result;
            }
        }


        /// <summary>
        /// must hold upgradable reader lock
        /// </summary>
        private void HandleGraphUpdates()
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null || Exiting)
            {
                return;
            }

            if (_newGraphSize != null)
            {
                Logging.RecordLogEvent($"Remaking textures as newgraphsize {_newGraphSize.Value} != current size {WidgetSize}");
                WidgetSize = _newGraphSize.Value;
                RecreateOutputTextures();
                _newGraphSize = null;
            }


            bool newAttribs = false;
            if (_processingAnimatedGraph && !graph.IsAnimated)
            {
                newAttribs = true;
                _processingAnimatedGraph = false;
            }
            else if (!_processingAnimatedGraph && graph.IsAnimated)
            {
                _processingAnimatedGraph = true;
            }
            if (graph.HighlightsChanged)
            {
                // newAttribs = true;
            }

            if (newAttribs)
            {
                graph.LayoutState.ResetNodeAttributes(_gd!);
                //graph.HighlightsChanged = false;
            }
        }




        /// <summary>
        /// Must hold read lock
        /// Check if the mouse position corresponds to a node ID embedded in the colour values of the picking texture
        /// If so - the mouse is over that node
        /// </summary>
        /// <param name="_gd"></param>
        private void DoMouseNodePicking(GraphicsDevice _gd)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null || Exiting)
            {
                return;
            }

            float mouseX = (_MousePos.X - WidgetPos.X);
            float mouseY = (WidgetPos.Y + _pickingStagingTexture!.Height) - _MousePos.Y;

            bool hit = false;
            //mouse is in graph widget
            if (mouseX > 0 && mouseY > 0 && mouseX < _pickingStagingTexture.Width && mouseY < _pickingStagingTexture.Height)
            {
                MappedResourceView<RgbaFloat> readView = _gd.Map<RgbaFloat>(_pickingStagingTexture, MapMode.Read);
                RgbaFloat f = readView[(int)mouseX, (int)mouseY];
                _gd.Unmap(_pickingStagingTexture);
                if (f.A != 0) //mouse is over something on picking texture
                {
                    if (f.A == 1) //mouse is over a node
                    {
                        if (f.R != MouseoverNodeID && f.R < graph.InternalProtoGraph.NodeList.Count) //mouse is over a different node
                        {
                            NodeData n = graph.InternalProtoGraph.NodeList[(int)f.R];
                            MouseoverNodeID = (int)f.R;
                        }
                        hit = true;
                    }
                }
            }
            if (!hit) //mouse is not over a node
            {
                MouseoverNodeID = -1;
            }

        }
    }
}
