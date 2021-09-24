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
    class GraphPlotWidget : IDisposable
    {
        public PlottedGraph? ActiveGraph { get; private set; }

        readonly QuickMenu _QuickMenu;
        readonly ImGuiController _controller;
        readonly GraphLayoutEngine _layoutEngine;
        readonly rgatState _clientState;

        public GraphLayoutEngine LayoutEngine => _layoutEngine;
        public bool Exiting = false;
        readonly GraphicsDevice _gd;
        readonly ResourceFactory _factory;
        public Vector2 WidgetSize { get; private set; }

        readonly TextureView _imageTextureView;
        readonly ReaderWriterLockSlim _graphLock = new ReaderWriterLockSlim();

        /// <summary>
        /// A widget for displaying a rendered graph plot
        /// </summary>
        /// <param name="controller">The ImGui controller</param>
        /// <param name="gdev">A Veldrid GraphicsDevice</param>
        /// <param name="clientState">The rgat clientstate</param>
        /// <param name="initialSize">The initial size of the widget</param>
        public GraphPlotWidget(ImGuiController controller, GraphicsDevice gdev, rgatState clientState, Vector2? initialSize = null)
        {
            _controller = controller;
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            _QuickMenu = new QuickMenu(_gd, controller);
            _clientState = clientState;

            WidgetSize = initialSize ?? new Vector2(400, 400);

            _layoutEngine = new GraphLayoutEngine(gdev, controller, "Main");
            _imageTextureView = controller.IconTexturesView;  //todo crash if closed early in load
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
        Action<bool>? _dialogStateChangeCallback = null;

        public void Dispose()
        {
            Exiting = true;
        }


        /// <summary>
        /// Must have write lock to call
        /// </summary>
        private void RecreateGraphicsBuffers()
        {
            VeldridGraphBuffers.VRAMDispose(_EdgeVertBuffer);
            VeldridGraphBuffers.VRAMDispose(_EdgeIndexBuffer);
            VeldridGraphBuffers.VRAMDispose(_NodeVertexBuffer);
            VeldridGraphBuffers.VRAMDispose(_NodePickingBuffer);


            _EdgeVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.VertexBuffer, name: _EdgeVertBuffer.Name);
            _EdgeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.IndexBuffer, name: _EdgeIndexBuffer.Name);
            _NodeVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 1, BufferUsage.VertexBuffer, name: _NodeVertexBuffer.Name);
            _NodePickingBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 1, BufferUsage.VertexBuffer, name: _NodePickingBuffer.Name);
        }




        public void ApplyZoom(float delta)
        {
            ActiveGraph?.ApplyMouseWheelDelta(delta);
        }

        bool _isInputTarget = false;
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

        int _centeringInFrame = 0;
        int _centeringSteps = 0;

        public void StartCenterGraphInFrameStepping(bool locked)
        {
            _centeringInFrame = locked ? 2 : 1;
            _centeringSteps = 0;
        }

        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// Must have read lock to call
        /// </summary>
        bool CenterGraphInFrameStep(Matrix4x4 worldView, out float MaxRemaining)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                MaxRemaining = 0;
                return false;
            }
            if (_centeringInFrame == 1) _centeringSteps += 1;


            _layoutEngine.GetScreenFitOffsets(graph, worldView, WidgetSize,
                out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets);
            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 80, targYpadding = 35;

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < graphDepth)
            {
                delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                float maxdelta = Math.Max(delta, 35);
                graph.CameraZoom -= maxdelta;
                MaxRemaining = maxdelta;
                return false;
            }

            //too zoomed in, zoom out
            if ((xoffsets.X < targXpadding && xoffsets.Y < targXpadding) || (yoffsets.X < targYpadding && yoffsets.Y < targYpadding))
            {
                if (xoffsets.X < targXpadding)
                    delta = Math.Min(targXpadding / 2, (targXpadding - xoffsets.X) / 3f);
                else
                    delta = Math.Min(targYpadding / 2, (targYpadding - yoffsets.Y) / 1.3f);

                if (delta > 50)
                {
                    graph.CameraZoom -= delta;
                    MaxRemaining = Math.Abs(delta);
                    return false;
                }
                else
                    zdelta = -1 * delta;
            }

            //too zoomed out, zoom in
            if ((xoffsets.X > targXpadding && xoffsets.Y > targXpadding) && (yoffsets.X > targYpadding && yoffsets.Y > targYpadding))
            {
                if (zoffsets.X > graphDepth)
                    zdelta += Math.Max((zoffsets.X - graphDepth) / 8, 50);
            }

            //too far left, move right
            if (xoffsets.X < targXpadding)
            {
                float diff = targXpadding - xoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta += delta;
            }

            //too far right, move left
            if (xoffsets.Y < targXpadding)
            {
                float diff = targXpadding - xoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta -= delta;
            }

            //off center, center it
            float XDiff = xoffsets.X - xoffsets.Y;
            if (Math.Abs(XDiff) > 40)
            {
                delta = Math.Max(Math.Abs(XDiff / 2), 15);
                if (XDiff > 0)
                    xdelta -= delta;
                else
                    xdelta += delta;
            }


            if (yoffsets.X < targYpadding)
            {
                float diff = targYpadding - yoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta += delta;
            }

            if (yoffsets.Y < targYpadding)
            {
                float diff = targYpadding - yoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta -= delta;
            }

            float YDiff = yoffsets.X - yoffsets.Y;
            if (Math.Abs(YDiff) > 40)
            {
                delta = Math.Max(Math.Abs(YDiff / 2), 15);
                if (YDiff > 0) ydelta -= delta;
                else ydelta += delta;
            }


            float actualXdelta = Math.Min(Math.Abs(xdelta), 150);
            if (xdelta > 0)
                graph.CameraXOffset += actualXdelta;
            else
                graph.CameraXOffset -= actualXdelta;

            float actualYdelta = Math.Min(Math.Abs(ydelta), 150);
            if (ydelta > 0)
                graph.CameraYOffset += actualYdelta;
            else
                graph.CameraYOffset -= actualYdelta;

            float actualZdelta = Math.Min(Math.Abs(zdelta), 300);
            if (zdelta > 0)
                graph.CameraZoom += actualZdelta;
            else
            {
                if (zdelta < 0) actualZdelta *= 10;
                graph.CameraZoom -= actualZdelta;
            }

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));

            return Math.Abs(xdelta) < 10 && Math.Abs(ydelta) < 10 && Math.Abs(zdelta) < 20;
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

        class KEYPRESS_CAPTION
        {
            public string message;
            public Key key;
            public ModifierKeys modifiers;
            public long startedMS;
            public long repeats;
            public string MenuShortut;
        }

        List<KEYPRESS_CAPTION> _keypressCaptions = new List<KEYPRESS_CAPTION>();

        void DisplayShortcutActivation(string shortcut, string action)
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


        void DisplayKeyPress(Tuple<Key, ModifierKeys> keyPressed, string messageCaption)
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


        public void AlertKeybindPressed(Tuple<Key, ModifierKeys> keyPressed, eKeybind boundAction)
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
                case eKeybind.ToggleHeatmap:
                    ToggleRenderingMode(eRenderingMode.eHeatmap);
                    resultText = _renderingMode == eRenderingMode.eHeatmap ? "Activated" : "Deactivated";
                    break;

                case eKeybind.ToggleConditionals:
                    ToggleRenderingMode(eRenderingMode.eConditionals);
                    resultText = _renderingMode == eRenderingMode.eConditionals ? "Activated" : "Deactivated";
                    break;

                case eKeybind.MoveUp:

                    float delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraYOffset += delta;
                    break;

                case eKeybind.MoveDown:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraYOffset -= delta;
                    break;

                case eKeybind.MoveLeft:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraXOffset -= delta;
                    break;

                case eKeybind.MoveRight:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    graph.CameraXOffset += delta;
                    break;

                case eKeybind.RollGraphZAnti:
                    {
                        delta = 0.07f;
                        delta += (shiftModifier * 0.13f);
                        _rollDelta += delta;
                        break;
                    }

                case eKeybind.RollGraphZClock:
                    {
                        delta = 0.07f;
                        delta += (shiftModifier * 0.13f);
                        _rollDelta += -1 * delta;
                        break;
                    }

                case eKeybind.YawYRight:
                    {
                        _yawDelta += 0.04f + (shiftModifier * 0.13f);
                        break;
                    }

                case eKeybind.YawYLeft:
                    {
                        _yawDelta += -1 * (0.04f + (shiftModifier * 0.13f));
                        break;
                    }

                case eKeybind.PitchXBack:
                    {
                        _pitchDelta += 0.06f + (shiftModifier * 0.13f);
                        break;
                    }
                case eKeybind.PitchXFwd:
                    {
                        _pitchDelta += -1 * (0.06f + (shiftModifier * 0.13f));
                        break;
                    }

                case eKeybind.CenterFrame:
                    StartCenterGraphInFrameStepping(false);
                    resultText = _centeringInFrame > 0 ? "Activated" : "Deactivated";
                    break;

                case eKeybind.LockCenterFrame:
                    StartCenterGraphInFrameStepping(true);
                    resultText = _centeringInFrame > 0 ? "Activated" : "Deactivated";
                    break;

                case eKeybind.RaiseForceTemperature:
                    graph.IncreaseTemperature();
                    break;

                case eKeybind.ToggleAllText:
                    graph.Opt_TextEnabled = !graph.Opt_TextEnabled;
                    resultText = graph.Opt_TextEnabled ? "Visible" : "Hidden";
                    break;

                case eKeybind.ToggleInsText:
                    graph.Opt_TextEnabledIns = !graph.Opt_TextEnabledIns;
                    resultText = graph.Opt_TextEnabledIns ? "Visible" : "Hidden";
                    break;

                case eKeybind.ToggleLiveText:
                    graph.Opt_TextEnabledLive = !graph.Opt_TextEnabledLive;
                    resultText = graph.Opt_TextEnabledLive ? "Visible" : "Hidden";
                    break;

                case eKeybind.Cancel:
                    _QuickMenu.CancelPressed();
                    break;

                case eKeybind.QuickMenu:
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
                if (resultText != null) caption += $": {resultText}";
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
        void UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null)
            {
                proj = Matrix4x4.Identity;
                view = Matrix4x4.Identity;
                world = Matrix4x4.Identity;
                return;
            }

            if (graph.CameraClippingFar <= graph.CameraClippingNear) graph.CameraClippingFar = graph.CameraClippingNear + 1;
            proj = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, (float)WidgetSize.X / WidgetSize.Y, graph.CameraClippingNear, graph.CameraClippingFar);

            Matrix4x4 pitch = Matrix4x4.CreateFromAxisAngle(Vector3.UnitX, _pitchDelta);
            Matrix4x4 yaw = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, _yawDelta);
            Matrix4x4 roll = Matrix4x4.CreateFromAxisAngle(Vector3.UnitZ, _rollDelta);
            _pitchDelta = 0; _yawDelta = 0f; _rollDelta = 0;

            Matrix4x4 offsetRotation = pitch * yaw * roll;

            world = graph.RotationMatrix * offsetRotation;

            view = Matrix4x4.CreateTranslation(new Vector3(graph.CameraXOffset, graph.CameraYOffset, graph.CameraZoom));
            graph.RotationMatrix = world;
        }

        /// <summary>
        /// Write the rendered graph/HUD items to the draw list
        /// </summary>
        /// <param name="graphSize">Size of the graph area being drawn</param>
        /// <param name="graph">The graph being drawn</param>
        public void Draw(Vector2 graphSize, PlottedGraph graph)
        {
            _graphLock.EnterReadLock();

            if (graph != ActiveGraph)
            {
                ActiveGraph = graph;
            }

            if (ActiveGraph != null)
            {
                DrawGraphImage();
            }

            DrawHUD(graphSize, ActiveGraph);

            _graphLock.ExitReadLock();
        }

        Framebuffer _outputFramebuffer1, _outputFramebuffer2, _pickingFrameBuffer;
        bool _processingAnimatedGraph;

        /// <summary>
        /// Edges pipeline = line list or line strp
        /// Points pipeline = visible nodes where we draw sphere/etc texture
        /// Picking pipleine = same as points but different data, not drawn to screen. Seperate shaders to reduce branching
        /// Font pipeline = triangles
        /// </summary>
        Pipeline _edgesPipelineRelative, _edgesPipelineRaw, _pointsPipeline, _pickingPipeline, _fontPipeline;
        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout, _fontRsrcLayout;
        Texture _outputTexture1, _outputTexture2, _testPickingTexture, _pickingStagingTexture;

        //vert/frag rendering buffers
        //ResourceSet _crs_core, _crs_nodesEdges, _crs_font;
        ResourceSet _crs_font;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _RawEdgeVertBuffer, _RawEdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodePickingBuffer, _NodeIndexBuffer;
        private DeviceBuffer _FontVertBuffer;
        private DeviceBuffer _FontIndexBufferAll;
        DeviceBuffer _paramsBuffer;


        int latestWrittenTexture = 1;
        /// <summary>
        /// Get a framebuffer we can safely draw to
        /// Must hold upgradable read lock
        /// </summary>
        /// <param name="drawtarget"></param>
        void GetOutputFramebuffer(out Framebuffer drawtarget)
        {
            _graphLock.EnterWriteLock();
            if (latestWrittenTexture == 1)
            {
                Logging.RecordLogEvent($"GetLatestTexture setting draw target to texture 2 --->", Logging.LogFilterType.BulkDebugLogFile);
                drawtarget = _outputFramebuffer2;
            }
            else
            {
                Logging.RecordLogEvent("GetLatestTexture setting draw target to texture 1 --->", Logging.LogFilterType.BulkDebugLogFile);
                drawtarget = _outputFramebuffer1;
            }
            _graphLock.ExitWriteLock();
        }

        /// <summary>
        /// Drawing is complete. Release the write lock so it can be displayed on the screen
        /// The other framebuffer will become locked for writing
        /// </summary>
        void ReleaseOutputFramebuffer()
        {
            _graphLock.EnterWriteLock();
            latestWrittenTexture = (latestWrittenTexture == 1) ? 2 : 1;
            Logging.RecordLogEvent($"ReleaseOutputFramebuffer set latest written graph texture to {latestWrittenTexture} <----", Logging.LogFilterType.BulkDebugLogFile);

            _graphLock.ExitWriteLock();
        }

        /// <summary>
        /// Get the most recently drawn framebuffer for displaying to the user
        /// </summary>
        /// <param name="graphtexture">Texture of the framebuffer contents</param>
        void GetLatestTexture(out Texture graphtexture)
        {
            if (latestWrittenTexture == 1)
            {
                Logging.RecordLogEvent($"GetLatestTexture {ActiveGraph?.TID}  Returning latest written graph texture 1", Logging.LogFilterType.BulkDebugLogFile);
                graphtexture = _outputTexture1;
            }
            else
            {
                Logging.RecordLogEvent($"GetLatestTexture {ActiveGraph?.TID}  Returning latest written graph texture 2", Logging.LogFilterType.BulkDebugLogFile);
                graphtexture = _outputTexture2;
            }
        }


        /// <summary>
        /// Initialise graphics resources
        /// </summary>
        unsafe void SetupRenderingResources()
        {

            _paramsBuffer = TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<GraphShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "GraphPlotparamsBuffer");

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));

            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeTextures", ResourceKind.TextureReadOnly, ShaderStages.Fragment)));


            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
            pipelineDescription.BlendState = BlendStateDescription.SingleAlphaBlend;
            pipelineDescription.DepthStencilState = DepthStencilStateDescription.DepthOnlyLessEqual;
            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: false,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout };
            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodeShaders(_gd, out _NodeVertexBuffer, out _NodeIndexBuffer);

            Debug.Assert(_outputTexture1 is null && _outputFramebuffer1 is null);
            Debug.Assert(_outputTexture2 is null && _outputFramebuffer2 is null);

            RecreateOutputTextures();

            Debug.Assert(_outputTexture1 is not null && _outputFramebuffer1 is not null);
            Debug.Assert(_outputTexture2 is not null && _outputFramebuffer2 is not null);

            pipelineDescription.Outputs = _outputFramebuffer1.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodePickingShaders(_gd, out _NodePickingBuffer);
            _pickingPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gd, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRelative = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRawShaders(_gd, out _RawEdgeVertBuffer, out _RawEdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRaw = _factory.CreateGraphicsPipeline(pipelineDescription);



            //font -----------------------

            _fontRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            ResourceSetDescription crs_font_rsd = new ResourceSetDescription(_fontRsrcLayout, _controller._fontTextureView);
            _crs_font = _factory.CreateResourceSet(crs_font_rsd);

            ShaderSetDescription fontshader = SPIRVShaders.CreateFontShaders(_gd, out _FontVertBuffer, out _FontIndexBufferAll);

            GraphicsPipelineDescription fontpd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                DepthStencilStateDescription.DepthOnlyLessEqual,
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, true, true),
                PrimitiveTopology.TriangleList, fontshader,
                new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer1.OutputDescription);
            _fontPipeline = _factory.CreateGraphicsPipeline(fontpd);
        }

        /// <summary>
        /// Re-initialise graphics resources, for use when the size of the widget has changed
        /// </summary>
        void RecreateOutputTextures()
        {

            Logging.RecordLogEvent("RecreateOutputTextures DISPOSING ALL", Logging.LogFilterType.BulkDebugLogFile);
            _graphLock.EnterWriteLock();
            VeldridGraphBuffers.DoDispose(_outputTexture1);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer1);
            VeldridGraphBuffers.DoDispose(_outputTexture2);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer2);
            VeldridGraphBuffers.DoDispose(_testPickingTexture);
            VeldridGraphBuffers.DoDispose(_pickingFrameBuffer);
            VeldridGraphBuffers.DoDispose(_pickingStagingTexture);

            _outputTexture1 = _factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture1.Name = "OutputTexture1" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer1 = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture1));
            _outputFramebuffer1.Name = $"OPFB1_" + _outputTexture1.Name;

            _outputTexture2 = _factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture2.Name = "OutputTexture2" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer2 = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture2));
            _outputFramebuffer2.Name = $"OPFB2_" + _outputTexture2.Name;

            _testPickingTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                    Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _pickingFrameBuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));

            _pickingStagingTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                    Veldrid.PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.Staging));
            _graphLock.ExitWriteLock();
            Logging.RecordLogEvent("RecreateOutputTextures recreated", Logging.LogFilterType.BulkDebugLogFile);
        }


        [StructLayout(LayoutKind.Sequential)]
        struct fontStruc
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


        eRenderingMode _renderingMode = eRenderingMode.eStandardControlFlow;

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
        void SetRenderingMode(eRenderingMode newMode)
        {
            switch (newMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    break;
                case eRenderingMode.eConditionals:
                    break;
                case eRenderingMode.eHeatmap:
                    ActiveGraph!.InternalProtoGraph.HeatSolvingComplete = false; //todo - temporary for dev
                    break;
                default:
                    Console.WriteLine("unknown rendering mode");
                    break;
            }
            _renderingMode = newMode;
        }


        static readonly Dictionary<string, List<fontStruc>> _cachedStrings = new Dictionary<string, List<fontStruc>>();

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
        static void RenderString(string inputString, uint nodeIdx, float fontScale, ImFontPtr font, ref List<fontStruc> stringVerts, uint colour, float yOff = 0)
        {
            if (inputString == null)
                return;
            if (_cachedStrings.TryGetValue(inputString, out List<fontStruc>? cached))
            {
                stringVerts.AddRange(cached);
                return;
            }

            float xPos = 0;
            float yPos = 50;
            float glyphYClip = 10;
            WritableRgbaFloat fcolour = new WritableRgbaFloat(colour);
            List<fontStruc> result = new List<fontStruc>();
            for (var i = 0; i < inputString.Length; i++)
            {
                ImFontGlyphPtr glyph = font.FindGlyph(inputString[i]);
                float charWidth = glyph.AdvanceX * fontScale;
                float charHeight = fontScale * (glyph.Y1 - glyph.Y0);


                float xEnd = xPos + charWidth;
                float yBase = yPos + (glyphYClip - glyph.Y1) * fontScale;
                float yTop = yBase + charHeight;

                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1), yOffset = yOff, fontColour = fcolour });
                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                result.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0), yOffset = yOff, fontColour = fcolour });
                xPos += charWidth;
            }
            _cachedStrings.Add(inputString, result);
            stringVerts.AddRange(result);
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
        GraphShaderParams updateShaderParams(PlottedGraph graph, uint textureSize, Matrix4x4 projection, Matrix4x4 view, Matrix4x4 world, CommandList cl)
        {
            GraphShaderParams shaderParams = new GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = _mouseoverNodeID,
                isAnimated = graph.IsAnimated
            };

            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(new Vector3(graph.CameraXOffset, graph.CameraYOffset, graph.CameraZoom));

            shaderParams.proj = projection;
            shaderParams.view = view;
            shaderParams.world = world;
            shaderParams.nonRotatedView = Matrix4x4.Multiply(Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0), cameraTranslation);

            cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);

            return shaderParams;
        }


        class RISINGEXTTXT
        {
            public int nodeIdx;
            public float currentY;
            public string text;
            public int remainingFrames;
        }

        readonly List<RISINGEXTTXT> _activeRisings = new List<RISINGEXTTXT>();

        void uploadFontVerts(List<fontStruc> stringVerts)
        {
            uint[] charIndexes = Enumerable.Range(0, stringVerts.Count).Select(i => (uint)i).ToArray();

            if (stringVerts.Count * fontStruc.SizeInBytes > _FontVertBuffer.SizeInBytes)
            {
                VeldridGraphBuffers.VRAMDispose(_FontVertBuffer);
                _FontVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)stringVerts.Count * fontStruc.SizeInBytes, BufferUsage.VertexBuffer, name: _FontVertBuffer.Name);
                VeldridGraphBuffers.VRAMDispose(_FontIndexBufferAll);
                _FontIndexBufferAll = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)charIndexes.Length * sizeof(uint), BufferUsage.IndexBuffer, name: _FontIndexBufferAll.Name);
            }

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.UpdateBuffer(_FontVertBuffer, 0, stringVerts.ToArray());
            cl.UpdateBuffer(_FontIndexBufferAll, 0, charIndexes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();
        }

        List<fontStruc> RenderHighlightedNodeText(List<Tuple<string, uint>> captions, int nodeIdx = -1)
        {
            const float fontScale = 8f;
            List<fontStruc> stringVerts = new List<fontStruc>();

            if (captions.Count > nodeIdx)
            {
                var caption = captions[nodeIdx];
                if (caption != null)
                {
                    RenderString(caption.Item1, (uint)nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, caption.Item2);
                }
            }

            maintainRisingTexts(fontScale, ref stringVerts);
            uploadFontVerts(stringVerts);

            return stringVerts;
        }

        void maintainRisingTexts(float fontScale, ref List<fontStruc> stringVerts)
        {
            _activeRisings.RemoveAll(x => x.remainingFrames == 0);
            PlottedGraph? graph = ActiveGraph;
            if (graph == null) return;

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
                    RISINGEXTTXT newriser = new RISINGEXTTXT()
                    {
                        currentY = 25.0f,
                        nodeIdx = (int)nodeString.Item1,
                        text = nodeString.Item2,
                        remainingFrames = -1
                    };
                    _activeRisings.Add(newriser);
                }
            }

            //add any new rising extern labels
            if (newRisingExterns.Count > 0)
            {
                foreach (var f in newRisingExterns)
                {
                    RISINGEXTTXT newriser = new RISINGEXTTXT()
                    {
                        currentY = 25.0f,
                        nodeIdx = (int)f.Item1,
                        text = f.Item2,
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
                //Console.WriteLine($"Drawing '{ar.text}' at y {ar.currentY}");
                RenderString(ar.text, (uint)ar.nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, risingSymColour, yOff: ar.currentY);
            }
        }

        readonly float _fontScale = 13.0f;

        List<fontStruc> renderGraphText(List<Tuple<string, uint>> captions)
        {
            List<fontStruc> stringVerts = new List<fontStruc>();
            PlottedGraph? graph = ActiveGraph;
            if (graph == null) return stringVerts;
            if (!graph.Opt_TextEnabled) return stringVerts;

            for (int nodeIdx = 0; nodeIdx < captions.Count; nodeIdx++)
            {
                if (captions[nodeIdx] == null) continue;
                RenderString(captions[nodeIdx].Item1, (uint)nodeIdx, _fontScale, _controller._unicodeFont, ref stringVerts, captions[nodeIdx].Item2);
            }


            return stringVerts;
        }

        void MaintainCaptions(List<fontStruc> stringVerts)
        {
            maintainRisingTexts(_fontScale, ref stringVerts);
            uploadFontVerts(stringVerts);
        }

        ulong _lastThemeVersion = 0;

        /// <summary>
        /// Draws the various nodes, edges, captions and illustrations to the framebuffer for display
        /// </summary>
        /// <param name="cl">A veldrid commandlist, for use by this thread only</param>
        /// <param name="graph">The PlottedGraph to draw</param>
        public void DrawGraph(CommandList cl, PlottedGraph graph)
        {
            Position2DColour[] EdgeLineVerts = graph.GetEdgeLineVerts(_renderingMode, out List<uint> edgeDrawIndexes, out int edgeVertCount, out int drawnEdgeCount);
            if (drawnEdgeCount == 0 || Exiting) return;

            Logging.RecordLogEvent("rendergraph start", filter: Logging.LogFilterType.BulkDebugLogFile);

            //theme changed, purged cached text in case its colour changed
            ulong themeVersion = Themes.ThemeVersion;
            bool newColours = _lastThemeVersion < themeVersion;
            if (newColours)
            {
                _cachedStrings.Clear();
                _lastThemeVersion = themeVersion;
            }

            //todo - thread safe persistent commandlist
            cl.Begin();

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _imageTextureView);

            //VeldridGraphBuffers.DoDispose(_crs_nodesEdges);
            ResourceSet crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);

            //rotval += 0.01f; //autorotate
            var textureSize = graph.LinearIndexTextureSize();

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            updateShaderParams(graph, textureSize, proj, view, world, cl);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer,
                _gd.PointSampler, graph.LayoutState.PositionsVRAM1, graph.LayoutState.AttributesVRAM1);
            ResourceSet crs_core = _factory.CreateResourceSet(crs_core_rsd);

            Position2DColour[] NodeVerts = graph.GetMaingraphNodeVerts(_renderingMode,
            out List<uint> nodeIndices, out Position2DColour[] nodePickingColors,
            out List<Tuple<string?, uint>> captions);

            //_layoutEngine.GetScreenFitOffsets(WidgetSize, out _furthestX, out _furthestY, out _furthestZ);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * Position2DColour.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                VRAMDispose(_NodeVertexBuffer);
                VRAMDispose(_NodePickingBuffer);
                VRAMDispose(_NodeIndexBuffer);

                _NodeVertexBuffer = TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "NodeVertexBuffer");
                _NodePickingBuffer = TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "NodePickingVertexBuffer");
                _NodeIndexBuffer = TrackedVRAMAlloc(_gd, (uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "NodeIndexBuffer");
            }

            //todo - only do this on changes
            cl.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            cl.UpdateBuffer(_NodePickingBuffer, 0, nodePickingColors);
            cl.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());

            if (((edgeVertCount * 4) > _EdgeIndexBuffer.SizeInBytes))
            {
                VRAMDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = TrackedVRAMAlloc(_gd, (uint)EdgeLineVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "EdgeVertexBuffer");
                VRAMDispose(_EdgeIndexBuffer);
                _EdgeIndexBuffer = TrackedVRAMAlloc(_gd, (uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "EdgeIndexBuffer");
            }

            //todo - only do this on changes
            cl.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            cl.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            Logging.RecordLogEvent("render graph 4", filter: Logging.LogFilterType.BulkDebugLogFile);
            List<fontStruc> stringVerts;
            if (_mouseoverNodeID == -1)
            {
                stringVerts = renderGraphText(captions);
            }
            else
            {
                stringVerts = RenderHighlightedNodeText(captions, _mouseoverNodeID);
            }

            MaintainCaptions(stringVerts);

            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / 4));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / 4));

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

                cl.DrawIndexed(indexCount: (uint)stringVerts.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
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
            cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            cl.CopyTexture(_testPickingTexture, _pickingStagingTexture);

            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            ReleaseOutputFramebuffer();

            crs_core.Dispose();
            crs_nodesEdges.Dispose();
            Logging.RecordLogEvent("rendergraph end", filter: Logging.LogFilterType.BulkDebugLogFile);
        }


        /// <summary>
        /// Add the most recently drawn framebuffer to the drawlist
        /// </summary>
        /// <returns>The texture for the drawn framebuffer. Useful for screenshots/videos</returns>
        public Texture DrawGraphImage()
        {
            Vector2 currentRegionSize = ImGui.GetContentRegionAvail();
            if (currentRegionSize != WidgetSize)
            {
                if (_newGraphSize == null || _newGraphSize != currentRegionSize)
                    _newGraphSize = currentRegionSize;
            }

            WidgetPos = ImGui.GetCursorScreenPos();
            _MousePos = ImGui.GetMousePos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 

            GetLatestTexture(out Texture outputTexture);

            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, outputTexture, "GraphMainPlot" + outputTexture.Name);

            Debug.Assert(!outputTexture.IsDisposed);

            imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: WidgetPos,
                p_max: new Vector2(WidgetPos.X + outputTexture.Width, WidgetPos.Y + outputTexture.Height),
                uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));

            _isInputTarget = ImGui.IsItemActive();

            return outputTexture;
        }

        /// <summary>
        /// Get the current text colour as a Vector4
        /// Wrapper for the memory unsafe ImGui API 
        /// </summary>
        /// <returns>A Vector4 describing the current text colour</returns>
        unsafe Vector4 GetTextColour() => *ImGui.GetStyleColorVec4(ImGuiCol.Text);


        /// <summary>
        /// Draw the latest keyboard shortcut activations to the screen
        /// </summary>
        /// <param name="topLeft">Location on the screen to draw to</param>
        void DrawKeystrokes(Vector2 topLeft)
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
                    if (keycaption.modifiers.HasFlag(ModifierKeys.Control)) keystroke = "Ctrl+" + keystroke;
                    if (keycaption.modifiers.HasFlag(ModifierKeys.Alt)) keystroke = "Alt+" + keystroke;
                    if (keycaption.modifiers.HasFlag(ModifierKeys.Shift)) keystroke = "Shift+" + keystroke;
                }

                string msg = $"[{keystroke}] -> {keycaption.message}";
                if (keycaption.repeats > 1) msg += $" x{keycaption.repeats}";

                float alpha = i == (_keypressCaptions.Count - 1) ? 255 : 220;
                if (keycaption.startedMS < fadeLimit)
                {
                    double fadetime = fadeLimit - keycaption.startedMS;
                    alpha *= (float)(1 - (fadetime / (double)fadeWindow));
                }

                ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(textCol).ToUint((uint)alpha));
                ImGui.Text(msg);
                ImGui.PopStyleColor();
            }
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
            if (graph == null) return;

            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            float depth = 20;//todo based on count 
            float maxWidth = 200;

            TraceRecord trace = graph.InternalProtoGraph.TraceData;

            Logging.TIMELINE_EVENT[] evts = trace.GetTimeLineEntries(oldest: timenow - GlobalConfig.VisMessageMaxLingerTime, max: 5);

            float currentY = depth;
            ImGui.SetCursorScreenPos(new Vector2(pos.X - maxWidth, pos.Y + currentY));
            for (var i = 0; i < evts.Length; i++)
            {
                Logging.TIMELINE_EVENT evt = evts[i];
                long displayTimeRemaining = GlobalConfig.VisMessageMaxLingerTime - (timenow - evt.EventTimeMS);

                ImGui.SetCursorPosX(pos.X - maxWidth);

                double alpha = i == (evts.Length - 1) ? 255 : 220;
                if (displayTimeRemaining <= GlobalConfig.VisMessageFadeStartTime)
                {
                    double fadetime = GlobalConfig.VisMessageFadeStartTime - displayTimeRemaining;
                    alpha *= 1.0 - (fadetime / (double)GlobalConfig.VisMessageFadeStartTime);
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
                    default:
                        textCol = System.Drawing.Color.Gray;
                        msg = "Unknown Timeline event" + evt.TimelineEventType.ToString();
                        break;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(textCol).ToUint((uint)alpha));
                ImGui.TextWrapped(msg);
                ImGui.PopStyleColor();
            }
        }


        /// <summary>
        /// Draw in-widget buttons such as the layout selector, keybind activations and the quickmenu
        /// </summary>
        /// <param name="widgetSize"></param>
        /// <param name="activeGraph"></param>
        void DrawHUD(Vector2 widgetSize, PlottedGraph activeGraph)
        {
            string msg;
            Vector2 topLeft = ImGui.GetCursorScreenPos();
            Vector2 bottomLeft = new Vector2(topLeft.X, topLeft.Y + widgetSize.Y);
            Vector2 bottomRight = new Vector2(bottomLeft.X + widgetSize.X, bottomLeft.Y);

            PlottedGraph? graph = ActiveGraph;
            if (graph != null)
            {
                DrawLayoutSelector(graph, bottomRight, 0.25f, activeGraph.ActiveLayoutStyle);
            }
            else
            {
                msg = "No active graph to display";
                Vector2 screenMiddle = new Vector2(bottomLeft.X + ((widgetSize.X / 2) - (ImGui.CalcTextSize(msg).X / 2)), bottomLeft.Y - (widgetSize.Y / 2));
                ImGui.SetCursorScreenPos(screenMiddle);
                ImGui.Text(msg);
                return;
            }

            if (GlobalConfig.ShowKeystrokes) DrawKeystrokes(topLeft);

            _QuickMenu.Draw(bottomLeft, 0.25f, graph);


            Vector2 midRight = new Vector2(bottomLeft.X + widgetSize.X, bottomLeft.Y - widgetSize.Y / 2);
            //DrawDisasmPreview(graph, midRight);
        }


        bool _showLayoutSelectorPopup;
        IntPtr getLayoutIcon(LayoutStyles.Style layout)
        {
            Texture? iconTex = null;
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
                    Console.WriteLine($"ERROR: no icond for layout {layout}");
                    iconTex = _controller.GetImage("Force3D");
                    break;
            }

            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, iconTex, "LayoutIcon");
            return CPUframeBufferTextureId;
        }


        void DrawLayoutSelector(PlottedGraph graph, Vector2 position, float scale, LayoutStyles.Style layout)
        {

            Vector2 iconSize = new Vector2(128 * scale, 128 * scale);
            float padding = 6f;
            Vector2 pmin = new Vector2((position.X - iconSize.X) - padding, ((position.Y - iconSize.Y) - 4) - padding);


            ImGui.SetCursorScreenPos(pmin);

            ImGui.PushStyleColor(ImGuiCol.Button, 0x11000000);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0x11000000);
            ImGui.ImageButton(getLayoutIcon(layout), iconSize);
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



        void DrawLayoutSelectorIcons(Vector2 iconSize, bool snappingToPreset)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null) return;
            float buttonWidth = 150f;

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(LayoutStyles.Style.ForceDirected3DNodes),
                iconSize, buttonWidth, "Force Directed Nodes", graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DNodes))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.ForceDirected3DNodes)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(LayoutStyles.Style.ForceDirected3DBlocks),
                iconSize, buttonWidth, "Force Directed Blocks", graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DBlocks))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.ForceDirected3DBlocks)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(LayoutStyles.Style.CylinderLayout),
                iconSize, buttonWidth, "Cylinder", graph.ActiveLayoutStyle == LayoutStyles.Style.CylinderLayout))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.CylinderLayout)) { graph.BeginNewLayout(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(LayoutStyles.Style.Circle),
                iconSize, buttonWidth, "Circle", graph.ActiveLayoutStyle == LayoutStyles.Style.Circle))
            {
                if (!snappingToPreset && graph.SetLayout(LayoutStyles.Style.Circle)) { graph.BeginNewLayout(); }
            }
        }


        Vector2? _newGraphSize = null;



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

            HandleGraphUpdates();

            _layoutEngine.Compute(cl, graph, _mouseoverNodeID, graph.IsAnimated);

            if (_controller.DialogOpen is false)
            {
                DoMouseNodePicking(_gd);
            }

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            Matrix4x4 worldView = world * view;
            if (_centeringInFrame is not 0)
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
                if (done && _centeringInFrame != 2)
                {
                    Console.WriteLine($"Centering done after {_centeringSteps} steps");
                    _centeringInFrame = 0;
                }
                else
                {
                    if (_centeringInFrame == 1 && _centeringSteps > 1000)
                    {
                        Console.WriteLine($"Warning: centering has taken {_centeringSteps} steps so far, abandoning");
                        _centeringInFrame = 0;
                    }
                }
            }


            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positionBuf));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, attribBuf));

            Logging.RecordLogEvent("GenerateMainGraph Starting rendergraph", filter: Logging.LogFilterType.BulkDebugLogFile);
            DrawGraph(cl, graph);

            Logging.RecordLogEvent("GenerateMainGraph upd then done", filter: Logging.LogFilterType.BulkDebugLogFile);
            graph.UpdatePreviewVisibleRegion(WidgetSize);
            _graphLock.ExitUpgradeableReadLock();
        }



        readonly object _lock = new object();
        readonly Queue<System.Drawing.Bitmap> frames = new Queue<System.Drawing.Bitmap>();
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
        void HandleGraphUpdates()
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null || Exiting) return;
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
                graph.LayoutState.ResetNodeAttributes(_gd);
                //graph.HighlightsChanged = false;
            }
        }



        public Vector2 WidgetPos { get; private set; }
        Vector2 _MousePos;

        int _mouseoverNodeID = -1;
        /// <summary>
        /// Must hold read lock
        /// Check if the mouse position corresponds to a node ID in the picking texture
        /// If so - the mouse is over that nod
        /// </summary>
        /// <param name="_gd"></param>
        void DoMouseNodePicking(GraphicsDevice _gd)
        {
            PlottedGraph? graph = ActiveGraph;
            if (graph == null || Exiting) return;

            float mouseX = (_MousePos.X - WidgetPos.X);
            float mouseY = (WidgetPos.Y + _pickingStagingTexture.Height) - _MousePos.Y;

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
                        if (f.R != _mouseoverNodeID && f.R < graph.InternalProtoGraph.NodeList.Count) //mouse is over a different node
                        {
                            NodeData n = graph.InternalProtoGraph.NodeList[(int)f.R];
                            Console.WriteLine($"Mouse: {mouseX},{mouseY} on node {f.R} -> 0x{n.address:X}. Out:{n.OutgoingNeighboursSet.Count} In:{n.IncomingNeighboursSet.Count}");
                            _mouseoverNodeID = (int)f.R;
                        }
                        hit = true;
                    }
                }
            }
            if (!hit) //mouse is not over a node
            {
                _mouseoverNodeID = -1;
            }

        }
    }
}
