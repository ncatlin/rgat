using ImGuiNET;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Veldrid;
using Veldrid.ImageSharp;
using Veldrid.SPIRV;
using rgatCore.Shaders.SPIR_V;
using static rgatCore.VeldridGraphBuffers;
using rgatCore.Widgets;

namespace rgatCore
{
    class GraphPlotWidget : IDisposable
    {
        public PlottedGraph ActiveGraph { get; private set; }

        System.Timers.Timer _IrregularActionTimer;
        bool _IrregularActionTimerFired;

        QuickMenu _QuickMenu;
        ImGuiController _controller;
        readonly ReaderWriterLock renderLock = new ReaderWriterLock();

        GraphLayoutEngine _layoutEngine;
        public GraphLayoutEngine LayoutEngine => _layoutEngine;


        GraphicsDevice _gd;
        ResourceFactory _factory;
        Vector2 _graphWidgetSize;

        TextureView _imageTextureView;

        public GraphPlotWidget(ImGuiController controller, GraphicsDevice gdev, Vector2? initialSize = null)
        {
            _controller = controller;
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            _QuickMenu = new QuickMenu(_gd, controller);

            _graphWidgetSize = initialSize ?? new Vector2(400, 400);
            _IrregularActionTimer = new System.Timers.Timer(600);
            _IrregularActionTimer.Elapsed += FireIrregularTimer;
            _IrregularActionTimer.AutoReset = true;
            _IrregularActionTimer.Start();

            _layoutEngine = new GraphLayoutEngine(gdev, controller);
            _imageTextureView = controller.IconTexturesView;
            SetupRenderingResources();

        }


        public void Dispose()
        {
            if (_IrregularActionTimer != null) _IrregularActionTimer.Dispose();
        }


        public void SetActiveGraph(PlottedGraph graph)
        {
            if (graph == ActiveGraph) return;


            //todo - grab lock
            if (graph == null)
            {
                renderLock.AcquireWriterLock(0);
                ActiveGraph = null;
                renderLock.ReleaseWriterLock();
                return;
            }

            renderLock.AcquireWriterLock(0);
            ActiveGraph = graph;
            _layoutEngine.Set_activeGraph(ActiveGraph);
            RecreateGraphicsBuffers();
            renderLock.ReleaseWriterLock();
        }


        private void RecreateGraphicsBuffers()
        {
            _EdgeVertBuffer?.Dispose();
            _EdgeVertBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            _EdgeIndexBuffer?.Dispose();
            _EdgeIndexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            BufferDescription vbDescription = new BufferDescription(1, BufferUsage.VertexBuffer);
            _NodeVertexBuffer?.Dispose();
            _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);
            _NodePickingBuffer?.Dispose();
            _NodePickingBuffer = _factory.CreateBuffer(vbDescription);
        }


        private void FireIrregularTimer(object sender, ElapsedEventArgs e) { _IrregularActionTimerFired = true; }


        public void ApplyZoom(float delta)
        {
            if (ActiveGraph != null)
            {
                ActiveGraph.ApplyMouseWheelDelta(delta);
            }
        }

        bool _isInputTarget = false;
        public void ApplyMouseDrag(Vector2 delta)
        {
            if (ActiveGraph != null && _isInputTarget)
            {
                ActiveGraph.ApplyMouseDragDelta(delta);
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

            if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + _graphWidgetSize.X))
            {
                if (MousePos.Y >= WidgetPos.Y && MousePos.Y < (WidgetPos.Y + _graphWidgetSize.Y))
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
        /// </summary>
        bool CenterGraphInFrameStep(Matrix4x4 worldView, out float MaxRemaining)
        {
            if (_centeringInFrame == 1) _centeringSteps += 1;


            _layoutEngine.GetScreenFitOffsets(worldView, _graphWidgetSize, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets);
            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 80, targYpadding = 35;

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < graphDepth)
            {
                delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                float maxdelta = Math.Max(delta, 35);
                ActiveGraph.CameraZoom -= maxdelta;
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
                    ActiveGraph.CameraZoom -= delta;
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
                ActiveGraph.CameraXOffset += actualXdelta;
            else
                ActiveGraph.CameraXOffset -= actualXdelta;

            float actualYdelta = Math.Min(Math.Abs(ydelta), 150);
            if (ydelta > 0)
                ActiveGraph.CameraYOffset += actualYdelta;
            else
                ActiveGraph.CameraYOffset -= actualYdelta;

            float actualZdelta = Math.Min(Math.Abs(zdelta), 300);
            if (zdelta > 0)
                ActiveGraph.CameraZoom += actualZdelta;
            else
            {
                if (zdelta < 0) actualZdelta *= 10;
                ActiveGraph.CameraZoom -= actualZdelta;
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
                bool swallowKeypress = _QuickMenu.KeyPressed(keyModTuple, out Tuple<string, string> ActivatedShortcut);
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

        public void DisplayShortcutActivation(string shortcut, string action)
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
            PlottedGraph activeGraph = ActiveGraph;
            if (activeGraph == null) return;

            float shiftModifier = ImGui.GetIO().KeyShift ? 1 : 0;
            switch (boundAction)
            {
                case eKeybind.ToggleHeatmap:
                    ToggleRenderingMode(eRenderingMode.eHeatmap);
                    break;

                case eKeybind.ToggleConditionals:
                    ToggleRenderingMode(eRenderingMode.eConditionals);
                    break;

                case eKeybind.MoveUp:
                    float delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    ActiveGraph.CameraYOffset += delta;
                    break;

                case eKeybind.MoveDown:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    ActiveGraph.CameraYOffset -= delta;
                    break;

                case eKeybind.MoveLeft:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    ActiveGraph.CameraXOffset -= delta;
                    break;

                case eKeybind.MoveRight:
                    delta = 50;
                    delta += (50 * (shiftModifier * 1.5f));
                    ActiveGraph.CameraXOffset += delta;
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
                    break;

                case eKeybind.LockCenterFrame:
                    StartCenterGraphInFrameStepping(true);
                    break;

                case eKeybind.RaiseForceTemperature:
                    ActiveGraph.InternalProtoGraph.TraceData.RecordTimelineEvent(Logging.eTimelineEvent.ProcessStart, 0);
                    ActiveGraph.IncreaseTemperature();
                    break;

                case eKeybind.ToggleAllText:
                    ActiveGraph.TextEnabled = !ActiveGraph.TextEnabled;
                    break;

                case eKeybind.ToggleInsText:
                    ActiveGraph.TextEnabledIns = !ActiveGraph.TextEnabledIns;
                    break;

                case eKeybind.ToggleLiveText:
                    ActiveGraph.TextEnabledLive = !ActiveGraph.TextEnabledLive;
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
                DisplayKeyPress(keyPressed, boundAction.ToString());
        }




        private float _pitchDelta, _yawDelta, _rollDelta = 0;

        void UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world)
        {
            if (ActiveGraph.CameraClippingFar <= ActiveGraph.CameraClippingNear) ActiveGraph.CameraClippingFar = ActiveGraph.CameraClippingNear + 1;
            proj = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, (float)_graphWidgetSize.X / _graphWidgetSize.Y, ActiveGraph.CameraClippingNear, ActiveGraph.CameraClippingFar);

            Matrix4x4 pitch = Matrix4x4.CreateFromAxisAngle(Vector3.UnitX, _pitchDelta);
            Matrix4x4 yaw = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, _yawDelta);
            Matrix4x4 roll = Matrix4x4.CreateFromAxisAngle(Vector3.UnitZ, _rollDelta);
            _pitchDelta = 0; _yawDelta = 0f; _rollDelta = 0;

            Matrix4x4 offsetRotation = pitch * yaw * roll;

            world = ActiveGraph.RotationMatrix * offsetRotation;

            view = Matrix4x4.CreateTranslation(new Vector3(ActiveGraph.CameraXOffset, ActiveGraph.CameraYOffset, ActiveGraph.CameraZoom));
            ActiveGraph.RotationMatrix = world;
        }


        public void Draw(Vector2 graphSize)
        {
            renderLock.AcquireReaderLock(200);
            if (_IrregularActionTimerFired)
                PerformIrregularActions();

            if (ActiveGraph != null)
            {
                DrawGraph();
            }

            drawHUD(graphSize);
            renderLock.ReleaseReaderLock();
        }

        Framebuffer _outputFramebuffer, _pickingFrameBuffer;
        bool processingAnimatedGraph;

        /// <summary>
        /// Edges pipeline = line list or line strp
        /// Points pipeline = visible nodes where we draw sphere/etc texture
        /// Picking pipleine = same as points but different data, not drawn to screen. Seperate shaders to reduce branching
        /// Font pipeline = triangles
        /// </summary>
        Pipeline _edgesPipelineRelative, _edgesPipelineRaw, _pointsPipeline, _pickingPipeline, _fontPipeline;
        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout, _fontRsrcLayout;
        Texture _outputTexture, _testPickingTexture, _pickingStagingTexture;

        //vert/frag rendering buffers
        ResourceSet _crs_core, _crs_nodesEdges, _crs_font;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _RawEdgeVertBuffer, _RawEdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodePickingBuffer, _NodeIndexBuffer;
        DeviceBuffer _FontVertBuffer, _FontIndexBuffer;
        DeviceBuffer _paramsBuffer;

        public DeviceBuffer _animBuffer { get; private set; }

        public unsafe void SetupRenderingResources()
        {
            _paramsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<GraphShaderParams>(), BufferUsage.UniformBuffer));

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));

            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
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
            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodeShaders(_factory, out _NodeVertexBuffer, out _NodeIndexBuffer);

            Debug.Assert(_outputTexture == null);
            Debug.Assert(_outputFramebuffer == null);

            RecreateOutputTextures();

            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodePickingShaders(_factory, out _NodePickingBuffer);
            _pickingPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRelative = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRawShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRaw = _factory.CreateGraphicsPipeline(pipelineDescription);



            //font -----------------------

            _fontRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            ResourceSetDescription crs_font_rsd = new ResourceSetDescription(_fontRsrcLayout, _controller._fontTextureView);
            _crs_font = _factory.CreateResourceSet(crs_font_rsd);

            ShaderSetDescription fontshader = SPIRVShaders.CreateFontShaders(_factory, out _FontVertBuffer, out _FontIndexBuffer);

            GraphicsPipelineDescription fontpd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                DepthStencilStateDescription.DepthOnlyLessEqual,
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, true, true),
                PrimitiveTopology.TriangleList, fontshader,
                new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer.OutputDescription);
            _fontPipeline = _factory.CreateGraphicsPipeline(fontpd);
        }


        void RecreateOutputTextures()
        {
            _outputTexture?.Dispose();
            _outputTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
                PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _outputFramebuffer?.Dispose();
            _outputFramebuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));

            _testPickingTexture?.Dispose();
            _testPickingTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _pickingFrameBuffer?.Dispose();
            _pickingFrameBuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));

            _pickingStagingTexture?.Dispose();
            _pickingStagingTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.Staging));
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
        //Sets rendering mode to the specified mode
        //If already using that mode, returns the mode to standard
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

        void SetRenderingMode(eRenderingMode newMode)
        {
            switch (newMode)
            {
                case eRenderingMode.eStandardControlFlow:
                    break;
                case eRenderingMode.eConditionals:
                    break;
                case eRenderingMode.eHeatmap:
                    ActiveGraph.InternalProtoGraph.HeatSolvingComplete = false; //todo - temporary for dev
                    break;
                default:
                    Console.WriteLine("unknown rendering mode");
                    break;
            }
            _renderingMode = newMode;
        }


        static void RenderString(string inputString, uint nodeIdx, float fontScale, ImFontPtr font, ref List<fontStruc> stringVerts, Color colour, float yOff = 0)
        {

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

                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0), yOffset = yOff, fontColour = fcolour });
                xPos += charWidth;
            }
        }


        GraphShaderParams updateShaderParams(uint textureSize, Matrix4x4 projection, Matrix4x4 view, Matrix4x4 world)
        {
            GraphShaderParams shaderParams = new GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = _mouseoverNodeID,
                isAnimated = ActiveGraph.IsAnimated
            };

            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(new Vector3(ActiveGraph.CameraXOffset, ActiveGraph.CameraYOffset, ActiveGraph.CameraZoom));

            shaderParams.proj = projection;
            shaderParams.view = view;
            shaderParams.world = world;
            shaderParams.nonRotatedView = Matrix4x4.Multiply(Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0), cameraTranslation);

            _gd.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _gd.WaitForIdle();

            return shaderParams;
        }


        class RISINGEXTTXT
        {
            public int nodeIdx;
            public float currentY;
            public string text;
            public int remainingFrames;
        }

        List<RISINGEXTTXT> _activeRisings = new List<RISINGEXTTXT>();

        void uploadFontVerts(List<fontStruc> stringVerts)
        {
            ushort[] charIndexes = Enumerable.Range(0, stringVerts.Count).Select(i => (ushort)i).ToArray();

            if (stringVerts.Count * fontStruc.SizeInBytes > _FontVertBuffer.SizeInBytes)
            {
                _FontVertBuffer.Dispose();
                BufferDescription tfontvDescription = new BufferDescription((uint)stringVerts.Count * fontStruc.SizeInBytes, BufferUsage.VertexBuffer);
                _FontVertBuffer = _factory.CreateBuffer(tfontvDescription);

                _FontIndexBuffer.Dispose();
                BufferDescription tfontIdxDescription = new BufferDescription((uint)charIndexes.Length * sizeof(ushort), BufferUsage.IndexBuffer);
                _FontIndexBuffer = _factory.CreateBuffer(tfontIdxDescription);
            }
            _gd.UpdateBuffer(_FontVertBuffer, 0, stringVerts.ToArray());
            _gd.UpdateBuffer(_FontIndexBuffer, 0, charIndexes);
            _gd.WaitForIdle();
        }

        List<fontStruc> RenderHighlightedNodeText(List<Tuple<string, Color>> captions, int nodeIdx = -1)
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

            ActiveGraph.GetActiveExternRisings(out List<Tuple<uint, string>> newRisingExterns,
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
            for (int idx = 0; idx < _activeRisings.Count; idx++)
            {
                var ar = _activeRisings[idx];
                if (ar.remainingFrames != -1)
                {
                    ar.currentY += GlobalConfig.ExternAnimRisePerFrame;
                    ar.remainingFrames -= 1;
                }
                //Console.WriteLine($"Drawing '{ar.text}' at y {ar.currentY}");
                RenderString(ar.text, (uint)ar.nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, Color.SpringGreen, yOff: ar.currentY);
            }
        }

        float _fontScale = 13.0f;

        List<fontStruc> renderGraphText(List<Tuple<string, Color>> captions)
        {
            List<fontStruc> stringVerts = new List<fontStruc>();
            if (!ActiveGraph.TextEnabled) return stringVerts;
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


        public void renderGraph(DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
        {



            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, nodeAttributesBuffer, _imageTextureView);

            _crs_nodesEdges?.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);

            //rotval += 0.01f; //autorotate
            var textureSize = ActiveGraph.LinearIndexTextureSize();

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            updateShaderParams(textureSize, proj, view, world);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, positionsBuffer);
            _crs_core?.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            Position2DColour[] NodeVerts = ActiveGraph.GetMaingraphNodeVerts(_renderingMode,
            out List<uint> nodeIndices, out Position2DColour[] nodePickingColors, out List<Tuple<string, Color>> captions);

            //_layoutEngine.GetScreenFitOffsets(_graphWidgetSize, out _furthestX, out _furthestY, out _furthestZ);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * Position2DColour.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer);
                _NodeVertexBuffer.Dispose();
                _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);
                _NodePickingBuffer.Dispose();
                _NodePickingBuffer = _factory.CreateBuffer(vbDescription);

                BufferDescription ibDescription = new BufferDescription((uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _NodeIndexBuffer.Dispose();
                _NodeIndexBuffer = _factory.CreateBuffer(ibDescription);
            }

            //todo - only do this on changes
            _gd.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            _gd.UpdateBuffer(_NodePickingBuffer, 0, nodePickingColors);
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());

            Position2DColour[] EdgeLineVerts = ActiveGraph.GetEdgeLineVerts(_renderingMode, out List<uint> edgeDrawIndexes, out int edgeVertCount, out int drawnEdgeCount);

            if (drawnEdgeCount == 0) return;
            if (((edgeVertCount * 4) > _EdgeIndexBuffer.SizeInBytes))
            {
                _EdgeVertBuffer.Dispose();
                BufferDescription tvbDescription = new BufferDescription((uint)EdgeLineVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer);
                _EdgeVertBuffer = _factory.CreateBuffer(tvbDescription);

                _EdgeIndexBuffer.Dispose();
                BufferDescription eibDescription = new BufferDescription((uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _EdgeIndexBuffer = _factory.CreateBuffer(eibDescription);
            }

            //todo - only do this on changes
            _gd.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());
            _gd.WaitForIdle();



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

            //draw nodes and edges
            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, GlobalConfig.mainColours.background.ToRgbaFloat());

            if (ActiveGraph.NodesVisible)
            {
                _cl.SetPipeline(_pointsPipeline);
                _cl.SetGraphicsResourceSet(0, _crs_core);
                _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
                _cl.SetVertexBuffer(0, _NodeVertexBuffer);
                _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
                _cl.DrawIndexed(indexCount: (uint)nodesToDraw, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            }

            if (ActiveGraph.EdgesVisible)
            {
                _cl.SetPipeline(_edgesPipelineRelative);
                _cl.SetGraphicsResourceSet(0, _crs_core);
                _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
                _cl.SetVertexBuffer(0, _EdgeVertBuffer);
                _cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
                _cl.DrawIndexed(indexCount: (uint)edgeVertCount, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            }

            GeomPositionColour[] IllustrationEdges = ActiveGraph.GetIllustrationEdges(out List<uint> illusEdgeDrawIndexes);

            if (IllustrationEdges.Length > 0)
            {

                if (_RawEdgeIndexBuffer == null || ((IllustrationEdges.Length * GeomPositionColour.SizeInBytes) > _RawEdgeIndexBuffer.SizeInBytes))
                {
                    _RawEdgeVertBuffer?.Dispose();
                    BufferDescription tvbDescription = new BufferDescription((uint)IllustrationEdges.Length * GeomPositionColour.SizeInBytes * 4, BufferUsage.VertexBuffer);
                    _RawEdgeVertBuffer = _factory.CreateBuffer(tvbDescription);

                    _RawEdgeIndexBuffer?.Dispose();
                    BufferDescription eibDescription = new BufferDescription((uint)illusEdgeDrawIndexes.Count * sizeof(uint) * 4, BufferUsage.IndexBuffer);
                    _RawEdgeIndexBuffer = _factory.CreateBuffer(eibDescription);
                }

                //todo - only do this on changes
                _gd.UpdateBuffer(_RawEdgeVertBuffer, 0, IllustrationEdges);
                _gd.UpdateBuffer(_RawEdgeIndexBuffer, 0, illusEdgeDrawIndexes.ToArray());

                _cl.SetPipeline(_edgesPipelineRaw);
                _cl.SetGraphicsResourceSet(0, _crs_core);
                _cl.SetVertexBuffer(0, _RawEdgeVertBuffer);
                _cl.SetIndexBuffer(_RawEdgeIndexBuffer, IndexFormat.UInt32);
                _cl.DrawIndexed(indexCount: (uint)illusEdgeDrawIndexes.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }


            //draw text
            if (ActiveGraph.TextEnabled)
            {
                _cl.SetViewport(0, new Viewport(0, 0, _graphWidgetSize.X, _graphWidgetSize.Y, -2200, 1000));

                _cl.SetPipeline(_fontPipeline);
                _cl.SetVertexBuffer(0, _FontVertBuffer);
                _cl.SetIndexBuffer(_FontIndexBuffer, IndexFormat.UInt16);
                _cl.SetGraphicsResourceSet(0, _crs_core);
                _cl.SetGraphicsResourceSet(1, _crs_font);
                _cl.DrawIndexed(indexCount: (uint)stringVerts.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            }


            //update the picking framebuffer
            _cl.SetPipeline(_pickingPipeline);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.SetVertexBuffer(0, _NodePickingBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.SetFramebuffer(_pickingFrameBuffer);

            _cl.ClearColorTarget(0, new RgbaFloat(0f, 0f, 0f, 0f));
            _cl.SetViewport(0, new Viewport(0, 0, _graphWidgetSize.X, _graphWidgetSize.Y, -2200, 1000));
            _cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            _cl.CopyTexture(_testPickingTexture, _pickingStagingTexture);

            _cl.End();
            _gd.SubmitCommands(_cl);
            _gd.WaitForIdle();


            //now draw the output to the screen
            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, _outputTexture);
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: pos,
                p_max: new Vector2(pos.X + _outputTexture.Width, pos.Y + _outputTexture.Height),
                uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));
            _isInputTarget = ImGui.IsItemActive();
            _cl.Dispose();
        }

        unsafe Vector4 GetTextColour() => *ImGui.GetStyleColorVec4(ImGuiCol.Text);

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

        public void DisplayEventMessages(Vector2 pos)
        {
            if (ActiveGraph == null) return;

            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            float depth = 20;//todo based on count 
            float maxWidth = 200;

            TraceRecord trace = ActiveGraph.InternalProtoGraph.TraceData;

            Logging.TIMELINE_EVENT[] evts = trace.GetTimeLineEntries(oldest: timenow - GlobalConfig.VisMessageMaxLingerTime);

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

                Color textCol;
                string msg;
                switch (evt.TimelineEventType)
                {
                    case Logging.eTimelineEvent.ProcessStart:
                        textCol = Color.LightGreen;
                        msg = $"Process {evt.ID} started";
                        break;
                    case Logging.eTimelineEvent.ProcessEnd:
                        textCol = Color.OrangeRed;
                        msg = $"Process {evt.ID} ended";
                        break;
                    case Logging.eTimelineEvent.ThreadStart:
                        textCol = Color.LightGreen;
                        msg = $"Thread {evt.ID} started";
                        break;
                    case Logging.eTimelineEvent.ThreadEnd:
                        textCol = Color.OrangeRed;
                        msg = $"Thread {evt.ID} ended";
                        break;
                    default:
                        textCol = Color.Gray;
                        msg = "Unknown Timeline event" + evt.TimelineEventType.ToString();
                        break;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(textCol).ToUint((uint)alpha));
                ImGui.TextWrapped(msg);
                ImGui.PopStyleColor();
            }
        }


        void drawHUD(Vector2 widgetSize)
        {
            string msg;
            Vector2 topLeft = ImGui.GetCursorScreenPos();
            Vector2 bottomLeft = new Vector2(topLeft.X, topLeft.Y + widgetSize.Y);
            Vector2 bottomRight = new Vector2(bottomLeft.X + widgetSize.X, bottomLeft.Y);

            PlottedGraph activeGraph = ActiveGraph;

            if (activeGraph != null)
                DrawLayoutSelector(bottomRight, 0.25f);

            if (activeGraph == null)
            {
                msg = "No active graph to display";
                Vector2 screenMiddle = new Vector2(bottomLeft.X + ((widgetSize.X / 2) - (ImGui.CalcTextSize(msg).X / 2)), bottomLeft.Y - (widgetSize.Y / 2));
                ImGui.SetCursorScreenPos(screenMiddle);
                ImGui.Text(msg);
                return;
            }

            if (GlobalConfig.ShowKeystrokes) DrawKeystrokes(topLeft);

            _QuickMenu.Draw(bottomLeft, 0.25f, activeGraph);


            Vector2 midRight = new Vector2(bottomLeft.X + widgetSize.X, bottomLeft.Y - widgetSize.Y / 2);
            //DrawDisasmPreview(activeGraph, midRight);
        }


        /*
        //drawing on graph, doesn't fit great
        void DrawDisasmPreview(PlottedGraph activeGraph, Vector2 midPosition)
        {
            Vector2 startPos = ImGui.GetCursorScreenPos();
            for (var i = 0; i < 5; i++)
            {
                ImGui.SetCursorScreenPos(midPosition - new Vector2(100, i * 15));
                ImGui.Text($"Ins {i}");
            }
            ImGui.SetCursorScreenPos(startPos);
        }
        */


        bool _showLayoutSelectorPopup;
        bool _showQuickMenu;
        IntPtr getLayoutIcon(eGraphLayout layout)
        {
            Texture iconTex = null;
            switch (layout)
            {
                case eGraphLayout.eForceDirected3DNodes:
                case eGraphLayout.eForceDirected3DBlocks:
                    iconTex = _controller.GetImage("Force3D");
                    break;
                case eGraphLayout.eCircle:
                    iconTex = _controller.GetImage("Circle");
                    break;
                case eGraphLayout.eCylinderLayout:
                    iconTex = _controller.GetImage("Cylinder");
                    break;
                default:
                    Console.WriteLine($"ERROR: no icond for layout {layout}");
                    iconTex = _controller.GetImage("Force3D");
                    break;
            }

            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, iconTex);
            return CPUframeBufferTextureId;
        }




        void DrawLayoutSelector(Vector2 position, float scale)
        {
            Vector2 iconSize = new Vector2(128 * scale, 128 * scale);
            float padding = 6f;
            Vector2 pmin = new Vector2((position.X - iconSize.X) - padding, ((position.Y - iconSize.Y) - 4) - padding);


            ImGui.SetCursorScreenPos(pmin);

            ImGui.PushStyleColor(ImGuiCol.Button, 0x11000000);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0x11000000);
            ImGui.ImageButton(getLayoutIcon(ActiveGraph.LayoutStyle), iconSize);
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

            bool snappingToPreset = _layoutEngine.ActivatingPreset;
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
            float buttonWidth = 150f;

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(eGraphLayout.eForceDirected3DNodes),
                iconSize, buttonWidth, "Force Directed Nodes", ActiveGraph.LayoutStyle == eGraphLayout.eForceDirected3DNodes))
            {
                if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eForceDirected3DNodes)) { _layoutEngine.ChangePreset(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(eGraphLayout.eForceDirected3DBlocks),
                iconSize, buttonWidth, "Force Directed Blocks", ActiveGraph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks))
            {
                if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eForceDirected3DBlocks)) { _layoutEngine.ChangePreset(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(eGraphLayout.eCylinderLayout),
                iconSize, buttonWidth, "Cylinder", ActiveGraph.LayoutStyle == eGraphLayout.eCylinderLayout))
            {
                if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eCylinderLayout)) { _layoutEngine.ChangePreset(); }
            }

            if (SmallWidgets.ImageCaptionButton(getLayoutIcon(eGraphLayout.eCircle),
                iconSize, buttonWidth, "Circle", ActiveGraph.LayoutStyle == eGraphLayout.eCircle))
            {
                if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eCircle)) { _layoutEngine.ChangePreset(); }
            }
        }




        void HandleGraphUpdates()
        {
            Vector2 currentRegionSize = ImGui.GetContentRegionAvail();
            if (currentRegionSize != _graphWidgetSize)
            {
                _graphWidgetSize = currentRegionSize;
                RecreateOutputTextures();
            }

            bool newAttribs = false;
            if (processingAnimatedGraph && !ActiveGraph.IsAnimated)
            {
                newAttribs = true;
                processingAnimatedGraph = false;
            }
            else if (!processingAnimatedGraph && ActiveGraph.IsAnimated)
            {
                processingAnimatedGraph = true;
            }
            if (ActiveGraph.HighlightsChanged)
            {
                newAttribs = true;
            }

            if (newAttribs)
            {
                _layoutEngine.ResetNodeAttributes(ActiveGraph);
                ActiveGraph.HighlightsChanged = false;
            }
        }

        public unsafe void DrawGraph()
        {

            HandleGraphUpdates();

            _layoutEngine.Compute((uint)ActiveGraph.DrawnEdgesCount, _mouseoverNodeID, ActiveGraph.IsAnimated);

            doPicking(_gd);

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            Matrix4x4 worldView = world * view;
            if (_centeringInFrame != 0)
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


            bool doDispose = FetchNodeBuffers(ActiveGraph, out DeviceBuffer positionBuf, out DeviceBuffer attribBuf);
            renderGraph(positionBuf, nodeAttributesBuffer: attribBuf);
            if (doDispose)
            {
                positionBuf?.Dispose();
                attribBuf?.Dispose();
            }

            ActiveGraph.UpdatePreviewVisibleRegion(_graphWidgetSize);
        }


        /*
         * Fetched pre-prepared device buffer from layout engine if it is in the working set
         * Otherwise creates a new one from the stored data in the plottedgraph
         * 
         * Returns True if the devicebuffer can be destroyed, or False if the Layoutengine is using it
         */
        public bool FetchNodeBuffers(PlottedGraph graph, out DeviceBuffer posBuffer, out DeviceBuffer attribBuffer)
        {
            if (_layoutEngine.GetPositionsBuffer(graph, out posBuffer) && _layoutEngine.GetNodeAttribsBuffer(graph, out attribBuffer))
            {
                return false;
            }
            else
            {
                posBuffer = CreateFloatsDeviceBuffer(graph.GetPositionFloats(), _gd);
                attribBuffer = CreateFloatsDeviceBuffer(graph.GetNodeAttribFloats(), _gd);
                return true;
            }
        }


        int _mouseoverNodeID = -1;
        //Check if the mouse position corresponds to a node ID in the picking texture
        //If so - the mouse is over that nod
        void doPicking(GraphicsDevice _gd)
        {
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();
            Vector2 mpos = ImGui.GetMousePos();
            float mouseX = (mpos.X - WidgetPos.X);
            float mouseY = (WidgetPos.Y + _pickingStagingTexture.Height) - mpos.Y;

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
                        if (f.R != _mouseoverNodeID) //mouse is over a different node
                        {
                            Console.WriteLine($"Mouse: {mouseX},{mouseY} on node {f.R},{f.G},{f.B}");
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


        private void PerformIrregularActions()
        {
            if (ActiveGraph == null)
                return;

            //store latest positions for the preview graphs

            _layoutEngine.LayoutPreviewGraphs(IgnoreGraph: ActiveGraph);

            _layoutEngine.SaveComputeBuffers();

            //highlight new nodes with highlighted address
            ActiveGraph.DoHighlightAddresses();
        }



    }
}
