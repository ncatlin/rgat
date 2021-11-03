using ImGuiNET;
using Newtonsoft.Json;
using rgat.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.VeldridGraphBuffers;

namespace rgat
{
    class SplashScreenRenderer
    {
        private GraphicsDevice? _gd;
        private ResourceFactory? _factory;
        public Vector2 WidgetSize { get; private set; }

        private readonly ImGuiController _controller;
        private readonly GraphLayoutEngine _layoutEngine;
        private TextureView? _imageTextureView;
        private Framebuffer? _outputFramebuffer1, _outputFramebuffer2;
        private Texture? _outputTexture1, _outputTexture2;
        private int latestWrittenTexture = 1;
        private DeviceBuffer? _EdgeVertBuffer, _NodeVertexBuffer, _paramsBuffer;
        private Pipeline? _edgesPipelineRelative, _pointsPipeline;
        private ResourceLayout? _coreRsrcLayout, _nodesEdgesRsrclayout;
        private TraceRecord animTrace;
        private PlottedGraph? tortoise;

        CommandList? _cl;
        float _baseRoll = 0.39209974f;
        float _wiggleRoll = 0;

        bool _isWalking = false;
        Vector2 CenterPosition => _tortoisePosition + new Vector2(_outputTexture1!.Width / 2, _outputTexture1.Height / 2);
        Random _rnd = new Random();

        Vector2 _tortoisePosition = Vector2.Zero;
        Vector2 _targetDestination = Vector2.Zero;
        bool _explore = false;
        int legforward = 0;
        float speed = 1;
        DateTime _lastTreatTime = DateTime.MinValue;
        List<Vector2> treats = new();


        /// <summary>
        /// Create a tortoise renderer
        /// </summary>
        /// <param name="gdev">Veldrid Graphics device</param>
        /// <param name="controller">ImGuiController</param>
        public SplashScreenRenderer(GraphicsDevice gdev, ImGuiController controller)
        {
            _layoutEngine = new GraphLayoutEngine("SplashRenderer");
            _layoutEngine.Init(gdev);
            _gd = gdev;
            _controller = controller;
            _factory = gdev.ResourceFactory;
            WidgetSize = new Vector2(250, 250);
            SetupRenderingResources();

            animTrace = new TraceRecord(0, 0, null, DateTime.MinValue);
            if (!GetModelData(out tortoise, out float[]? presetPositions) || tortoise is null || presetPositions is null)
            {
                return;
            }

            tortoise.RenderGraph();
            _layoutEngine.Compute(_cl!, tortoise, -1, false);

            tortoise.CameraState.MainCameraXOffset = 0;
            tortoise.CameraState.MainCameraYOffset = 0;
            tortoise.LayoutState.InitialisePresetBuffer(presetPositions);
            tortoise.LayoutState.ActivateRawPreset();
            tortoise.CameraState.MainCameraZoom -= 4000;
            _baseRoll = 0.39209974f;
            _rollDelta = _baseRoll;
            _pitchDelta = -1f;
            _tortoisePosition = new Vector2(_rnd.Next(0, _controller.WindowWidth), _rnd.Next(0, controller.WindowHeight));

        }

        bool GetModelData(out PlottedGraph? graph, out float[]? positions)
        {
            Debug.Assert(_gd is not null);

            graph = null;
            positions = null;

            string companionTrace = global::rgat.Properties.Resources.CompanionTrace;
            using var sr = new StringReader(companionTrace);
            using (JsonTextReader jsnReader = new JsonTextReader(sr) { SupportMultipleContent = true })
            {
                jsnReader.Read();
                jsnReader.Read();
                JsonSerializer serializer = new JsonSerializer();
                Newtonsoft.Json.Linq.JToken? mdTok = serializer.Deserialize<Newtonsoft.Json.Linq.JObject>(jsnReader);
                if (!animTrace.Load(jsnReader, serializer,
                    new Newtonsoft.Json.Linq.JObject(), new rgatState.SERIALISE_PROGRESS("Splash"), _gd))
                {
                    Logging.RecordError("Splash animation data not loaded");
                }
                graph = animTrace.GetFirstGraph();
                if (graph is null)
                {
                    Logging.RecordLogEvent("Failed to init companion graph");
                    return false;
                }

                double[,] tortoiseVertPositions = new double[,] {
                           {0.684366, -0.375652, -0.104415}, {0.539007, -0.403717, -0.154739}, {0.621004, -0.297949, 0.0154483}, {0.457796, -0.26336, 0.0361917}, {0.397283, -0.341337, -0.0894762}, {0.337585, -0.132361, 0.128244},
                           {0.20818, -0.299482, -0.140751}, {0.053128, -0.19975, -0.0355903}, {0.127465, -0.103752, 0.118539}, {-0.155024, -0.150253, -0.0815675}, {-0.0119269, 0.0347639, 0.214581}, {-0.297253, -0.0252586, 0.0302964},
                           {-0.22639, 0.0662863, 0.176859}, {-0.489235, 0.0338762, -0.0235115}, {-0.353252, 0.209655, 0.257919},{-0.593099, 0.157446, 0.0663563}, {-0.526765, 0.243093, 0.203655}, {-0.715248, 0.223708, -0.00565106},
                           {-0.595535, 0.378247, 0.242227}, {-0.718204, 0.350796, 0.117492}, {0.491146, -0.427925, -0.284362},{0.337369, -0.397122, -0.329493}, {0.163373, -0.347411, -0.305398}, {-0.0314343, -0.290724, -0.323302},
                           {-0.205549, -0.193278, -0.262441}, {-0.397323, -0.107901, -0.263651}, {-0.549204, 0.0052625, -0.187487},{-0.687142, 0.113344, -0.137035}, {0.673142, -0.193124, 0.0926921}, {0.57868, -0.0854615, 0.170634},
                           {0.4217, -0.0136907, 0.229833}, {0.272458, 0.102075, 0.30567}, {0.0759037, 0.170482, 0.319601},{-0.0918041, 0.286956, 0.368054}, {-0.287544, 0.343292, 0.353669}, {-0.456188, 0.411606, 0.341002},
                           {-0.46013, 0.502577, 0.393216}, {-0.272414, 0.451425, 0.419832}, {-0.0681851, 0.359512, 0.405119},{0.125586, 0.254147, 0.368065}, {0.321761, 0.158736, 0.336734}, {0.496912, 0.0465882, 0.267567},
                           {0.663202, -0.0660958, 0.177706}, {0.772724, -0.196939, 0.0692139}, {0.797803, -0.340683, -0.0860485},{0.741301, -0.413753, -0.202982}, {0.577701, -0.448789, -0.334869}, {0.386394, -0.423757, -0.396148},
                           {0.172157, -0.37316, -0.405094}, {-0.0359254, -0.303652, -0.403344}, {-0.230238, -0.205719, -0.367478},{-0.429759, -0.107622, -0.341944}, {-0.618306, 0.00480576, -0.29464}, {-0.755068, 0.121913, -0.216443},
                           {-0.791358, 0.252152, -0.0742342}, {-0.745937, 0.436714, 0.154638}, {-0.61939, 0.474097, 0.281581},{0.619704, -0.544042, -0.45516}, {0.579387, -0.586933, -0.54035}, {0.480811, -0.526273, -0.501492},
                           {-0.773893, 0.00129586, -0.376071}, {-0.891296, 0.0297995, -0.398586}, {-0.87362, 0.088269, -0.317176},{-0.471192, 0.606961, 0.513164}, {-0.41296, 0.646577, 0.587069}, {-0.332487, 0.570682, 0.533828},
                           {0.831175, -0.0734514, 0.225904}, {0.947248, -0.111378, 0.223827}, {0.909508, -0.169176, 0.146397}, {-0.853251, 0.454437, 0.117572}, {0.940169, -0.417626, -0.127571}, {0.89586, -0.47516, -0.218708},
                           {0.965, -0.464799, -0.178821}, {-0.792022, 0.377159, 0.0591504}, {-0.721907, 0.278052, -0.0603824}, {-0.587892, 0.451017, 0.217133}, {-0.678141, 0.390694, 0.0732359}, {-0.43109, 0.459357, 0.304882},
                           {-0.665558, 0.156632, -0.180404}, {-0.245038, 0.392694, 0.299922}, {-0.0569399, 0.332157, 0.324757}, {0.116854, 0.227589, 0.269412}, {0.298236, 0.157848, 0.274553}, {0.443164, 0.0550586, 0.214382},
                           {0.522577, -0.0615843, 0.0930758}, {0.666919, -0.190098, 0.0108917}, {0.685425, -0.322607, -0.138079}, {0.534267, -0.361229, -0.263866}, {0.334584, -0.304395, -0.296613}, {0.162223, -0.307912, -0.367443},
                           {-0.0153968, -0.247519, -0.374458}, {-0.16786, -0.140331, -0.319249}, {-0.363632, -0.0641466, -0.309326}, {-0.505365, 0.0564594, -0.238487}, {-0.04201, -0.0469528, -0.210643}, {0.0758362, 0.0313912, -0.0661637},
                           {0.107026, 0.145696, 0.0974845}, {0.30235, -0.0427412, -0.0209518}, {0.238263, -0.125437, -0.154059}, {-0.213565, 0.306647, 0.130161}, {-0.186664, 0.177031, -0.030708}, {-0.349792, 0.130655, -0.151891},
                           {-0.355244, 0.298206, -0.0250737}, {-0.524182, 0.374988, 0.00859916}, {-0.243625, 0.118804, 0.0332106}, {-0.274597, 0.0399616, 0.097577}, {0.354125, -0.0793953, 0.0586848}, {0.242005, -0.224462, -0.17633}};

                int nodeCount = tortoiseVertPositions.Length / 3;
                float[] presetPositions = new float[4 * nodeCount];
                int size = 4000;
                for (var i = 0; i < nodeCount; i++)
                {
                    presetPositions[i * 4] = (float)tortoiseVertPositions[i, 0] * size;
                    presetPositions[i * 4 + 1] = (float)tortoiseVertPositions[i, 1] * size;
                    presetPositions[i * 4 + 2] = (float)tortoiseVertPositions[i, 2] * size;
                    presetPositions[i * 4 + 3] = 1;
                }
                positions = presetPositions;
                return true;
            }

        }


        /// <summary>
        /// Initialise graphics resources
        /// </summary>
        private unsafe void SetupRenderingResources()
        {
            Debug.Assert(_gd is not null, "Init not called");
            ResourceFactory factory = _gd.ResourceFactory;
            _cl = factory.CreateCommandList();
            _paramsBuffer = TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<GraphPlotWidget.GraphShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "GraphPlotparamsBuffer");

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
                ShaderSet = SPIRVShaders.CreateNodeShaders(_gd, out _NodeVertexBuffer)
            };

            Debug.Assert(_outputTexture1 is null && _outputFramebuffer1 is null);
            Debug.Assert(_outputTexture2 is null && _outputFramebuffer2 is null);

            RecreateOutputTextures();

            Debug.Assert(_outputTexture1 is not null && _outputFramebuffer1 is not null);
            Debug.Assert(_outputTexture2 is not null && _outputFramebuffer2 is not null);

            pipelineDescription.Outputs = _outputFramebuffer1.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gd, out _EdgeVertBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRelative = factory.CreateGraphicsPipeline(pipelineDescription);

            _imageTextureView = _controller.IconTexturesView;
        }


        /// <summary>
        /// Re-initialise graphics resources, for use when the size of the widget has changed
        /// </summary>
        private void RecreateOutputTextures()
        {
            VeldridGraphBuffers.DoDispose(_outputTexture1);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer1);
            VeldridGraphBuffers.DoDispose(_outputTexture2);
            VeldridGraphBuffers.DoDispose(_outputFramebuffer2);

            _outputTexture1 = _factory!.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture1.Name = "SplashOutputTexture1" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer1 = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture1));
            _outputFramebuffer1.Name = $"sOPFB1_" + _outputTexture1.Name;

            _outputTexture2 = _factory.CreateTexture(TextureDescription.Texture2D((uint)WidgetSize.X, (uint)WidgetSize.Y, 1, 1,
                Veldrid.PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputTexture2.Name = "SplashOutputTexture2" + DateTime.Now.ToFileTime().ToString();
            _outputFramebuffer2 = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture2));
            _outputFramebuffer2.Name = $"sOPFB2_" + _outputTexture2.Name;
        }


        public void Draw()
        {
            if (tortoise is not null)
            {
                Debug.Assert(_cl is not null);
                tortoise.RenderGraph();
                bool recentTreat = (DateTime.Now - _lastTreatTime).Seconds < 15;

                if (recentTreat is false &&     //follow the mouse if we are hungry
                    treats.Any() is false &&    // and there is nothing to eat
                    _controller.MousePresent && // and the mouse is in the window 
                    _controller.LastMouseActivityMS < 14000) // and it has moved recently
                {
                    _targetDestination = ImGui.GetIO().MousePos;
                    _explore = false;
                }
                else
                {
                    if (_explore is false) _targetDestination = RandomPosition;
                    _explore = true;
                }

                MoveTortoise();
                OrientTortoise();
                AnimateWalking();

                //not particularly thread safe, but this isn't meant to be running when anything else is
                float previousDivisor = GlobalConfig.PresetSpeedDivisor;
                GlobalConfig.PresetSpeedDivisor = 10f / speed;
                _layoutEngine.Compute(_cl, tortoise, mouseoverNodeID: -1, isAnimated: false);
                GlobalConfig.PresetSpeedDivisor = previousDivisor;

                if (tortoise.Temperature < 10)
                    tortoise.IncreaseTemperature();

                ImGuiIOPtr IO = ImGui.GetIO();
                if (IO.MouseClicked.Count > 0 &&
                   IO.MouseClicked[0])
                {
                    if (recentTreat is false || IO.KeyShift)
                    {
                        treats.Add(IO.MouseClickedPos[0]);
                        _lastTreatTime = DateTime.Now;
                    }
                }

                DrawGraph(_cl, tortoise);
                GetLatestTexture(out Texture outputTexture);
                ImDrawListPtr imdp = ImGui.GetWindowDrawList();

                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_factory!, outputTexture, "SplashTex" + outputTexture.Name);

                foreach (var pos in treats)
                {
                    imdp.AddText(pos, 0xff257c24, $"{ImGuiController.FA_ICON_PLANT}");
                    imdp.AddText(pos + new Vector2(2, 12), 0xff0000ff, $"{ImGuiController.FA_ICON_EGG}"); //don't have the effort reserves to find a way to flip this to look like a strawberry
                }

                //draw our tortoise
                imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: _tortoisePosition,
                    p_max: _tortoisePosition + new Vector2(outputTexture.Width, outputTexture.Height),
                    uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));


            }

        }

        void OrientTortoise()
        {
            Vector2 tortoiseCenter = CenterPosition;
            double angle = Math.Atan2(0, -1f * tortoiseCenter.X) - Math.Atan2(tortoiseCenter.Y - _targetDestination.Y, tortoiseCenter.X - _targetDestination.X);// - Math.Atan2(mpos.Y, mpos.X);
            angle -= _rollTotal;
            angle += _baseRoll - _wiggleRoll;
            if (angle != 0)
            {
                if (angle > 0)
                {
                    if (angle > 6.2)
                        _rollDelta += 6.2f;
                    else
                        _rollDelta += Math.Min(treats.Any() ? 0.1f : 0.05f, (float)angle);
                }
                else
                {
                    if (angle < -6.2)
                        _rollDelta += -6.2f;
                    else
                        _rollDelta += Math.Max(treats.Any() ? -0.1f : -0.05f, (float)angle);
                }
            }
        }


        void AnimateWalking()
        {
            if (_isWalking is false)
            {
                _rollDelta -= _wiggleRoll;
                _wiggleRoll = 0;
            }
            else
            {
                if (legforward == 1)
                {
                    _wiggleRoll += 0.005f;
                    _rollDelta += 0.005f;
                }
                else if (legforward == -1)
                {
                    _wiggleRoll -= 0.005f;
                    _rollDelta -= 0.005f;
                }
                if (Math.Abs(_wiggleRoll) > 0.14)
                {
                    _rollDelta -= (_wiggleRoll / 5);
                    _wiggleRoll -= (_wiggleRoll / 5);
                }
            }

            if (tortoise!.LayoutState.ActivatingPreset is false && _isWalking)
            {
                float[] positions = tortoise.LayoutState.DownloadVRAMPositions();
                Random rnd = new Random();

                int frontL1 = 57 * 4;
                int backL1 = 60 * 4;
                int backR1 = 63 * 4;
                int frontR1 = 66 * 4;
                float[] offsets = { 400, -750, 50 };
                float moveMult = 0;

                if (legforward == 0) //move from the neutral position
                {
                    moveMult = -0.75f;
                    legforward = 1;
                }
                else if (legforward == -1)
                {
                    moveMult = -1.5f;
                    legforward = 1;
                }
                else if (legforward == 1)
                {
                    moveMult = 1.5f;
                    legforward = -1;
                }
                for (int footi = 0; footi < 12; footi += 4) //three points on each foot
                {
                    for (int coordi = 0; coordi < 3; coordi++) //xyz
                    {
                        float moveDist = moveMult * offsets[coordi];
                        positions[frontR1 + footi + coordi] = positions[frontR1 + footi + coordi] - moveDist;
                        positions[backR1 + footi + coordi] = positions[backR1 + footi + coordi] - moveDist * 1.2f;
                        positions[backL1 + footi + coordi] = positions[backL1 + footi + coordi] + moveDist * 1.2f;
                        positions[frontL1 + footi + coordi] = positions[frontL1 + footi + coordi] + moveDist;
                    }
                }

                tortoise.LayoutState.InitialisePresetBuffer(positions);
                tortoise.LayoutState.ActivateRawPreset();
            }
        }

        Vector2 RandomPosition => new Vector2(_rnd.Next(0, _controller.WindowWidth), _rnd.Next(0, _controller.WindowHeight));

        void MoveTortoise()
        {
            Vector2 centerPosition = CenterPosition;
            bool chasingTreat = false;
            if (treats.Any())
            {
                chasingTreat = true;
                if (_targetDestination != treats[0])
                {
                    _targetDestination = treats[0];
                }
            }

            float distToTravel = Vector2.Distance(_targetDestination, centerPosition);

            if (distToTravel < (_outputTexture1!.Width / 2))
            {
                if (chasingTreat)
                {
                    treats.RemoveAt(0);
                }

                if (_explore)
                {
                    _targetDestination = RandomPosition;
                }
                _isWalking = false;
                return;

            }

            float maxSpeedX = 2;
            speed = 1;
            float maxSpeedY = 1.3f;
            if (chasingTreat)
            {
                maxSpeedX = 12;
                maxSpeedY = 7;
                speed = 2;
            }
            else if (_explore)
            {
                maxSpeedX = 1.5f;
                maxSpeedY = 1.0f;
            }
            _isWalking = true;

            Vector2 tortoiseVelocity = Vector2.Zero;
            tortoiseVelocity.X = (_targetDestination.X - centerPosition.X) / (chasingTreat ? 5 : 150);
            tortoiseVelocity.Y = (_targetDestination.Y - centerPosition.Y) / (chasingTreat ? 20 : 150);
            if (Math.Abs(tortoiseVelocity.X) > maxSpeedX) tortoiseVelocity.X = tortoiseVelocity.X > 0 ? maxSpeedX : -1 * maxSpeedX;
            if (Math.Abs(tortoiseVelocity.Y) > maxSpeedY) tortoiseVelocity.Y = tortoiseVelocity.Y > 0 ? maxSpeedY : -1 * maxSpeedY;
            _tortoisePosition += tortoiseVelocity;
        }


        private float _pitchTotal, _yawTotal, _rollTotal = 0;
        private float _pitchDelta, _yawDelta, _rollDelta = 0;

        /// <summary>
        /// Must hold read lock
        /// </summary>
        /// <param name="proj"></param>
        /// <param name="view"></param>
        /// <param name="world"></param>
        private void UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world)
        {
            PlottedGraph? graph = tortoise;
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
            _pitchTotal += _pitchDelta;
            _yawTotal += _yawDelta;
            _rollTotal += _rollDelta;
            _pitchDelta = 0; _yawDelta = 0f; _rollDelta = 0;

            Matrix4x4 offsetRotation = pitch * yaw * roll;

            world = graph.CameraState.RotationMatrix * offsetRotation;

            view = graph.CameraState.MainCameraTranslation;
            graph.CameraState.RotationMatrix = world;
        }


        /// <summary>
        /// Draws the various nodes, edges, captions and illustrations to the framebuffer for display
        /// </summary>
        /// <param name="cl">A veldrid commandlist, for use by this thread only</param>
        /// <param name="plot">The PlottedGraph to draw</param>
        public unsafe void DrawGraph(CommandList cl, PlottedGraph plot)
        {
            Debug.Assert(_gd is not null);

            Position1DColourMultiVert[] EdgeLineVerts = plot.GetEdgeLineVerts(eRenderingMode.eStandardControlFlow, out int edgeVertCount);
            if (plot.LayoutState.Initialised is false || edgeVertCount == 0 || rgatState.rgatIsExiting)
            {
                return;
            }

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("Splash Draw start", filter: Logging.LogFilterType.BulkDebugLogFile);

            cl.Begin();

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _imageTextureView);
            ResourceSet crs_nodesEdges = _factory!.CreateResourceSet(crs_nodesEdges_rsd);

            //rotval += 0.01f; //autorotate
            var textureSize = plot.LinearIndexTextureSize();

            UpdateAndGetViewMatrix(out Matrix4x4 proj, out Matrix4x4 view, out Matrix4x4 world);
            GraphPlotWidget.UpdateShaderParams(plot, textureSize, -1, proj, view, world, cl, _paramsBuffer!);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer,
                _gd.PointSampler, plot.LayoutState.PositionsVRAM1, plot.LayoutState.AttributesVRAM1);
            ResourceSet crs_core = _factory.CreateResourceSet(crs_core_rsd);

            Position1DColour[] NodeVerts = plot.GetMaingraphNodeVerts(eRenderingMode.eStandardControlFlow, (int)textureSize, out Position1DColour[] _,
            out List<Tuple<string?, uint>> captions, out int nodeCount);

            if (_NodeVertexBuffer!.SizeInBytes < NodeVerts.Length * Position1DColour.SizeInBytes)
            {
                VRAMDispose(_NodeVertexBuffer);
                _NodeVertexBuffer = TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position1DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "NodeVertexBuffer");
            }

            //todo - only do this on changes

            fixed (Position1DColour* vertsPtr = NodeVerts)
            {
                cl.UpdateBuffer(_NodeVertexBuffer, 0, (IntPtr)vertsPtr, (uint)nodeCount * Position1DColour.SizeInBytes);
            }

            if ((EdgeLineVerts.Length * Position1DColourMultiVert.SizeInBytes) > _EdgeVertBuffer!.SizeInBytes)
            {
                VRAMDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = TrackedVRAMAlloc(_gd, (uint)EdgeLineVerts.Length * Position1DColourMultiVert.SizeInBytes, BufferUsage.VertexBuffer, name: "EdgeVertexBuffer");
            }

            ReadOnlySpan<Position1DColourMultiVert> elvSpan = new ReadOnlySpan<Position1DColourMultiVert>(EdgeLineVerts, 0, edgeVertCount);
            fixed (Position1DColourMultiVert* vertsPtr = elvSpan)
            {
                cl.UpdateBuffer(_EdgeVertBuffer, 0, (IntPtr)vertsPtr, (uint)(edgeVertCount * Position1DColourMultiVert.SizeInBytes));
            }

            Framebuffer drawtarget = latestWrittenTexture == 1 ? _outputFramebuffer2! : _outputFramebuffer1!;

            //draw nodes and edges
            cl.SetFramebuffer(drawtarget);
            cl.ClearColorTarget(0, new WritableRgbaFloat(0, 0, 0, 0).ToRgbaFloat());

            cl.SetPipeline(_edgesPipelineRelative);
            cl.SetGraphicsResourceSet(0, crs_core);
            cl.SetGraphicsResourceSet(1, crs_nodesEdges);
            cl.SetVertexBuffer(0, _EdgeVertBuffer);
            cl.Draw((uint)edgeVertCount);

            cl.SetPipeline(_pointsPipeline);
            cl.SetGraphicsResourceSet(0, crs_core);
            cl.SetGraphicsResourceSet(1, crs_nodesEdges);
            cl.SetVertexBuffer(0, _NodeVertexBuffer);
            cl.Draw((uint)nodeCount);
            cl.End();

            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            latestWrittenTexture = (latestWrittenTexture == 1) ? 2 : 1;

            crs_core.Dispose();
            crs_nodesEdges.Dispose();
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("rendergraph end", filter: Logging.LogFilterType.BulkDebugLogFile);

        }


        /// <summary>
        /// Get the most recently drawn framebuffer for displaying to the user
        /// </summary>
        /// <param name="graphtexture">Texture of the framebuffer contents</param>
        private void GetLatestTexture(out Texture graphtexture)
        {
            if (latestWrittenTexture == 1)
            {
                graphtexture = _outputTexture1!;
            }
            else
            {
                graphtexture = _outputTexture2!;
            }
        }
    }
}
