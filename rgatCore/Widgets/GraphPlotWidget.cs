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

namespace rgatCore
{
    class GraphPlotWidget
    {
        public PlottedGraph ActiveGraph { get; private set; } = null;

        private bool inited1 = false;


        System.Timers.Timer IrregularActionTimer;
        bool IrregularActionTimerFired = false;

        Dictionary<PlottedGraph, VeldridGraphBuffers> graphBufferDict = new Dictionary<PlottedGraph, VeldridGraphBuffers>();
        VeldridGraphBuffers graphBuffers = null;
        ImGuiController _controller;
        ReaderWriterLock renderLock = new ReaderWriterLock();
        GraphLayoutEngine _layoutEngine;

        private Vector2 graphWidgetSize;


        GraphicsDevice _gd;
        ResourceFactory _factory;

        public GraphPlotWidget(ImGuiController controller, GraphicsDevice gdev, Vector2? initialSize = null)
        {
            _controller = controller;
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            graphWidgetSize = initialSize ?? new Vector2(400, 400);
            IrregularActionTimer = new System.Timers.Timer(600);
            IrregularActionTimer.Elapsed += FireIrregularTimer;
            IrregularActionTimer.AutoReset = true;
            IrregularActionTimer.Start();

            _layoutEngine = new GraphLayoutEngine(gdev, controller);

            SetupRenderingResources();
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

            //todo - is this still needed? do we need to store multiple graphs in GPU ram at once? 
            //i think not since rendering is so fast now
            //store old positions/verts floats in graph when switching
            /*
            if (!graphBufferDict.TryGetValue(graph, out graphBuffers))
            {
                graphBuffers = new VeldridGraphBuffers();
                graphBufferDict.Add(graph, graphBuffers);
                //graph.UpdateGraphicBuffers(graphWidgetSize, _gd);
                //graphBuffers.InitPipelines(_gd, CreateGraphShaders(), graph._outputFramebuffer, true);
            }
            */

            renderLock.AcquireWriterLock(0);
            ActiveGraph = graph;
            _layoutEngine.Set_activeGraph(ActiveGraph);
            RecreateGraphicsBuffers();
            renderLock.ReleaseWriterLock();
        }

        private void RecreateGraphicsBuffers()
        {
            currentGraphNodeCount = 0;
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

        private void FireIrregularTimer(object sender, ElapsedEventArgs e) { IrregularActionTimerFired = true; }

        /* 
	 * Triggered automatically when main window is resized
	 * Manually called when we detect window changes size otherwise
	 */
        public void AlertResized(Vector2 size)
        {
            lastResizeSize = size;
            lastResize = DateTime.Now;
            scheduledGraphResize = true;
        }

        private DateTime lastResize = DateTime.Now;
        private bool scheduledGraphResize = true;
        private Vector2 lastResizeSize = new Vector2(0, 0);

        public void ApplyZoom(float direction)
        {
            if (ActiveGraph != null)
            {
                float newValue = ActiveGraph.CameraZoom - (direction * 100);
                if (newValue >= 100)
                    ActiveGraph.CameraZoom = newValue;
            }
        }

        static public bool IsMouseInWidget(Vector2 graphSize)
        {
            Vector2 MousePos = ImGui.GetMousePos();
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();

            if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + graphSize.X))
            {
                if (MousePos.Y >= WidgetPos.Y && MousePos.Y < (WidgetPos.Y + graphSize.Y))
                {
                    return true;
                }
            }
            return false;
        }

        public void HandleInput(Vector2 graphSize)
        {
            bool mouseInWidget = IsMouseInWidget(graphSize);


            if (mouseInWidget)
            {
                float scroll = ImGui.GetIO().MouseWheel;
                if (scroll != 0) ApplyZoom(scroll);

                if (ActiveGraph != null && ImGui.GetIO().MouseDown[0])
                {
                    ActiveGraph.ApplyMouseDelta(ImGui.GetIO().MouseDelta);
                }
            }


        }


        public void Draw(Vector2 graphSize, ImGuiController _ImGuiController)
        {

            HandleInput(graphSize);

            if (IrregularActionTimerFired)
                PerformIrregularActions();

            if (ActiveGraph != null)
            {
                renderLock.AcquireReaderLock(10); //todo handle timeout
                doTestRender(_ImGuiController);
                renderLock.ReleaseReaderLock();
            }
            /*
            

            if (scheduledGraphResize)
            {
                double TimeSinceLastResize = (DateTime.Now - lastResize).TotalMilliseconds;
                if (TimeSinceLastResize > 150)
                {
                    graphWidgetSize = graphSize;
                    ActiveGraph.InitGraphTexture(graphWidgetSize, _gd);
                    scheduledGraphResize = false;
                }
            }
            //Can't find an event for in-imgui resize of childwindows so have to check on every render
            if (graphSize != graphWidgetSize && graphSize != lastResizeSize) AlertResized(graphSize);

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 pos = ImGui.GetCursorScreenPos();
            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, ActiveGraph._outputTexture);
            imdp.AddImage(CPUframeBufferTextureId,
                pos,
                new Vector2(pos.X + ActiveGraph._outputTexture.Width, pos.Y + ActiveGraph._outputTexture.Height), new Vector2(0, 1), new Vector2(1, 0));

            //drawHUD();
            */
        }





















      


        







        public float _delta;

        bool flipflop = true;
        public DeviceBuffer _viewBuffer { get; private set; }
        Framebuffer _outputFramebuffer, _pickingFrameBuffer;

        uint currentGraphNodeCount = 0;
        bool processingAnimatedGraph;

        /// <summary>
        /// Edges pipeline = line list or line strp
        /// Points pipeline = visible nodes where we draw sphere/etc texture
        /// Picking pipleine = same as points but different data, not drawn to screen. Seperate shaders to reduce branching
        /// Font pipeline = triangles
        /// </summary>
        Pipeline _edgesPipeline, _pointsPipeline, _pickingPipeline, _fontPipeline;



        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout, _fontRsrcLayout;
        Texture _outputTexture, _testPickingTexture, _pickingStagingTexture;

        //vert/frag rendering buffers
        ResourceSet _crs_core, _crs_nodesEdges, _crs_font;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodePickingBuffer, _NodeIndexBuffer;
        DeviceBuffer _FontVertBuffer, _FontIndexBuffer;
        DeviceBuffer _paramsBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;

        public DeviceBuffer _animBuffer { get; private set; }

        public unsafe void SetupRenderingResources()
        {


            _paramsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<graphShaderParams>(), BufferUsage.UniformBuffer));

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));



            string imgpath = @"C:\Users\nia\Desktop\rgatstuff\js\analytics-master\textures\new_circle.png";
            _NodeCircleSprite = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, _factory);
            _NodeCircleSpritetview = _factory.CreateTextureView(_NodeCircleSprite);


            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));


            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
            pipelineDescription.BlendState = BlendStateDescription.SingleAlphaBlend;
            pipelineDescription.DepthStencilState = new DepthStencilStateDescription(
                depthTestEnabled: true,
                depthWriteEnabled: true,
                comparisonKind: ComparisonKind.LessEqual);

            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: true,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout };
            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodeShaders(_factory, out _NodeVertexBuffer, out _NodeIndexBuffer);

            Debug.Assert(_outputTexture == null);
            Debug.Assert(_outputFramebuffer == null);
            _outputTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                    (uint)graphWidgetSize.X, (uint)graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));

            Debug.Assert(_testPickingTexture == null);
            _testPickingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                   (uint)graphWidgetSize.X, (uint)graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.RenderTarget | TextureUsage.Sampled));
            _pickingFrameBuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));
            _pickingStagingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                    (uint)graphWidgetSize.X, (uint)graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.Staging));

            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodePickingShaders(_factory, out _NodePickingBuffer);
            _pickingPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);



            //font -----------------------

            _fontRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            ResourceSetDescription crs_font_rsd = new ResourceSetDescription(_fontRsrcLayout, _controller._fontTextureView);
            _crs_font = _factory.CreateResourceSet(crs_font_rsd);

            ShaderSetDescription fontshader = SPIRVShaders.CreateFontShaders(_factory, out _FontVertBuffer, out _FontIndexBuffer);

            GraphicsPipelineDescription fontpd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                new DepthStencilStateDescription(false, false, ComparisonKind.Always),
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, false, true),
                PrimitiveTopology.TriangleList, fontshader, 
                new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer.OutputDescription);
            _fontPipeline = _factory.CreateGraphicsPipeline(fontpd);




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
        public struct graphShaderParams
        {
            public Matrix4x4 rotatedView;
            public Matrix4x4 nonRotatedView;
            public uint TexWidth;
            public int pickingNode;
            public bool isAnimated;
            //must be multiple of 16

            private ushort _padding1;
            private bool _padding3a;
            private bool _padding3b;
            private bool _padding3c;
        }



        void processKeyPresses()
        {
            bool kp = false;
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.UpArrow))) { ActiveGraph.CameraYOffset += 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.DownArrow))) { ActiveGraph.CameraYOffset -= 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.LeftArrow))) { ActiveGraph.CameraXOffset -= 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.RightArrow))) { ActiveGraph.CameraXOffset += 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.PageUp))) { ActiveGraph.CameraZoom += 100; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.PageDown))) { ActiveGraph.CameraZoom -= 100; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.End))) { ActiveGraph.PlotZRotation += 0.05f; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Delete))) { ActiveGraph.PlotZRotation -= 0.05f; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.V))) { ActiveGraph.IncreaseTemperature(); kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.X))) { ActiveGraph.AddTestNodes(); }
            //if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.C))) { ActiveGraph.AnimationStep(1); }

            //if (kp) Console.WriteLine($"xZoom: { ActiveGraph.CameraXOffset}, yZoom: { ActiveGraph.CameraYOffset} zzoom: {ActiveGraph.CameraZoom}");

        }



        void RenderString(string inputString, uint nodeIdx, float fontScale,  ref List<fontStruc> stringVerts, Color colour, float yOff = 0)
        {
                      
            float xPos = 0;
            float yPos = 50;
            float glyphYClip = 10;
            WritableRgbaFloat fcolour = new WritableRgbaFloat(colour);
            for (var i = 0; i < inputString.Length; i++)
            {
                ImFontGlyphPtr glyph = _controller._unicodeFont.FindGlyph(inputString[i]);
                float charWidth = glyph.AdvanceX * fontScale;
                float charHeight = fontScale * (glyph.Y1 - glyph.Y0);
                float xEnd = xPos + charWidth;
                float yBase = yPos + (glyphYClip - glyph.Y1) * fontScale;
                float yTop = yBase + charHeight;

                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1), yOffset = yOff, fontColour= fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1), yOffset = yOff, fontColour = fcolour });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0), yOffset = yOff, fontColour = fcolour });
                xPos += charWidth;
            }
        }

        graphShaderParams updateShaderParams(uint textureSize)
        {
            graphShaderParams shaderParams = new graphShaderParams { TexWidth = textureSize, pickingNode = _mouseoverNodeID, isAnimated = ActiveGraph.IsAnimated };

            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(ActiveGraph.CameraFieldOfView,
                aspectRatio, ActiveGraph.CameraClippingNear, ActiveGraph.CameraClippingFar);
            Vector3 translation = new Vector3(ActiveGraph.CameraXOffset, ActiveGraph.CameraYOffset, ActiveGraph.CameraZoom);
            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(translation);

            Matrix4x4 newView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, ActiveGraph.PlotZRotation);
            newView = Matrix4x4.Multiply(newView, cameraTranslation);
            newView = Matrix4x4.Multiply(newView, projection);
            shaderParams.rotatedView = newView;

            newView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            newView = Matrix4x4.Multiply(newView, cameraTranslation);
            shaderParams.nonRotatedView = newView;

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


        List<fontStruc> renderGraphText(List<Tuple<string,Color>> captions)
        {
            const float fontScale = 13.0f;
            List<fontStruc> stringVerts = new List<fontStruc>();

            for (int nodeIdx = 0; nodeIdx < captions.Count; nodeIdx++)
            {
                RenderString(captions[nodeIdx].Item1, (uint)nodeIdx, fontScale, ref stringVerts, captions[nodeIdx].Item2);
            }


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
                var currentLingeringCaptionNodes = _activeRisings
                    .Where(x => x.remainingFrames == -1)
                    .Select(x => x.nodeIdx);

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
                RenderString(ar.text, (uint)ar.nodeIdx, fontScale, ref stringVerts, Color.SpringGreen, yOff: ar.currentY);
            }

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

            return stringVerts;
        }





        public void renderGraph(ImGuiController _ImGuiController, DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
        {

            //rotval += 0.01f; //autorotate
            if (ActiveGraph.PlotZRotation >= 360) ActiveGraph.PlotZRotation = 0;
            var textureSize = ActiveGraph.LinearIndexTextureSize();
            updateShaderParams(textureSize);

            VertexPositionColor[] NodeVerts = ActiveGraph.GetNodeVerts(out List<uint> nodeIndices, 
                out VertexPositionColor[] nodePickingColors, out List<Tuple<string,Color>> captions);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * VertexPositionColor.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)NodeVerts.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
                _NodeVertexBuffer.Dispose();
                _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);
                _NodePickingBuffer.Dispose();
                _NodePickingBuffer = _factory.CreateBuffer(vbDescription);

                BufferDescription ibDescription = new BufferDescription((uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _NodeIndexBuffer.Dispose();
                _NodeIndexBuffer = _factory.CreateBuffer(ibDescription);
            }

            _gd.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            _gd.UpdateBuffer(_NodePickingBuffer, 0, nodePickingColors);
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());



            int drawnEdgeCount = ActiveGraph.GetEdgeLineVerts(out List<uint> edgeDrawIndexes, out int edgeVertCount, out VertexPositionColor[] EdgeLineVerts);

            if (drawnEdgeCount == 0) return;
            if (((edgeVertCount * 4) > _EdgeIndexBuffer.SizeInBytes))
            {
                _EdgeVertBuffer.Dispose();
                BufferDescription tvbDescription = new BufferDescription((uint)EdgeLineVerts.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
                _EdgeVertBuffer = _factory.CreateBuffer(tvbDescription);
                _gd.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);

                _EdgeIndexBuffer.Dispose();
                BufferDescription eibDescription = new BufferDescription((uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _EdgeIndexBuffer = _factory.CreateBuffer(eibDescription);
                _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());
            }

            //have hacked in a solution here but the codepoint and visible attribs (which we don't use) wont work. 
            //https://github.com/mellinoe/ImGui.NET/issues/206
            System.Diagnostics.Debug.Assert(_controller._unicodeFont.GetCharAdvance('4') == _controller._unicodeFont.FindGlyph('4').AdvanceX);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, positionsBuffer);
            _crs_core?.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, nodeAttributesBuffer, _NodeCircleSpritetview);
            _crs_nodesEdges?.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);


            List<fontStruc> stringVerts = renderGraphText(captions);

            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / 4));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / 4));

            //draw nodes and edges
            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, GlobalConfig.mainColours.background.ToRgbaFloat());
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));

            _cl.SetPipeline(_pointsPipeline);
            _cl.SetVertexBuffer(0, _NodeVertexBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.DrawIndexed(indexCount: (uint)nodesToDraw, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.SetPipeline(_edgesPipeline);
            _cl.SetVertexBuffer(0, _EdgeVertBuffer);
            _cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)edgeVertCount, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            //draw text
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));

            _cl.SetPipeline(_fontPipeline);
            _cl.SetVertexBuffer(0, _FontVertBuffer);
            _cl.SetIndexBuffer(_FontIndexBuffer, IndexFormat.UInt16);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_font);
            _cl.DrawIndexed(indexCount: (uint)stringVerts.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            //update the picking framebuffer
            _cl.Begin();
            _cl.SetPipeline(_pickingPipeline);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.SetVertexBuffer(0, _NodePickingBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.SetFramebuffer(_pickingFrameBuffer);

            _cl.ClearColorTarget(0, new RgbaFloat(0f, 0f, 0f, 0f));
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));
            _cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            _cl.CopyTexture(_testPickingTexture, _pickingStagingTexture);
            _cl.End();
            _gd.SubmitCommands(_cl);
            _gd.WaitForIdle();


            //now draw the output to the screen
            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, _outputTexture);
            imdp.AddImage(CPUframeBufferTextureId, pos,
            new Vector2(pos.X + _outputTexture.Width, pos.Y + _outputTexture.Height),
            new Vector2(0, 1), new Vector2(1, 0));

            _cl.Dispose();

            Vector2 mp = new Vector2(ImGui.GetMousePos().X + 8, ImGui.GetMousePos().Y - 12);
            ImGui.GetWindowDrawList().AddText(_ImGuiController._unicodeFont, 16, mp, 0xffffffff, $"{ImGui.GetMousePos().X},{ImGui.GetMousePos().Y}");

        }








        public unsafe void doTestRender(ImGuiController _ImGuiController)
        {

            if (processingAnimatedGraph && !ActiveGraph.IsAnimated)
            {
                _layoutEngine.ResetNodeAttributes(ActiveGraph);
                processingAnimatedGraph = false;
            }
            else if (!processingAnimatedGraph && ActiveGraph.IsAnimated)
            {
                processingAnimatedGraph = true;
            }

            processKeyPresses();

            _layoutEngine.Compute((uint)ActiveGraph.DrawnEdgesCount, _mouseoverNodeID);

            doPicking(_gd);
            renderGraph(_ImGuiController, _layoutEngine.GetPositionsBuffer(ActiveGraph), _layoutEngine.GetNodeAttribsBuffer(ActiveGraph));
        }


        int _mouseoverNodeID = -1;
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

            //store latest positions for the preview graph
            _layoutEngine.StoreNodePositions(ActiveGraph);

            //highlight new nodes with highlighted address
            ActiveGraph.DoHighlightAddresses();

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.ePlaying)
            {
                //ui->replaySlider->setValue(1000 * ActiveGraph.getAnimationPercent());
            }

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.eEnded)
            {
                //ui->dynamicAnalysisContentsTab->stopAnimation();
            }

        }



    }
}
