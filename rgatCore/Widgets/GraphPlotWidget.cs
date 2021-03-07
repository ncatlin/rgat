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

        System.Timers.Timer _IrregularActionTimer;
        bool _IrregularActionTimerFired = false;

        ImGuiController _controller;
        ReaderWriterLock renderLock = new ReaderWriterLock();
        GraphLayoutEngine _layoutEngine;
        GraphicsDevice _gd;
        ResourceFactory _factory;
        Vector2 _graphWidgetSize;

        TextureView _imageTextureView;

        public GraphPlotWidget(ImGuiController controller, GraphicsDevice gdev, Vector2? initialSize = null)
        {
            _controller = controller;
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            _graphWidgetSize = initialSize ?? new Vector2(400, 400);
            _IrregularActionTimer = new System.Timers.Timer(600);
            _IrregularActionTimer.Elapsed += FireIrregularTimer;
            _IrregularActionTimer.AutoReset = true;
            _IrregularActionTimer.Start();

            _layoutEngine = new GraphLayoutEngine(gdev, controller);
            _imageTextureView = controller.GetImageView;
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


        public void Draw(Vector2 graphSize)
        {
            renderLock.AcquireReaderLock(200);
            HandleInput(graphSize);

            if (_IrregularActionTimerFired)
                PerformIrregularActions();

            if (ActiveGraph != null)
            {
                renderLock.AcquireReaderLock(10); //todo handle timeout
                DrawGraph();
                renderLock.ReleaseReaderLock();
            }

            drawHUD(graphSize);
            renderLock.ReleaseReaderLock();
        }

        public DeviceBuffer _viewBuffer { get; private set; }
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
            _paramsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<graphShaderParams>(), BufferUsage.UniformBuffer));

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));

            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeTextures", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
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
                new DepthStencilStateDescription(false, false, ComparisonKind.Always),
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, false, true),
                PrimitiveTopology.TriangleList, fontshader,
                new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer.OutputDescription);
            _fontPipeline = _factory.CreateGraphicsPipeline(fontpd);
        }


        void RecreateOutputTextures()
        {
            _outputTexture?.Dispose();
            _outputTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
                PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _outputFramebuffer?.Dispose();
            _outputFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));

            _testPickingTexture?.Dispose();
            _testPickingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _pickingFrameBuffer?.Dispose();
            _pickingFrameBuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));

            _pickingStagingTexture?.Dispose();
            _pickingStagingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D((uint)_graphWidgetSize.X, (uint)_graphWidgetSize.Y, 1, 1,
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
        public struct graphShaderParams
        {
            public Matrix4x4 rotatedView;
            public Matrix4x4 nonRotatedView;
            public uint TexWidth;
            public int pickingNode;
            public bool isAnimated;
            //must be multiple of 16

            private ulong _padding1;
            private bool _padding3c;
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
                    ActiveGraph.internalProtoGraph.HeatSolvingComplete = false; //todo - temporary for dev
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

        graphShaderParams updateShaderParams(uint textureSize)
        {
            graphShaderParams shaderParams = new graphShaderParams { TexWidth = textureSize, pickingNode = _mouseoverNodeID, isAnimated = ActiveGraph.IsAnimated };

            float aspectRatio = _graphWidgetSize.X / _graphWidgetSize.Y;
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
        }

        List<fontStruc> renderNodeText(List<Tuple<string, Color>> captions, int nodeIdx = -1)
        {
            const float fontScale = 16.0f;
            List<fontStruc> stringVerts = new List<fontStruc>();

            RenderString(captions[nodeIdx].Item1, (uint)nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, captions[nodeIdx].Item2);
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
                RenderString(ar.text, (uint)ar.nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, Color.SpringGreen, yOff: ar.currentY);
            }
        }


        List<fontStruc> renderGraphText(List<Tuple<string, Color>> captions)
        {
            const float fontScale = 13.0f;
            List<fontStruc> stringVerts = new List<fontStruc>();

            for (int nodeIdx = 0; nodeIdx < captions.Count; nodeIdx++)
            {
                RenderString(captions[nodeIdx].Item1, (uint)nodeIdx, fontScale, _controller._unicodeFont, ref stringVerts, captions[nodeIdx].Item2);
            }

            maintainRisingTexts(fontScale, ref stringVerts);
            uploadFontVerts(stringVerts);

            return stringVerts;
        }


        public void renderGraph(DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
        {
            //rotval += 0.01f; //autorotate
            if (ActiveGraph.PlotZRotation >= 360) ActiveGraph.PlotZRotation = 0;
            var textureSize = ActiveGraph.LinearIndexTextureSize();
            updateShaderParams(textureSize);

            TextureOffsetColour[] NodeVerts = ActiveGraph.GetMaingraphNodeVerts(
                out List<uint> nodeIndices,
                out TextureOffsetColour[] nodePickingColors,
                out List<Tuple<string, Color>> captions,
                _renderingMode);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * TextureOffsetColour.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)NodeVerts.Length * TextureOffsetColour.SizeInBytes, BufferUsage.VertexBuffer);
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

            TextureOffsetColour[] EdgeLineVerts = ActiveGraph.GetEdgeLineVerts(_renderingMode, out List<uint> edgeDrawIndexes, out int edgeVertCount, out int drawnEdgeCount);

            if (drawnEdgeCount == 0) return;
            if (((edgeVertCount * 4) > _EdgeIndexBuffer.SizeInBytes))
            {
                _EdgeVertBuffer.Dispose();
                BufferDescription tvbDescription = new BufferDescription((uint)EdgeLineVerts.Length * TextureOffsetColour.SizeInBytes, BufferUsage.VertexBuffer);
                _EdgeVertBuffer = _factory.CreateBuffer(tvbDescription);

                _EdgeIndexBuffer.Dispose();
                BufferDescription eibDescription = new BufferDescription((uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _EdgeIndexBuffer = _factory.CreateBuffer(eibDescription);
            }

            //todo - only do this on changes
            _gd.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            //have hacked in a solution here but the codepoint and visible attribs (which we don't use) wont work. 
            //https://github.com/mellinoe/ImGui.NET/issues/206
            System.Diagnostics.Debug.Assert(_controller._unicodeFont.GetCharAdvance('4') == _controller._unicodeFont.FindGlyph('4').AdvanceX);

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, positionsBuffer);
            _crs_core?.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, nodeAttributesBuffer, _imageTextureView);

            _crs_nodesEdges?.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);


            List<fontStruc> stringVerts;
            if (_mouseoverNodeID == -1)
            {
                stringVerts = renderGraphText(captions);
            }
            else
            {
                stringVerts = renderNodeText(captions, _mouseoverNodeID);
            }

            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / 4));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / 4));

            //draw nodes and edges
            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, GlobalConfig.mainColours.background.ToRgbaFloat());
            _cl.SetViewport(0, new Viewport(0, 0, _graphWidgetSize.X, _graphWidgetSize.Y, -2200, 1000));


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

            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            //draw text
            if (ActiveGraph.TextEnabled)
            {
                _cl.Begin();
                _cl.SetFramebuffer(_outputFramebuffer);
                _cl.SetViewport(0, new Viewport(0, 0, _graphWidgetSize.X, _graphWidgetSize.Y, -2200, 1000));

                _cl.SetPipeline(_fontPipeline);
                _cl.SetVertexBuffer(0, _FontVertBuffer);
                _cl.SetIndexBuffer(_FontIndexBuffer, IndexFormat.UInt16);
                _cl.SetGraphicsResourceSet(0, _crs_core);
                _cl.SetGraphicsResourceSet(1, _crs_font);
                _cl.DrawIndexed(indexCount: (uint)stringVerts.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

                _cl.End();
                _gd.SubmitCommands(_cl);
                _gd.WaitForIdle(); //needed?
            }


            //update the picking framebuffer
            _cl.Begin();
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

            _cl.Dispose();

            Vector2 mp = new Vector2(ImGui.GetMousePos().X + 8, ImGui.GetMousePos().Y - 12);
            ImGui.GetWindowDrawList().AddText(font: _controller._unicodeFont, font_size: 16,
                pos: mp, col: 0xffffffff, text_begin: $"{ImGui.GetMousePos().X},{ImGui.GetMousePos().Y}");

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


            msg = $"Displaying thread {activeGraph.tid}";
            Vector2 currentPos = ImGui.GetCursorPos();
            ImGui.SetCursorScreenPos(new Vector2(topLeft.X + 4, topLeft.Y + 4));
            ImGui.Text(msg);
            ImGui.SetCursorPos(currentPos);

            DrawVisibilitySelector(bottomLeft, 0.25f);

        }




        bool ImageCaptionButton(Texture iconTex, Vector2 iconsize, float width, string caption, bool isSelected)
        {

            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, iconTex);
            bool isMouseHover = ImGui.IsMouseHoveringRect(ImGui.GetCursorScreenPos(), ImGui.GetCursorScreenPos() + new Vector2(width, iconsize.Y));
            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x45d5d5d5);
            else
            {
                if (isMouseHover)
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff989898);
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
                }
            }

            bool clicked = false;
            Vector2 widgetSize = new Vector2(width, iconsize.Y + 4);
            if (ImGui.BeginChild(ImGui.GetID(caption + "ICB"), widgetSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                Vector2 a = ImGui.GetCursorScreenPos() + new Vector2(5, 2);

                if (ImGui.InvisibleButton(caption + "IVB", widgetSize))
                {
                    clicked = true;
                }

                ImGui.SetCursorScreenPos(a);
                ImGui.Image(CPUframeBufferTextureId, iconsize);
                ImGui.SameLine(iconsize.X + 14);
                Vector2 iconPos = ImGui.GetCursorScreenPos();
                ImGui.SetCursorScreenPos(new Vector2(iconPos.X, iconPos.Y + 7));
                ImGui.Text(caption);
                ImGui.SetCursorScreenPos(iconPos);

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
            return clicked;
        }

        uint _lastActiveID;
        DateTime _LastActiveIdTimer;
        bool _tmpNodesIsToggled;
        bool _tmpEdgesIsToggled;
        static float ImSaturate(float f) { return (f < 0.0f) ? 0.0f : (f > 1.0f) ? 1.0f : f; }

        void ToggleButton(string str_id, ref bool isToggled)
        {
            Vector2 p = ImGui.GetCursorScreenPos();
            ImDrawListPtr draw_list = ImGui.GetWindowDrawList();

            float height = ImGui.GetFrameHeight();
            float width = height * 1.55f;
            float radius = height * 0.50f;

            ImGui.InvisibleButton(str_id, new Vector2(width, height));
            if (ImGui.IsItemClicked())
            {
                isToggled = !isToggled;
                _lastActiveID = ImGui.GetID(str_id);
                _LastActiveIdTimer = DateTime.UtcNow;
            }

            float t = isToggled ? 1.0f : 0.0f;

            float ANIM_SPEED = 0.08f;
            if (_lastActiveID == ImGui.GetID(str_id))
            {
                float t_anim = ImSaturate((float)(DateTime.UtcNow - _LastActiveIdTimer).TotalSeconds / ANIM_SPEED);
                t = isToggled ? (t_anim) : (1.0f - t_anim);
                if (t == 0f || t == 1.0f) { _lastActiveID = 0; }
            }

            uint col_bg;
            if (ImGui.IsItemHovered())
                col_bg = isToggled ? 0xff223344 : 0xff554433;
            else
                col_bg = isToggled ? 0xff773744 : 0xff994413;

            draw_list.AddRectFilled(p, new Vector2(p.X + width, p.Y + height), col_bg, height * 0.5f);
            draw_list.AddCircleFilled(new Vector2(p.X + radius + t * (width - radius * 2.0f), p.Y + radius), radius - 1.5f, 0xffffffff);
        }


        bool _showLayoutSelectorPopup;
        bool _showVisibilitySelector;
        Texture getLayoutIcon(eGraphLayout layout)
        {
            switch (layout)
            {
                case eGraphLayout.eForceDirected3DNodes:
                case eGraphLayout.eForceDirected3DBlocks:
                    return  _controller.GetImage("Force3D");
                case eGraphLayout.eCircle:
                    return _controller.GetImage("Circle");
                case eGraphLayout.eCylinderLayout:
                    return _controller.GetImage("Cylinder");
                default:
                    Console.WriteLine($"ERROR: no icond for layout {layout}");
                    return _controller.GetImage("Force3D");
            }
        }


        void DrawLayoutSelector(Vector2 position, float scale)
        {
            Texture btnIcon = getLayoutIcon(ActiveGraph.LayoutStyle);
            Vector2 iconSize = new Vector2(128 * scale, 128 * scale);
            float padding = 6f;
            Vector2 pmin = new Vector2((position.X - iconSize.X) - padding, ((position.Y - iconSize.Y) - 4) - padding);
            float buttonWidth = 150f;

            ImGui.SetCursorScreenPos(pmin);

            ImGui.PushStyleColor(ImGuiCol.Button, 0x11000000);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0x11000000);
            ImGui.ImageButton(_controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon), iconSize);
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
                if (ImageCaptionButton(getLayoutIcon(eGraphLayout.eForceDirected3DNodes), iconSize, buttonWidth, "Force Directed Nodes", ActiveGraph.LayoutStyle == eGraphLayout.eForceDirected3DNodes))
                {
                    if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eForceDirected3DNodes)) { _layoutEngine.ChangePreset(); }
                }
                if (ImageCaptionButton(getLayoutIcon(eGraphLayout.eForceDirected3DBlocks), iconSize, buttonWidth, "Force Directed Blocks", ActiveGraph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks))
                {
                    if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eForceDirected3DBlocks)) { _layoutEngine.ChangePreset(); }
                }
                if (ImageCaptionButton(getLayoutIcon(eGraphLayout.eCylinderLayout), iconSize, buttonWidth, "Cylinder", ActiveGraph.LayoutStyle == eGraphLayout.eCylinderLayout))
                {
                    if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eCylinderLayout)) { _layoutEngine.ChangePreset(); }
                }
                if (ImageCaptionButton(getLayoutIcon(eGraphLayout.eCircle), iconSize, buttonWidth, "Circle", ActiveGraph.LayoutStyle == eGraphLayout.eCircle))
                {
                    if (!snappingToPreset && ActiveGraph.SetLayout(eGraphLayout.eCircle)) { _layoutEngine.ChangePreset(); }
                }

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

        void DrawVisibilitySelector(Vector2 position, float scale)
        {
            Texture btnIcon = _controller.GetImage("Eye");
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon);
            float padding = 6f;
            Vector2 iconSize = new Vector2(btnIcon.Width * scale, btnIcon.Height * scale);
            Vector2 pmin = new Vector2((position.X) + padding, ((position.Y - iconSize.Y) - 4) - padding);

            ImGui.SetCursorScreenPos(pmin);

            ImGui.PushStyleColor(ImGuiCol.Button, 0x11000000);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0x11000000);
            ImGui.ImageButton(CPUframeBufferTextureId, iconSize);
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();

            bool buttonHover = ImGui.IsItemHovered(flags: ImGuiHoveredFlags.AllowWhenBlockedByPopup);
            if (!_showVisibilitySelector && buttonHover)
            {
                _showVisibilitySelector = true;
            }

            if (_showVisibilitySelector)
            {
                ImGui.SetNextWindowPos(new Vector2(pmin.X, pmin.Y - iconSize.Y * 3));
                ImGui.OpenPopup("VisibilityPopup");
            }
            //ImGui.SetTooltip("I am a tooltip over a popup");
            if (ImGui.BeginPopup("VisibilityPopup"))
            {
                if (ImGui.BeginChildFrame(ImGui.GetID("VisibilityPopupFrame"), new Vector2(300, 300)))
                {

                    ImGui.Text("Show Edges");
                    ImGui.SameLine();
                    ToggleButton("edgesToggle", ref ActiveGraph.EdgesVisible);
                    ImGui.Text("Show Nodes");
                    ImGui.SameLine();
                    ToggleButton("nodes", ref ActiveGraph.NodesVisible);
                    ImGui.Text("Enable Text");
                    ImGui.SameLine();
                    ToggleButton("textenable", ref ActiveGraph.TextEnabled);
                    ImGui.Text("Instruction Text");
                    ImGui.Text("Symbol Text");

                    ImGui.EndChildFrame();
                }

                if (!ImGui.IsWindowHovered(flags: ImGuiHoveredFlags.RootAndChildWindows
                        | ImGuiHoveredFlags.AllowWhenBlockedByPopup
                        | ImGuiHoveredFlags.AllowWhenBlockedByActiveItem) && !buttonHover)
                {
                    _showVisibilitySelector = false;
                    ImGui.CloseCurrentPopup();
                }
                ImGui.EndPopup();
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

            bool doDispose = FetchNodeBuffers(ActiveGraph, out DeviceBuffer positionBuf, out DeviceBuffer attribBuf);
            renderGraph(positionBuf, nodeAttributesBuffer: attribBuf);
            if (doDispose)
            {
                positionBuf?.Dispose();
                attribBuf?.Dispose();
            }

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

            //store latest positions for the preview graph

            _layoutEngine.StoreCurrentGraphData();

            //highlight new nodes with highlighted address
            ActiveGraph.DoHighlightAddresses();
        }



    }
}
