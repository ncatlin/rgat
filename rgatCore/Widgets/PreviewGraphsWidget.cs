using ImGuiNET;
using rgatCore.Shaders.SPIR_V;
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
using System.Timers;
using Veldrid;
using Veldrid.ImageSharp;
using Veldrid.SPIRV;
using static rgatCore.VeldridGraphBuffers;

namespace rgatCore
{
    class PreviewGraphsWidget
    {
        List<PlottedGraph> DrawnPreviewGraphs = new List<PlottedGraph>();


        System.Timers.Timer IrregularTimer;
        bool IrregularTimerFired = false;

        TraceRecord ActiveTrace = null;

        public float dbg_FOV = 1.0f;//1.0f;
        public float dbg_near = 0.5f;
        public float dbg_far = 8000f;
        public float dbg_camX = 0f;
        public float dbg_camY = 5f;
        public float dbg_camZ = 100f;
        public float dbg_rot = 0;

        public float EachGraphWidth = UI_Constants.PREVIEW_PANE_WIDTH - (2 * UI_Constants.PREVIEW_PANE_PADDING);
        public float EachGraphHeight = UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT;
        public float MarginWidth = 5f;

        public uint selectedGraphTID;
        public PlottedGraph clickedGraph { get; private set; }

        ImGuiController _ImGuiController;
        GraphicsDevice _gd;
        ResourceFactory _factory;
        rgatState _rgatState;

        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout;
        ResourceSet _crs_core, _crs_nodesEdges;
        DeviceBuffer _paramsBuffer;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodeIndexBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;
        Pipeline _edgesPipeline, _pointsPipeline;


        GraphLayoutEngine _layoutEngine;
        public GraphLayoutEngine LayoutEngine => _layoutEngine;

        public PreviewGraphsWidget(ImGuiController controller, GraphicsDevice gdev, rgatState clientState)
        {
            IrregularTimer = new System.Timers.Timer(600);
            IrregularTimer.Elapsed += FireTimer;
            IrregularTimer.AutoReset = true;
            IrregularTimer.Start();
            _rgatState = clientState;
            _ImGuiController = controller;
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _layoutEngine = new GraphLayoutEngine(gdev, controller);
            SetupRenderingResources();
        }

        private void FireTimer(object sender, ElapsedEventArgs e) { IrregularTimerFired = true; }

        public void SetActiveTrace(TraceRecord trace) => ActiveTrace = trace;

        public void SetSelectedGraph(PlottedGraph graph)
        {
            _layoutEngine.StoreVRAMGraphDataToGraphObj(graph);
            selectedGraphTID = graph.tid;
        }

        private void HandleClickedGraph(PlottedGraph graph) => clickedGraph = graph;
        public void ResetClickedGraph() => clickedGraph = null;


        //we do it via Draw so events are handled by the same thread
        public void HandleFrameTimerFired()
        {
            //Console.WriteLine("Handling timer fired");
            IrregularTimerFired = false;
            foreach (PlottedGraph graph in _centeringRequired.Keys.ToList())
            {
                _centeringRequired[graph] = true;
            }
        }


        public void SetupRenderingResources()
        {
            _paramsBuffer = _factory.CreateBuffer(new BufferDescription(
                (uint)Unsafe.SizeOf<GraphPlotWidget.GraphShaderParams>(), BufferUsage.UniformBuffer));

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));


            _NodeCircleSprite = _ImGuiController.GetImage("VertCircle");
            _NodeCircleSpritetview = _ImGuiController.GetImageView;


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

            OutputAttachmentDescription[] oads = { new OutputAttachmentDescription(PixelFormat.R32_G32_B32_A32_Float) };
            pipelineDescription.Outputs = new OutputDescription
            {
                DepthAttachment = null,
                SampleCount = TextureSampleCount.Count1,
                ColorAttachments = oads
            };

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

        }

        /*
         * Fetched pre-prepared device buffer from layout engine if it is in the working set
         * Otherwise creates a new one from the stored data in the plottedgraph
         * 
         * Returns True if the devicebuffer can be destroyed, or False if the Layoutengine is using it
         */
        //todo - preview buffer caches
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


        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// </summary>
        bool CenterGraphInFrameStep(out float MaxRemaining, PlottedGraph graph)
        {
            Vector2 size = new Vector2(EachGraphWidth, EachGraphHeight);
            if (!_layoutEngine.GetPreviewFitOffsets(size, graph, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets))
            {
                MaxRemaining = 0;
                return false;
            }

            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 80, targYpadding = 35;

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < graphDepth)
            {
                delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                float maxdelta = Math.Max(delta, 35);
                graph.PreviewCameraZoom -= maxdelta;
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
                    graph.PreviewCameraZoom -= delta;
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
                graph.PreviewCameraXOffset += actualXdelta;
            else
                graph.PreviewCameraXOffset -= actualXdelta;

            float actualYdelta = Math.Min(Math.Abs(ydelta), 150);
            if (ydelta > 0)
                graph.PreviewCameraYOffset += actualYdelta;
            else
                graph.PreviewCameraYOffset -= actualYdelta;

            float actualZdelta = Math.Min(Math.Abs(zdelta), 300);
            if (zdelta > 0)
                graph.PreviewCameraZoom += actualZdelta;
            else
                graph.PreviewCameraZoom -= actualZdelta;

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));


            return Math.Abs(xdelta) < 10 && Math.Abs(ydelta) < 10 && Math.Abs(zdelta) < 10;
        }





        public void DrawWidget()
        {
            TraceRecord activeTrace = ActiveTrace;
            if (activeTrace == null) return;
            if (IrregularTimerFired) HandleFrameTimerFired();

            Vector2 subGraphPosition = ImGui.GetCursorScreenPos();
            subGraphPosition.X -= MarginWidth;

            float captionHeight = ImGui.CalcTextSize("123456789").Y + 3; //dunno where the 3 comes from but it works

            DrawnPreviewGraphs = activeTrace.GetPlottedGraphsList(mode: eRenderingMode.eStandardControlFlow);
            uint captionBackgroundcolor = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint();

            _layoutEngine.SetActiveTrace(activeTrace);
            _layoutEngine.UpdatePositionCaches();

            for (var graphIdx = 0; graphIdx < DrawnPreviewGraphs.Count; graphIdx++)
            {
                PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                if (DrawPreviewGraph(graph, subGraphPosition, captionHeight, captionBackgroundcolor))
                {
                    var MainGraphs = graph.internalProtoGraph.TraceData.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                    HandleClickedGraph(MainGraphs[graphIdx]);
                    subGraphPosition.Y += (EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING);
                }
            }

        }

        void DrawPreviewViewBox(PlottedGraph graph, Vector2 subGraphPosition )
        {
            ImDrawListPtr imdp = ImGui.GetWindowDrawList();
            float previewBaseY = subGraphPosition.Y + EachGraphHeight;

            graph.GetPreviewVisibleRegion(new Vector2(EachGraphWidth, EachGraphHeight), PreviewProjection, out Vector2 TopLeft, out Vector2 BaseRight);

            float C1X = subGraphPosition.X + TopLeft.X;
            float C2X = subGraphPosition.X + BaseRight.X;
            float C1Y = previewBaseY - TopLeft.Y;
            float C2Y = previewBaseY - BaseRight.Y;

            C1Y = Math.Min(previewBaseY - 1, C1Y);
            C2Y = Math.Max(subGraphPosition.Y, C2Y);
            uint boxcol = 0x65ffffff;

            if (C1Y > subGraphPosition.Y && C1Y < previewBaseY)
                imdp.AddLine(new Vector2(C1X, C1Y), new Vector2(C2X, C1Y), boxcol);

            if (C2Y > subGraphPosition.Y && C2Y < previewBaseY)
                imdp.AddLine(new Vector2(C2X, C2Y), new Vector2(C1X, C2Y), boxcol);

            if (C2Y < previewBaseY && C1Y > subGraphPosition.Y)
            {
                imdp.AddLine(new Vector2(C2X, C1Y), new Vector2(C2X, C2Y), boxcol);
                imdp.AddLine(new Vector2(C1X, C2Y), new Vector2(C1X, C1Y), boxcol);
            }

        }


        public bool DrawPreviewGraph(PlottedGraph graph, Vector2 subGraphPosition, float captionHeight, uint captionBackgroundcolor)
        {
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            bool clicked = false;
            if (graph == null) return clicked;
            int graphNodeCount = graph.GraphNodeCount();
            if (graphNodeCount == 0) return clicked;


            if (graph != _rgatState.ActiveGraph)
            {
                _layoutEngine.Set_activeGraph(graph);
                _layoutEngine.Compute((uint)graph.DrawnEdgesCount, -1, false);
            }

            bool doDispose = FetchNodeBuffers(graph, out DeviceBuffer positionBuf, out DeviceBuffer attribBuf);
            renderPreview(graph: graph, positionsBuffer: positionBuf, nodeAttributesBuffer: attribBuf);

            if (doDispose)
            {
                positionBuf?.Dispose();
                attribBuf?.Dispose();
            }
            if (graph._previewTexture == null) return clicked;
            bool isSelected = graph.tid == selectedGraphTID;


            //copy in the actual rendered graph
            ImGui.SetCursorPosY(ImGui.GetCursorPosY());
            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._previewTexture);
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId,
                p_min: subGraphPosition,
                p_max: new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight),
                uv_min: new Vector2(0, 1),
                uv_max: new Vector2(1, 0));




            //selection border
            if (isSelected)
            {
                DrawPreviewViewBox(graph, subGraphPosition);

                imdp.AddRect(
                    p_min: new Vector2(subGraphPosition.X + 1, subGraphPosition.Y),
                    p_max: new Vector2(subGraphPosition.X + EachGraphWidth - 1, subGraphPosition.Y + EachGraphHeight),
                    col: graph.internalProtoGraph.Terminated ? 0xff0000ff : 0xff00ff00);
            }

            //write the caption
            string Caption = $"TID:{graph.tid} {graphNodeCount}nodes {(isSelected ? "[Selected]" : "")}";

            ImGui.SetCursorPosX(ImGui.GetCursorPosX());
            Vector2 captionBGStart = new Vector2(ImGui.GetCursorScreenPos().X - 3, ImGui.GetCursorScreenPos().Y + 1);
            Vector2 captionBGEnd = new Vector2((ImGui.GetCursorScreenPos().X + EachGraphWidth) - (MarginWidth + 3), ImGui.GetCursorScreenPos().Y + captionHeight);
            imdp.AddRectFilled(p_min: captionBGStart, p_max: captionBGEnd, col: captionBackgroundcolor);
            ImGui.Text(Caption);
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + EachGraphWidth - 48);

            //live thread activity plot
            if (!ActiveTrace.WasLoadedFromSave)
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - captionHeight);

                float maxVal;
                float[] values = null;
                if (graph.internalProtoGraph.TraceReader != null)
                {
                    values = graph.internalProtoGraph.TraceReader.RecentMessageRates();
                }
                if (values == null || values.Length == 0)
                {
                    values = new List<float>() { 0, 0, 0, 0, 0 }.ToArray();
                    maxVal = 100;
                }
                else
                {
                    maxVal = values.Max(); // should instead do the max of all the values from all the threads?
                }
                ImGui.PushStyleColor(ImGuiCol.FrameBg, captionBackgroundcolor);
                ImGui.PlotLines("", ref values[0], values.Length, 0, "", 0, maxVal, new Vector2(40, captionHeight));
                ImGui.PopStyleColor();
            }


            //invisible button to detect graph click
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - (float)(captionHeight));
            if (ImGui.InvisibleButton("PrevGraphBtn" + graph.tid, new Vector2(EachGraphWidth, EachGraphHeight)))
            {
                clicked = true;
            }
            return clicked;

        }



        Matrix4x4 PreviewProjection => Matrix4x4.CreatePerspectiveFieldOfView(1.0f, EachGraphWidth / EachGraphHeight, 1, 50000);


        GraphPlotWidget.GraphShaderParams updateShaderParams(uint textureSize, PlottedGraph graph)
        {
            GraphPlotWidget.GraphShaderParams shaderParams = new GraphPlotWidget.GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = -1,
                isAnimated = false
            };

            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(new Vector3(graph.PreviewCameraXOffset, graph.PreviewCameraYOffset, graph.PreviewCameraZoom));


            shaderParams.nonRotatedView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            shaderParams.proj = PreviewProjection;
            shaderParams.view = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            shaderParams.world = cameraTranslation;


            shaderParams.world = graph.RotationMatrix;


            shaderParams.view = cameraTranslation;


            _gd.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _gd.WaitForIdle();

            return shaderParams;
        }

        Dictionary<PlottedGraph, bool> _centeringRequired = new Dictionary<PlottedGraph, bool>();


        void renderPreview(PlottedGraph graph, DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
        {
            if (graph == null || positionsBuffer == null || nodeAttributesBuffer == null) return;
            if (graph._previewTexture == null)
            {
                int width = UI_Constants.PREVIEW_PANE_WIDTH - (UI_Constants.PREVIEW_PANE_PADDING * 2);
                graph.InitPreviewTexture(new Vector2(width, UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT), _gd);
            }

            bool needsCentering = true;
            if (!_centeringRequired.TryGetValue(graph, out needsCentering))
            {
                _centeringRequired.Add(graph, true);
            }

            /*
            if (needsCentering)
            {
               bool done = CenterGraphInFrameStep(out float maxremaining, graph);
                if (done)
                {
                    _centeringRequired[graph] = false;
                }
            }*/

            var textureSize = graph.LinearIndexTextureSize();
            updateShaderParams(textureSize, graph);

            TextureOffsetColour[] NodeVerts = graph.GetPreviewgraphNodeVerts(out List<uint> nodeIndices, eRenderingMode.eStandardControlFlow);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * TextureOffsetColour.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)NodeVerts.Length * TextureOffsetColour.SizeInBytes, BufferUsage.VertexBuffer);
                _NodeVertexBuffer.Dispose();
                _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);

                BufferDescription ibDescription = new BufferDescription((uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _NodeIndexBuffer.Dispose();
                _NodeIndexBuffer = _factory.CreateBuffer(ibDescription);
            }

            _gd.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());



            TextureOffsetColour[] EdgeLineVerts = graph.GetEdgeLineVerts(eRenderingMode.eStandardControlFlow, out List<uint> edgeDrawIndexes, out int edgeVertCount, out int drawnEdgeCount);

            if (drawnEdgeCount == 0) return;
            if (((edgeVertCount * sizeof(uint)) > _EdgeIndexBuffer.SizeInBytes))
            {
                _EdgeVertBuffer.Dispose();
                BufferDescription tvbDescription = new BufferDescription((uint)EdgeLineVerts.Length * TextureOffsetColour.SizeInBytes, BufferUsage.VertexBuffer);
                _EdgeVertBuffer = _factory.CreateBuffer(tvbDescription);

                _EdgeIndexBuffer.Dispose();
                BufferDescription eibDescription = new BufferDescription((uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _EdgeIndexBuffer = _factory.CreateBuffer(eibDescription);
            }

            _gd.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, positionsBuffer);
            _crs_core?.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, nodeAttributesBuffer, _NodeCircleSpritetview);
            _crs_nodesEdges?.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);

            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / sizeof(uint)));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / sizeof(uint)));

            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(graph._previewFramebuffer);

            WritableRgbaFloat background = graph.internalProtoGraph.Terminated ? GlobalConfig.mainColours.terminatedPreview : GlobalConfig.mainColours.runningPreview;
            _cl.ClearColorTarget(0, background.ToRgbaFloat());
            _cl.SetViewport(0, new Viewport(0, 0, EachGraphWidth, EachGraphHeight, -2200, 1000));

            //draw nodes
            _cl.SetPipeline(_pointsPipeline);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.SetVertexBuffer(0, _NodeVertexBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)nodesToDraw, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            //draw edges
            _cl.SetPipeline(_edgesPipeline);
            _cl.SetVertexBuffer(0, _EdgeVertBuffer);
            _cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)edgeVertCount, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);


            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            _cl.Dispose();
        }


    }
}
