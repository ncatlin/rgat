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

        GraphLayoutEngine _layoutEngine;
        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout;
        ResourceSet _crs_core, _crs_nodesEdges;
        DeviceBuffer _paramsBuffer;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodeIndexBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;
        Pipeline _edgesPipeline, _pointsPipeline;



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

        public void SetSelectedGraph(PlottedGraph graph) {
            _layoutEngine.StoreGraphData(graph);
            selectedGraphTID = graph.tid;
        }

        private void HandleClickedGraph(PlottedGraph graph) => clickedGraph = graph;
        public void ResetClickedGraph() => clickedGraph = null;


        //we do it via Draw so events are handled by the same thread
        public void HandleFrameTimerFired()
        {
            //Console.WriteLine("Handling timer fired");
            IrregularTimerFired = false;
        }


        public void SetupRenderingResources()
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

            OutputAttachmentDescription[] oads = { new OutputAttachmentDescription(PixelFormat.R32_G32_B32_A32_Float) };
            pipelineDescription.Outputs = new OutputDescription { 
                DepthAttachment = null, 
                SampleCount = TextureSampleCount.Count1,
                ColorAttachments = oads };

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

        
        public void DrawWidget()
        {
            TraceRecord activeTrace = ActiveTrace;
            if (activeTrace == null) return;
            if (IrregularTimerFired) HandleFrameTimerFired();

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos();
            subGraphPosition.X -= MarginWidth;

            float captionHeight = ImGui.CalcTextSize("123456789").Y + 3; //dunno where the 3 comes from but it works

            DrawnPreviewGraphs = activeTrace.GetPlottedGraphsList(mode: eRenderingMode.eStandardControlFlow);
            uint captionBackgroundcolor = new WritableRgbaFloat(Af:0.3f, Gf: 0, Bf:0, Rf:0).ToUint(); 
            
            for (var graphIdx = 0; graphIdx < DrawnPreviewGraphs.Count; graphIdx++)
            {
                PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                if (graph == null) continue;
                int graphNodeCount = graph.GraphNodeCount();
                if (graphNodeCount == 0) continue;

                if (graph != _rgatState.ActiveGraph && activeTrace == _rgatState.ActiveTrace)
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
                if (graph._previewTexture == null) continue;

                ImGui.SetCursorPosY(ImGui.GetCursorPosY());
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._previewTexture);
                imdp.AddImage(user_texture_id: CPUframeBufferTextureId,
                    p_min: subGraphPosition,
                    p_max: new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight), 
                    uv_min: new Vector2(0, 1), 
                    uv_max: new Vector2(1, 0));

                string Caption = $"TID:{graph.tid} {graphNodeCount}nodes {(graph.tid == selectedGraphTID ? "[Selected]" : "")}";

                ImGui.SetCursorPosX(ImGui.GetCursorPosX());
                imdp.AddRectFilled(p_min: new Vector2(ImGui.GetCursorScreenPos().X -3, ImGui.GetCursorScreenPos().Y),
                                   p_max: new Vector2(ImGui.GetCursorScreenPos().X + EachGraphWidth - MarginWidth, ImGui.GetCursorScreenPos().Y + 20), 
                                   col: captionBackgroundcolor);
                ImGui.Text(Caption);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - (float)(captionHeight));
                ImGui.SetCursorPosX(ImGui.GetCursorPosX());

                if (ImGui.InvisibleButton("PrevGraphBtn"+ graph.tid, new Vector2(EachGraphWidth, EachGraphHeight)))
                {
                    var MainGraphs = activeTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                    HandleClickedGraph(MainGraphs[graphIdx]);
                }

                subGraphPosition.Y += (EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING);
            }
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

        graphShaderParams updateShaderParams(uint textureSize)
        {
            graphShaderParams shaderParams = new graphShaderParams { TexWidth = textureSize, pickingNode = -1, isAnimated = false };

            float aspectRatio = EachGraphWidth / EachGraphHeight;
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(1.0f,  aspectRatio, 1, 50000);
            Vector3 translation = new Vector3(0, 0, -4000);
            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(translation);

            Matrix4x4 newView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
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

        void renderPreview(PlottedGraph graph, DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
        {
            if (graph == null || positionsBuffer == null || nodeAttributesBuffer == null) return;
            if (graph._previewTexture == null)
            {
                int width = UI_Constants.PREVIEW_PANE_WIDTH - (UI_Constants.PREVIEW_PANE_PADDING * 2);
                graph.InitPreviewTexture(new Vector2(width, UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT), _gd);
            }

            //rotval += 0.01f; //autorotate
            if (graph.PlotZRotation >= 360) graph.PlotZRotation = 0;
            var textureSize = graph.LinearIndexTextureSize();
            updateShaderParams(textureSize);

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



            TextureOffsetColour[] EdgeLineVerts  = graph.GetEdgeLineVerts(eRenderingMode.eStandardControlFlow, out List<uint> edgeDrawIndexes, out int edgeVertCount, out int drawnEdgeCount);

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

            _gd.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, positionsBuffer);
            _crs_core?.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, nodeAttributesBuffer, _NodeCircleSpritetview);
            _crs_nodesEdges?.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);

            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / 4));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / 4));

            //draw nodes and edges
            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(graph._previewFramebuffer);

            WritableRgbaFloat background = graph.internalProtoGraph.Terminated ? GlobalConfig.mainColours.terminatedPreview : GlobalConfig.mainColours.runningPreview;
            _cl.ClearColorTarget(0, background.ToRgbaFloat());
            _cl.SetViewport(0, new Viewport(0, 0, EachGraphWidth, EachGraphHeight, -2200, 1000));

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

            _cl.Dispose();
        }


    }
}
