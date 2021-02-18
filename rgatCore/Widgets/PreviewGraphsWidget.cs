﻿using ImGuiNET;
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
        DeviceBuffer _paramsBuffer;

        GraphLayoutEngine _layoutEngine;
        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout;
        ResourceSet _crs_core, _crs_nodesEdges;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodeIndexBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;
        Pipeline _edgesPipeline, _pointsPipeline;



        public PreviewGraphsWidget(ImGuiController controller, GraphicsDevice gdev)
        {
            IrregularTimer = new System.Timers.Timer(600);
            IrregularTimer.Elapsed += FireTimer;
            IrregularTimer.AutoReset = true;
            IrregularTimer.Start();
            _ImGuiController = controller;
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _layoutEngine = new GraphLayoutEngine(gdev, controller);
            SetupRenderingResources();
        }

        private void FireTimer(object sender, ElapsedEventArgs e) { IrregularTimerFired = true; }

        public void SetActiveTrace(TraceRecord trace) => ActiveTrace = trace;

        public void SetSelectedGraph(PlottedGraph graph) => selectedGraphTID = graph.tid;

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
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

        }

        /*
         * Fetched pre-prepared device buffer from layout engine if it is in the working set
         * Otherwise creates a new one from the stored data in the plottedgraph
         * 
         * Returns True if the devicebuffer can be destroyed, or False if the Layoutengine is using it
         */
        //todo - a secondary cache of devicebuffers for inactive graphs?
        public bool FetchNodeBuffers(PlottedGraph graph, out DeviceBuffer posBuffer, out DeviceBuffer attribBuffer)
        {
            DeviceBuffer positionsBuffer = _layoutEngine.GetPositionsBuffer(graph);
            DeviceBuffer attribsBuffer = _layoutEngine.GetPositionsBuffer(graph);
            if (positionsBuffer != null && attribsBuffer != null)
            {
                posBuffer = positionsBuffer;
                attribBuffer = attribsBuffer;
                return false;
            }
            else
            {
                posBuffer = CreateFloatsDeviceBuffer(graph.GetPositionFloats(), _gd);
                attribBuffer = CreateFloatsDeviceBuffer(graph.GetNodeAttribFloats(), _gd);
                return true;
            }
        }


        public void Draw(Vector2 widgetSize, ImGuiController _ImGuiController, GraphicsDevice _gd)
        {
            if (ActiveTrace == null) return;
            if (IrregularTimerFired) HandleFrameTimerFired();

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos();
            subGraphPosition.X += MarginWidth;

            float captionHeight = ImGui.CalcTextSize("123456789").Y + 3; //dunno where the 3 comes from but it works

            DrawnPreviewGraphs = ActiveTrace.GetPlottedGraphsList(mode: eRenderingMode.eStandardControlFlow);
            uint backgroundcolor = GlobalConfig.mainColours.background.ToUint(customAlpha: 180);
            for (var graphIdx = 0; graphIdx < 5; graphIdx++)
            {
                PlottedGraph graph = DrawnPreviewGraphs[0];

                //for (var graphIdx = 0; graphIdx < DrawnPreviewGraphs.Count; graphIdx++)
                //{
                //PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                if (graph == null) continue;

                FetchNodeBuffers(graph, out DeviceBuffer positionBuf, out DeviceBuffer attribBuf);

                renderPreview(graph, positionBuf, attribBuf);
                if (graph._previewTexture == null) continue;

                ImGui.SetCursorPosY(ImGui.GetCursorPosY());
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._previewTexture);
                imdp.AddImage(CPUframeBufferTextureId,
                    subGraphPosition,
                    new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight), 
                    new Vector2(0, 1), 
                    new Vector2(1, 0));

                string Caption = $"TID:{graph.tid} {graph.GraphNodeCount()}vts {(graph.tid == selectedGraphTID ? "[Selected]" : "")}";
                float captionWidth = ImGui.CalcTextSize(Caption).X + 3.0f; //dunno where the 3 comes from but it works

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 8);
                imdp.AddRectFilled(ImGui.GetCursorScreenPos(),
                    new Vector2(ImGui.GetCursorScreenPos().X + captionWidth, ImGui.GetCursorScreenPos().Y + 20), backgroundcolor);
                ImGui.Text(Caption);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - (float)(captionHeight));
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() - 8);

                if (ImGui.InvisibleButton("PrevGraphBtn"+ graph.tid, new Vector2(EachGraphWidth, EachGraphHeight)))
                {
                    var MainGraphs = ActiveTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                    HandleClickedGraph(MainGraphs[graphIdx]);
                }

                subGraphPosition.Y += (EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING);
                //subGraphPosition.Y -= captionHeight;// * graphIdx;
            }
        }


        private static long _startTime = System.DateTime.Now.Ticks;
        private void SetupView(CommandList _cl, VeldridGraphBuffers graphRenderInfo, PlottedGraph graph)
        {

            _cl.SetViewport(0, new Viewport(0, 0, EachGraphWidth, EachGraphHeight, 0, 200));

            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(dbg_FOV, (float)EachGraphWidth / EachGraphHeight, dbg_near, dbg_far);
            Vector3 cameraPosition = new Vector3(dbg_camX, dbg_camY, (-1 * graph.scalefactors.plotSize) - dbg_camZ);
            Matrix4x4 view = Matrix4x4.CreateTranslation(cameraPosition);

            //if autorotation...
            float _ticks = (System.DateTime.Now.Ticks - _startTime) / (1000f);
            float angle = _ticks / 10000;
            Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
            Matrix4x4 newView = rotation;
            newView = Matrix4x4.Multiply(newView, view);
            newView = Matrix4x4.Multiply(newView, projection);

            _cl.UpdateBuffer(graphRenderInfo._viewBuffer, 0, newView);
        }


        /*

        public void AddGraphicsCommands(CommandList _cl, GraphicsDevice _gd)
        {
            foreach (PlottedGraph graph in DrawnPreviewGraphs)
            {
                if (graph == null) continue;
                if (graph.EdgesDisplayData.CountRenderedEdges == 0) continue;

                if (graph._previewTexture == null)
                {
                    graph.UpdatePreviewBuffers(_gd);
                }

                VeldridGraphBuffers graphRenderInfo = null;
                if (!graphicInfos.TryGetValue(graph.tid, out graphRenderInfo))
                {
                    graphicInfos.Add(graph.tid, new VeldridGraphBuffers());
                    graphRenderInfo = graphicInfos[graph.tid];

                    graphRenderInfo.InitPipelines(_gd, CreateGraphShaders(_gd.ResourceFactory), graph._previewFramebuffer);
                }


                _cl.SetFramebuffer(graph._previewFramebuffer);
                RgbaFloat graphBackground = graph.internalProtoGraph.Terminated ?
                    new RgbaFloat(0.5f, 0, 0, 0.2f) :
                    new RgbaFloat(0, 0.5f, 0, 0.2f);

                _cl.ClearColorTarget(0, graphBackground);

                SetupView(_cl, graphRenderInfo, graph);
                graphRenderInfo.DrawEdges(_cl, _gd, graph.EdgesDisplayData);
                graphRenderInfo.DrawPoints(_cl, _gd, graph.NodesDisplayData);
            }
        }
        */



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

        public void renderPreview(PlottedGraph graph, DeviceBuffer positionsBuffer, DeviceBuffer nodeAttributesBuffer)
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

            VertexPositionColor[] NodeVerts = graph.GetNodeVerts(out List<uint> nodeIndices);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * VertexPositionColor.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)NodeVerts.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
                _NodeVertexBuffer.Dispose();
                _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);

                BufferDescription ibDescription = new BufferDescription((uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _NodeIndexBuffer.Dispose();
                _NodeIndexBuffer = _factory.CreateBuffer(ibDescription);
            }

            _gd.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());



            int drawnEdgeCount = graph.GetEdgeLineVerts(out List<uint> edgeDrawIndexes, out int edgeVertCount, out VertexPositionColor[] EdgeLineVerts);

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
            _cl.ClearColorTarget(0, GlobalConfig.mainColours.background.ToRgbaFloat());
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
