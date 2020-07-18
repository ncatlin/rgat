using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Timers;
using Veldrid;
using Veldrid.SPIRV;

namespace rgatCore
{
    class PreviewGraphsWidget
    {
        List<PlottedGraph> DrawnGraphs = new List<PlottedGraph>();
        static rgatState _rgatState = null;
        private bool inited1 = false;

        System.Timers.Timer FrameTimer;
        bool FrameTimerFired = false;


        private Vector2 graphWidgetSize;

        public float dbg_FOV = 1.0f;//1.0f;
        public float dbg_near = 0.5f;
        public float dbg_far = 8000f;
        public float dbg_camX = 0f;
        public float dbg_camY = 65f;
        public float dbg_camZ = -800f;
        public float dbg_rot = 0;

        public float EachGraphWidth = UI_Constants.PREVIEW_PANE_WIDTH - (2 * UI_Constants.PREVIEW_PANE_PADDING);
        public float EachGraphHeight = UI_Constants.PREVIEW_PANE_GRAPH_HEIGHT;
        public float MarginWidth = 5f;


        public PreviewGraphsWidget(rgatState clientState)
        {
            _rgatState = clientState;
            FrameTimer = new System.Timers.Timer(600);
            FrameTimer.Elapsed += FireFrameTimer;
            FrameTimer.AutoReset = true;
            FrameTimer.Start();

        }
        private void FireFrameTimer(object sender, ElapsedEventArgs e) { FrameTimerFired = true; }

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


        public void Draw(Vector2 widgetSize, ImGuiController _ImGuiController)
        {
            //if (FrameTimerFired) Update();

            if (_rgatState.ActiveTrace == null)
                return;
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 pos = ImGui.GetCursorScreenPos();
            pos.X += MarginWidth;
            float captionHeight = ImGui.CalcTextSize("123456789").Y;
            DrawnGraphs = _rgatState.ActiveTrace.GetPlottedGraphsList();
            foreach (PlottedGraph graph in DrawnGraphs)
            {
                if (graph.previewnodes.CountVerts() == 0 || graph._previewTexture == null) continue;
                ImGui.Text($"TID:{graph.tid} {graph.previewnodes.CountVerts()}vts");
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_rgatState._GraphicsDevice.ResourceFactory, graph._previewTexture);
                imdp.AddImage(CPUframeBufferTextureId,
                    pos,
                    new Vector2(pos.X + EachGraphWidth, pos.Y + EachGraphHeight), new Vector2(0, 1), new Vector2(1, 0));

                int cursorGap = (int)(EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING - captionHeight + 4f); //ideally want to draw the text in the texture itself

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + cursorGap);
                pos.Y += (EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING);
            }

            //drawHUD();
        }

        private static long _startTime = System.DateTime.Now.Ticks;

        private static Shader[] _shaders;

        /*
		private static Pipeline _wireframePipeline;
		private static VertexPositionColor[] _WireframeVertices;
		private static DeviceBuffer _WireframeVertexBuffer;
		private static DeviceBuffer _WireframeIndexBuffer;
		*/

        Dictionary<uint, GraphRenderObject> graphicInfos = new Dictionary<uint, GraphRenderObject>();

        //TODO: move a bunch of the functionality into this class, maybe use it from maingraph widget too
        private class GraphRenderObject
        {
            public GraphRenderObject(PlottedGraph _graph) => graph = _graph;

            PlottedGraph graph;
            public  Pipeline _linesPipeline;
            public VertexPositionColor[] _LineVertices;
            public DeviceBuffer _LineVertexBuffer;
            public DeviceBuffer _LineIndexBuffer;

            public Pipeline _pointsPipeline;
            public VertexPositionColor[] _PointVertices;
            public DeviceBuffer _PointVertexBuffer;
            public DeviceBuffer _PointIndexBuffer;

            public ResourceSet _projViewSet;

            public DeviceBuffer _worldBuffer;
            public DeviceBuffer _projectionBuffer;
            public DeviceBuffer _viewBuffer;

            public void InitLineVertexData(GraphicsDevice _gd)
            {

                if (!(graph.previewlines.safe_get_vert_array(out _LineVertices)))
                {
                    Console.WriteLine("Unhandled error 1");
                }

                Console.WriteLine($"Initing graph with {_LineVertices.Length} line verts");

                ResourceFactory factory = _gd.ResourceFactory;
                if (_LineIndexBuffer != null)
                {
                    _LineIndexBuffer.Dispose();                 
                    _LineVertexBuffer.Dispose();
                }

                BufferDescription vbDescription = new BufferDescription(
                    (uint)_LineVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
                _LineVertexBuffer = factory.CreateBuffer(vbDescription);
                _gd.UpdateBuffer(_LineVertexBuffer, 0, _LineVertices);


                List<ushort> lineIndices = Enumerable.Range(0, _LineVertices.Length)
                    .Select(i => (ushort)i)
                    .ToList();

                BufferDescription ibDescription = new BufferDescription((uint)lineIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
                _LineIndexBuffer = factory.CreateBuffer(ibDescription);
                _gd.UpdateBuffer(_LineIndexBuffer, 0, lineIndices.ToArray());
            }

            public ResourceLayout SetupProjectionBuffers(ResourceFactory factory)
            {
                ResourceLayoutElementDescription pb = new ResourceLayoutElementDescription("ProjectionBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
                ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("ViewBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
                ResourceLayoutElementDescription wb = new ResourceLayoutElementDescription("WorldBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
                ResourceLayout projViewLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(pb, vb, wb));
                _worldBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
                _projectionBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
                _viewBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
                _projViewSet = factory.CreateResourceSet(new ResourceSetDescription(projViewLayout, _projectionBuffer, _viewBuffer, _worldBuffer));
                return projViewLayout;
            }





            public void DrawLines(CommandList _cl)
            {
                _cl.SetVertexBuffer(0, _LineVertexBuffer);
                _cl.SetIndexBuffer(_LineIndexBuffer, IndexFormat.UInt16);
                _cl.SetPipeline(_linesPipeline);
                _cl.SetGraphicsResourceSet(0, _projViewSet);
                _cl.DrawIndexed(
                    indexCount: (uint)_LineVertices.Length,
                    instanceCount: 1,
                    indexStart: 0,
                    vertexOffset: 0,
                    instanceStart: 0);
            }

            public void DrawPoints(CommandList _cl)
            {
                _cl.SetVertexBuffer(0, _PointVertexBuffer);
                _cl.SetIndexBuffer(_PointIndexBuffer, IndexFormat.UInt16);
                _cl.SetPipeline(_pointsPipeline);
                _cl.SetGraphicsResourceSet(0, _projViewSet);
                _cl.DrawIndexed(
                    indexCount: (uint)_PointVertices.Length,
                    instanceCount: 1,
                    indexStart: 0,
                    vertexOffset: 0,
                    instanceStart: 0);
            }
        }





        static void InitNodeVertexData(GraphicsDevice _gd, PlottedGraph graph, GraphRenderObject renderInfo)
        {

            if (!(graph.previewnodes.safe_get_vert_array(out renderInfo._PointVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }
            Console.WriteLine($"Initing graph with {renderInfo._PointVertices.Length} node verts");


            ResourceFactory factory = _gd.ResourceFactory;
            uint bufferSize = (uint)renderInfo._PointVertices.Length * VertexPositionColor.SizeInBytes;
            /*
			 * 
			 * 
			TODO: can be much much more efficient here with option to just update new stuff
			*
			*
			*/

            if (renderInfo._PointIndexBuffer != null)
            {
                renderInfo._PointIndexBuffer.Dispose();
                renderInfo._PointVertexBuffer.Dispose();
            }
            BufferDescription vbDescription = new BufferDescription(bufferSize, BufferUsage.VertexBuffer);
            renderInfo._PointVertexBuffer = factory.CreateBuffer(vbDescription);

            _gd.UpdateBuffer(renderInfo._PointVertexBuffer, 0, renderInfo._PointVertices);

            List<ushort> pointIndices = Enumerable.Range(0, renderInfo._PointVertices.Length)
                .Select(i => (ushort)i)
                .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)pointIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            renderInfo._PointIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(renderInfo._PointIndexBuffer, 0, pointIndices.ToArray());
        }



        private void SetupView(CommandList _cl, GraphRenderObject graphRenderInfo)
        {

            _cl.SetViewport(0, new Viewport(0, 0, EachGraphWidth, EachGraphHeight, 0, 200));
            _cl.UpdateBuffer(graphRenderInfo._projectionBuffer, 0, Matrix4x4.CreatePerspectiveFieldOfView(dbg_FOV, (float)EachGraphWidth / EachGraphHeight, dbg_near, dbg_far));

            Vector3 cameraPosition = new Vector3(dbg_camX, dbg_camY, dbg_camZ);
            //_cl.UpdateBuffer(_viewBuffer, 0, Matrix4x4.CreateLookAt(Vector3.UnitZ*7, cameraPosition, Vector3.UnitY));
            _cl.UpdateBuffer(graphRenderInfo._viewBuffer, 0, Matrix4x4.CreateTranslation(cameraPosition));

            //if autorotation...
            float _ticks = (System.DateTime.Now.Ticks - _startTime) / (1000f);
            float angle = _ticks / 10000;
            //else
            //angle = dbg_rot;

            Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
            _cl.UpdateBuffer(graphRenderInfo._worldBuffer, 0, ref rotation);
        }

        private static ShaderSetDescription CreateGraphShaders(ResourceFactory factory)
        {

            //create shaders
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(VertexCode), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(FragmentCode), "main");

            _shaders = factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc);
            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
            vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
            shaders: _shaders);

            return shaderSetDesc;
        }


        public void AddGraphicsCommands(CommandList _cl, GraphicsDevice _gd)
        {
            foreach (PlottedGraph graph in DrawnGraphs)
            {
                if (graph == null) continue;
                if (graph.previewlines.CountRenderedEdges == 0 || graph.previewnodes.CountVerts() == 0) continue;

                if (graph._previewTexture == null)
                {

                    graph.UpdatePreviewBuffers(_rgatState._GraphicsDevice);
                }

                GraphRenderObject graphRenderInfo = null;
                if (!graphicInfos.TryGetValue(graph.tid, out graphRenderInfo))
                {
                    graphicInfos.Add(graph.tid, new GraphRenderObject(graph));
                    graphRenderInfo = graphicInfos[graph.tid];

                    ResourceFactory factory = _gd.ResourceFactory;
                    ShaderSetDescription shaderSetDesc = CreateGraphShaders(factory);
                    ResourceLayout projViewLayout = graphRenderInfo.SetupProjectionBuffers(factory);


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
                    pipelineDescription.ResourceLayouts = new[] { projViewLayout };
                    pipelineDescription.ShaderSet = shaderSetDesc;

                    pipelineDescription.Outputs = graph._previewFramebuffer.OutputDescription;

                    pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineStrip;
                    graphRenderInfo._linesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

                    pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
                    graphRenderInfo._pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);
                }


                if (graph.previewnodes.DataChanged)
                {
                    graph.previewnodes.SignalDataRead();
                    InitNodeVertexData(_gd, graph, graphRenderInfo);
                }
                if (graph.previewlines.DataChanged)
                {
                    graph.previewlines.SignalDataRead();
                    graphRenderInfo.InitLineVertexData(_gd);
                }


                _cl.SetFramebuffer(graph._previewFramebuffer);
                _cl.ClearColorTarget(0, new RgbaFloat(1, 0, 0, 0.1f));
                //_cl.ClearDepthStencil(1f);
                SetupView(_cl, graphRenderInfo);
                graphRenderInfo.DrawLines(_cl);
                graphRenderInfo.DrawPoints(_cl);
            }
        }


        /*
		private void DrawWireframe(CommandList _cl)
		{
			_cl.SetVertexBuffer(0, _WireframeVertexBuffer);
			_cl.SetIndexBuffer(_WireframeIndexBuffer, IndexFormat.UInt16);
			_cl.SetPipeline(_wireframePipeline);
			_cl.SetGraphicsResourceSet(0, _projViewSet);
			_cl.DrawIndexed(
				indexCount: (uint)_WireframeVertices.Length,
				instanceCount: 1,
				indexStart: 0,
				vertexOffset: 0,
				instanceStart: 0);

		}
		*/










        private const string VertexCode = @"
#version 450

layout(location = 0) in vec3 Position;
layout(location = 1) in vec4 Color;

layout(set = 0, binding = 0) uniform ProjectionBuffer
{
    mat4 Projection;
};

layout(set = 0, binding = 1) uniform ViewBuffer
{
    mat4 View;
};

layout(set = 0, binding = 2) uniform WorldBuffer
{
    mat4 Rotation;
};


layout(location = 0) out vec4 fsin_Color;

void main()
{


    vec4 worldPosition = Rotation * vec4(Position,1);
    vec4 viewPosition = View * worldPosition;
    vec4 clipPosition = Projection * viewPosition;

    gl_PointSize = 3.0f;
    gl_Position =clipPosition;
    fsin_Color = Color;
}";

        private const string FragmentCode = @"
#version 450

layout(location = 0) in vec4 fsin_Color;
layout(location = 0) out vec4 fsout_Color;

void main()
{
    fsout_Color = fsin_Color;
}";







        bool setMouseoverNode()
        {
            /*
			float zmul = ActiveGraph.zoomMultiplier();
			if (!_rgatState.should_show_external_symbols(zmul) && !_rgatState.should_show_internal_symbols(zmul))
				return false;

			//mouse still over same node?
			if (activeMouseoverNode && mouseoverNodeRect.rect.contains(mousePos.x(), mousePos.y()))
			{
				node_data* nodeptr = ActiveGraph.get_protoGraph()->safe_get_node(mouseoverNode());
				if (nodeptr->external)
					return _rgatState.should_show_external_symbols(zmul);
				else
					return _rgatState.should_show_internal_symbols(zmul);
			}

			//mouse over any node?
			for each(TEXTRECT nodelabel in ActiveGraph.labelPositions)
			{
				if (nodelabel.rect.contains(mousePos.x(), mousePos.y()))
				{
					node_data* nodeptr = ActiveGraph.get_protoGraph()->safe_get_node(nodelabel.index);
					if (nodeptr->external)
					{
						if (!_rgatState.should_show_external_symbols(zmul))
							return false;
					}
					else
					{
						if (!_rgatState.should_show_internal_symbols(zmul))
							return false;
					}

					mouseoverNodeRect = nodelabel;
					activeMouseoverNode = true;
					return false;
				}
			}

			activeMouseoverNode = false;
			*/
            return false;
        }
    }
}
