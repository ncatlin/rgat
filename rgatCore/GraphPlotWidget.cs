using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Veldrid;
using Veldrid.SPIRV;

namespace rgatCore
{
    class GraphPlotWidget
    {
        PlottedGraph ActiveGraph = null;
		static rgatState _rgatState = null;
		private bool inited1 = false;

		Dictionary<TraceRecord, PlottedGraph> LastGraphs = new Dictionary<TraceRecord, PlottedGraph>();
		Dictionary<TraceRecord, uint> LastSelectedTheads = new Dictionary<TraceRecord, uint>();
		System.Timers.Timer IrregularActionTimer;
		bool IrregularActionTimerFired = false;


		private Vector2 graphWidgetSize = new Vector2(400, 400);

		public GraphPlotWidget(rgatState clientState)
        {

			_rgatState = clientState;
			IrregularActionTimer = new System.Timers.Timer(600);
			IrregularActionTimer.Elapsed += FireIrregularTimer;
			IrregularActionTimer.AutoReset = true;
			IrregularActionTimer.Start();

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


		public void Draw(Vector2 size, ImGuiController _ImGuiController)
        {
			if (IrregularActionTimerFired) PerformIrregularActions();
			if (ActiveGraph == null || ActiveGraph.beingDeleted)
				return;

			_rgatState.ActiveGraph.UpdateGraphicBuffers(size, _rgatState._GraphicsDevice);
			if (scheduledGraphResize)
			{
				double TimeSinceLastResize = (DateTime.Now - lastResize).TotalMilliseconds;
				if (TimeSinceLastResize > 150)
				{
					graphWidgetSize = new Vector2(400, 400);
					_rgatState.ActiveGraph.InitMainGraphTexture(graphWidgetSize, _rgatState._GraphicsDevice);
					scheduledGraphResize = false;
				}
			}
			//Can't find an event for in-imgui resize of childwindows so have to check on every render
			if (size != graphWidgetSize && size != lastResizeSize) AlertResized(size);

			ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
			Vector2 pos = ImGui.GetCursorScreenPos();
			IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_rgatState._GraphicsDevice.ResourceFactory, _rgatState.ActiveGraph._outputTexture);
			imdp.AddImage(CPUframeBufferTextureId,
				new Vector2(0, 0),
				new Vector2(pos.X + graphWidgetSize.X, pos.Y + graphWidgetSize.Y), new Vector2(0, 1), new Vector2(1, 0));


			//drawHUD();
		}

		private static long _startTime = System.DateTime.Now.Ticks;
		private static DeviceBuffer _worldBuffer;
		private static DeviceBuffer _projectionBuffer;
		private static DeviceBuffer _viewBuffer;
		private static Shader[] _shaders;
		private static Pipeline _linesPipeline;
		private static Pipeline _pointsPipeline;
		private static VertexPositionColor[] _LineVertices;
		private static VertexPositionColor[] _PointVertices;
		private static DeviceBuffer _LineVertexBuffer;
		private static DeviceBuffer _LineIndexBuffer;
		private static DeviceBuffer _PointVertexBuffer;
		private static DeviceBuffer _PointIndexBuffer;
		private static ResourceSet _projViewSet;
		private static Framebuffer _outputFramebuffer = null;





		public void InitLineVertexData(GraphicsDevice _gd)
		{
			VertexPositionColor[] _lineVertices = {
				new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Red),
				new VertexPositionColor(new Vector3(.75f, .75f, -.25f), RgbaFloat.Green),
				new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Blue),
				new VertexPositionColor(new Vector3(.75f, -.75f, 0f), RgbaFloat.Yellow),
				new VertexPositionColor(new Vector3(-.75f, .75f, -0.75f), RgbaFloat.White),
				new VertexPositionColor(new Vector3(-1.75f, 0f, -0.75f), RgbaFloat.Pink),
				new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Grey)
			};
			_LineVertices = _lineVertices;

			ResourceFactory factory = _gd.ResourceFactory;
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

		public void InitNodeVertexData(GraphicsDevice _gd)
		{

			VertexPositionColor[] _pointVertices = {
				new VertexPositionColor(new Vector3(-.75f, .75f, -.25f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(.75f, .75f, -.25f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(.75f, -.75f, 0f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(-.75f, .75f, -0.75f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(-1.75f, 0f, -0.75f), RgbaFloat.Cyan),
				new VertexPositionColor(new Vector3(-.75f, -.75f, 0f), RgbaFloat.Cyan)
			};
			_PointVertices = _pointVertices;


			ResourceFactory factory = _gd.ResourceFactory;
			uint bufferSize = (uint)_PointVertices.Length * VertexPositionColor.SizeInBytes;
			BufferDescription vbDescription = new BufferDescription(bufferSize, BufferUsage.VertexBuffer);
			_PointVertexBuffer = factory.CreateBuffer(vbDescription);
			_gd.UpdateBuffer(_PointVertexBuffer, 0, _PointVertices);

			List<ushort> pointIndices = Enumerable.Range(0, _PointVertices.Length)
				.Select(i => (ushort)i)
				.ToList();

			BufferDescription ibDescription = new BufferDescription((uint)pointIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
			_PointIndexBuffer = factory.CreateBuffer(ibDescription);
			_gd.UpdateBuffer(_PointIndexBuffer, 0, pointIndices.ToArray());
		}


		private ResourceLayout SetupProjectionBuffers(ResourceFactory factory)
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

		private ShaderSetDescription CreateGraphShaders(ResourceFactory factory)
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
			if (ActiveGraph == null) return;
			ActiveGraph.InitMainGraphTexture(graphWidgetSize, _gd);
			if (!inited1)
			{
				ResourceFactory factory = _gd.ResourceFactory;

				ShaderSetDescription shaderSetDesc = CreateGraphShaders(factory);

				//create data
				InitLineVertexData(_gd);
				InitNodeVertexData(_gd);

				ResourceLayout projViewLayout = SetupProjectionBuffers(factory);


				// Create pipelines
				GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
				pipelineDescription.BlendState = BlendStateDescription.SingleOverrideBlend;
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

				pipelineDescription.Outputs = _rgatState.ActiveGraph._outputFramebuffer.OutputDescription; // _gd.SwapchainFramebuffer.OutputDescription;

				pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineStrip;
				_linesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

				pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
				_pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);
				inited1 = true;
			}


			_cl.SetFramebuffer(_rgatState.ActiveGraph._outputFramebuffer);
			_cl.ClearColorTarget(0, RgbaFloat.Black);
			//_cl.ClearDepthStencil(1f);
			SetupView(_cl);
			DrawLines(_cl);
			DrawPoints(_cl);
		}


		private void SetupView(CommandList _cl)
		{
			float _ticks = (System.DateTime.Now.Ticks - _startTime) / (1000f);
			float angle = _ticks / 10000;

			_cl.UpdateBuffer(_projectionBuffer, 0, Matrix4x4.CreatePerspectiveFieldOfView(1.0f, (float)graphWidgetSize.X / graphWidgetSize.Y, 0.5f, 100f));

			_cl.UpdateBuffer(_viewBuffer, 0, Matrix4x4.CreateLookAt(Vector3.UnitZ * (7), Vector3.Zero, Vector3.UnitY));

			Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
			_cl.UpdateBuffer(_worldBuffer, 0, ref rotation);
		}

		private void DrawLines(CommandList _cl)
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

		private void DrawPoints(CommandList _cl)
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


    //gl_Position = vec4(Position,1);
    //gl_Position *= Rotation;
    //gl_Position *= View;
    //gl_Position *=  Projection ;

    gl_PointSize = 5.0f;
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

		struct VertexPositionColor
		{
			public const uint SizeInBytes = 28;
			public Vector3 Position;
			public RgbaFloat Color;
			public VertexPositionColor(Vector3 position, RgbaFloat color)
			{
				Position = position;
				Color = color;
			}
		}





		bool setMouseoverNode()
        {
			if (ActiveGraph == null)
				return false;
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



		private void PerformIrregularActions()
        {
            bool haveDisplayGraph = chooseGraphToDisplay();
            if (!haveDisplayGraph)
                return;

            if (ActiveGraph.replayState == PlottedGraph.REPLAY_STATE.ePlaying)
            {
                //ui->replaySlider->setValue(1000 * ActiveGraph.getAnimationPercent());
            }

            if (ActiveGraph.replayState == PlottedGraph.REPLAY_STATE.eEnded)
            {
                //ui->dynamicAnalysisContentsTab->stopAnimation();
            }

            if (!setMouseoverNode())
            {
                //_rgatState.labelMouseoverWidget->hide();
            }
        }

		void SwitchToGraph(PlottedGraph graph)
		{
			//valid target or not, we assume current graph is no longer fashionable
			_rgatState.ClearActiveGraph();

			if (graph == null || graph.NeedReplotting || graph.beingDeleted) return;

			TraceRecord trace = _rgatState.ActiveTrace;
			if (trace == null) return;

			if (_rgatState.SetActiveGraph(graph))
			{
				LastGraphs[trace] = graph;
				LastSelectedTheads[trace] = graph.tid;
			}

			//setGraphUIControls(graph);
		}

		bool chooseGraphToDisplay()
		{
			if (_rgatState.SwitchTrace != null)
			{
				_rgatState.SelectActiveTrace(_rgatState.SwitchTrace);
				_rgatState.SwitchTrace = null;
				//ui->dynamicAnalysisContentsTab->updateVisualiserUI(true);
			}

			PlottedGraph switchGraph = _rgatState.SwitchGraph;
			if (_rgatState.SwitchGraph != null && switchGraph.beingDeleted && !switchGraph.NeedReplotting)
			{
				SwitchToGraph(switchGraph);
				_rgatState.SwitchGraph = null;
			}

			if (ActiveGraph != null)
			{
				if (ActiveGraph.beingDeleted || (ActiveGraph != _rgatState.getActiveGraph(false)))
				{
					//ActiveGraph.decrease_thread_references(141);
					ActiveGraph = null;
					return false;
				}

				return true;
			}

			ActiveGraph = _rgatState.getActiveGraph(true);
			if (ActiveGraph == null && !_rgatState.WaitingForNewTrace)
			{
				if (_rgatState.ActiveTrace != null)
					_rgatState.SelectActiveTrace();


				selectGraphInActiveTrace();
			}


			return (ActiveGraph != null);

		}

		//activate a graph in the active trace
		//selects the last one that was active in this trace, or the first seen
		void selectGraphInActiveTrace()
		{
			TraceRecord selectedTrace = _rgatState.ActiveTrace;
			if (selectedTrace == null) return;

			if(LastGraphs.TryGetValue(selectedTrace, out PlottedGraph foundGraph))
			{
				bool found = false;
				List<PlottedGraph> traceGraphs = selectedTrace.GetPlottedGraphsList();
				if (traceGraphs.Contains(foundGraph))
                {
					SwitchToGraph(foundGraph);
					found = true;
				}
				else
				{
					uint lastTID = LastSelectedTheads[selectedTrace];
					PlottedGraph lastgraph = traceGraphs.Find(pg => pg.tid == lastTID);
					if (lastgraph != null)
                    {
						SwitchToGraph(lastgraph);
						found = true;
					}
				}

				//foreach (graph, traceGraphs){ graph->decrease_thread_references(144); }
				if (found) return;
			}

			PlottedGraph firstgraph = selectedTrace.GetFirstGraph();
			if (firstgraph != null)
			{
				Console.WriteLine("Got first graph "+firstgraph.tid);
				SwitchToGraph(firstgraph);
				//firstgraph->decrease_thread_references(33);
			}
		}

	}
}
