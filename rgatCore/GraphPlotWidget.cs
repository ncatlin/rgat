using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Drawing;
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


		private Vector2 graphWidgetSize;

		public float dbg_FOV = 1.0f;
		public float dbg_near = 0.5f;
		public float dbg_far = 2000f;
		public float dbg_camX = 0f;
		public float dbg_camY = 65f;
		public float dbg_camZ = -200f;
		public float dbg_rot = 0;



		public GraphPlotWidget(rgatState clientState, Vector2? initialSize = null)
        {
			graphWidgetSize = initialSize ?? new Vector2(400, 400);
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


		public void Draw(Vector2 graphSize, ImGuiController _ImGuiController)
        {
			if (IrregularActionTimerFired) PerformIrregularActions();
			if (ActiveGraph == null || ActiveGraph.beingDeleted)
				return;

			_rgatState.ActiveGraph.UpdateGraphicBuffers(graphSize, _rgatState._GraphicsDevice);
			if (scheduledGraphResize)
			{
				double TimeSinceLastResize = (DateTime.Now - lastResize).TotalMilliseconds;
				if (TimeSinceLastResize > 150)
				{
					graphWidgetSize = graphSize;
					_rgatState.ActiveGraph.InitMainGraphTexture(graphWidgetSize, _rgatState._GraphicsDevice);
					scheduledGraphResize = false;
				}
			}
			//Can't find an event for in-imgui resize of childwindows so have to check on every render
			if (graphSize != graphWidgetSize && graphSize != lastResizeSize) AlertResized(graphSize);

			ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
			Vector2 pos = ImGui.GetCursorScreenPos();
			IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_rgatState._GraphicsDevice.ResourceFactory, _rgatState.ActiveGraph._outputTexture);
			imdp.AddImage(CPUframeBufferTextureId,
				pos,
				new Vector2(pos.X + _rgatState.ActiveGraph._outputTexture.Width, pos.Y + _rgatState.ActiveGraph._outputTexture.Height), new Vector2(0, 1), new Vector2(1, 0));


			//drawHUD();
		}

		private static long _startTime = System.DateTime.Now.Ticks;
		private static DeviceBuffer _worldBuffer;
		private static DeviceBuffer _projectionBuffer;
		private static DeviceBuffer _viewBuffer;
		private static Shader[] _shaders;


		private static Pipeline _wireframePipeline;
		private static VertexPositionColor[] _WireframeVertices;
		private static DeviceBuffer _WireframeVertexBuffer;
		private static DeviceBuffer _WireframeIndexBuffer;

		private static Pipeline _linesPipeline;
		private static VertexPositionColor[] _LineVertices;
		private static DeviceBuffer _LineVertexBuffer;
		private static DeviceBuffer _LineIndexBuffer;

		private static Pipeline _pointsPipeline;
		private static VertexPositionColor[] _PointVertices;
		private static DeviceBuffer _PointVertexBuffer;
		private static DeviceBuffer _PointIndexBuffer;

		private static ResourceSet _projViewSet;



		public static void InitWireframeVertexData(GraphicsDevice _gd, PlottedGraph graph)
		{

			if (!(graph.wireframelines.safe_get_vert_array(out _WireframeVertices)))
			{
				Console.WriteLine("Unhandled error 1");
			}


				Console.WriteLine($"Initing graph with {_WireframeVertices.Length} wireframe verts");

			ResourceFactory factory = _gd.ResourceFactory;

			if (_WireframeIndexBuffer != null)
			{
				_WireframeIndexBuffer.Dispose();
				_WireframeVertexBuffer.Dispose();
			}


			BufferDescription vbDescription = new BufferDescription(
				(uint)_WireframeVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
			_WireframeVertexBuffer = factory.CreateBuffer(vbDescription);
			_gd.UpdateBuffer(_WireframeVertexBuffer, 0, _WireframeVertices);

			List<ushort> wfIndices = Enumerable.Range(0, _WireframeVertices.Length)
				.Select(i => (ushort)i)
				.ToList();

			BufferDescription ibDescription = new BufferDescription((uint)wfIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
			_WireframeIndexBuffer = factory.CreateBuffer(ibDescription);
			_gd.UpdateBuffer(_WireframeIndexBuffer, 0, wfIndices.ToArray());
		}

		public static ulong InitLineVertexData(GraphicsDevice _gd, PlottedGraph graph, ulong lastBufsize)
		{

			if(!(graph.mainlinedata.safe_get_vert_array(out _LineVertices))){
				Console.WriteLine("Unhandled error 1");
            }

			Console.WriteLine($"Initing graph with {_LineVertices.Length} line verts");

			List<ushort> lineIndices = Enumerable.Range(0, _LineVertices.Length).Select(i => (ushort)i).ToList();
			ResourceFactory factory = _gd.ResourceFactory;
			uint bufferSize = (uint)_LineVertices.Length * VertexPositionColor.SizeInBytes;

			if (lastBufsize < (ulong)bufferSize)
			{
				if (_LineIndexBuffer != null)
				{
					_LineIndexBuffer.Dispose();
					_LineVertexBuffer.Dispose();
				}
				uint newVertBufSize = (uint)Math.Floor((uint)_LineVertices.Length * VertexPositionColor.SizeInBytes * 1.5);
				lastBufsize = newVertBufSize;
				BufferDescription vbDescription = new BufferDescription(newVertBufSize, BufferUsage.VertexBuffer);
				_LineVertexBuffer = factory.CreateBuffer(vbDescription);

				uint newIdxBufSize = (uint)Math.Floor((uint)lineIndices.Count * sizeof(ushort) * 1.5);
				BufferDescription ibDescription = new BufferDescription(newIdxBufSize, BufferUsage.IndexBuffer);
				_LineIndexBuffer = factory.CreateBuffer(ibDescription);
			}

			_gd.UpdateBuffer(_LineVertexBuffer, 0, _LineVertices);
			_gd.UpdateBuffer(_LineIndexBuffer, 0, lineIndices.ToArray());
			return lastBufsize;
		}

		ulong lastLineBufferSize = 0;
		ulong lastNodeBufferSize = 0;

		public static ulong InitNodeVertexData(GraphicsDevice _gd, PlottedGraph graph, ulong lastBufsize)
		{
			if (!(graph.mainnodesdata.safe_get_vert_array(out _PointVertices)))
			{
				Console.WriteLine("Unhandled error 1");
			}

			Console.WriteLine($"Initing graph with {_PointVertices.Length} node verts");


			ResourceFactory factory = _gd.ResourceFactory;
			uint bufferSize = (uint)_PointVertices.Length * VertexPositionColor.SizeInBytes;

			List<ushort> pointIndices = Enumerable.Range(0, _PointVertices.Length)
	.Select(i => (ushort)i)
	.ToList();

			/*
			 * 
			 * 
			TODO: can be much much more efficient here with option to just update new stuff
			*
			*
			*/

			if (lastBufsize < (ulong)bufferSize)
            {
				if (_PointIndexBuffer != null)
				{
					_PointIndexBuffer.Dispose();
					_PointVertexBuffer.Dispose();
				}
				uint newVertBufSize = (uint)Math.Floor((uint)_PointVertices.Length * VertexPositionColor.SizeInBytes * 1.5);
				BufferDescription vbDescription = new BufferDescription(newVertBufSize, BufferUsage.VertexBuffer);
				_PointVertexBuffer = factory.CreateBuffer(vbDescription);
				lastBufsize = newVertBufSize;
				Console.WriteLine($"Reiniting node very buffer to len {lastBufsize}");
				uint newIdxBufSize = (uint)Math.Floor((uint)pointIndices.Count * sizeof(ushort) * 1.5);
				BufferDescription ibDescription = new BufferDescription(newIdxBufSize, BufferUsage.IndexBuffer);
				_PointIndexBuffer = factory.CreateBuffer(ibDescription);
			}

			_gd.UpdateBuffer(_PointVertexBuffer, 0, _PointVertices);
			_gd.UpdateBuffer(_PointIndexBuffer, 0, pointIndices.ToArray());
			return lastBufsize;
		}


		private static ResourceLayout SetupProjectionBuffers(ResourceFactory factory)
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
			if (ActiveGraph == null) return;
			ActiveGraph.InitMainGraphTexture(graphWidgetSize, _gd);
			if (!inited1)
			{
				ResourceFactory factory = _gd.ResourceFactory;

				ShaderSetDescription shaderSetDesc = CreateGraphShaders(factory);

				//create data

				InitWireframeVertexData(_gd, ActiveGraph);
				lastLineBufferSize = InitLineVertexData(_gd, ActiveGraph, lastLineBufferSize);
				lastNodeBufferSize = InitNodeVertexData(_gd, ActiveGraph, lastNodeBufferSize);

				ResourceLayout projViewLayout = SetupProjectionBuffers(factory);


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

				pipelineDescription.Outputs = _rgatState.ActiveGraph._outputFramebuffer.OutputDescription; // _gd.SwapchainFramebuffer.OutputDescription;

				pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
				_wireframePipeline = factory.CreateGraphicsPipeline(pipelineDescription);
				

				pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineStrip;
				_linesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

				pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
				_pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

				inited1 = true;



				/*
				//preview test
				if (ActiveGraph.previewnodes.DataChanged)
				{
					ActiveGraph.previewnodes.SignalDataRead();
					InitNodeVertexData(_gd, ActiveGraph);
				}
				if (ActiveGraph.previewlines.DataChanged)
				{
					ActiveGraph.previewlines.SignalDataRead();
					InitLineVertexData(_gd, ActiveGraph);
				}
				*/



			}

			if (ActiveGraph.wireframelines.DataChanged)
			{
				ActiveGraph.wireframelines.SignalDataRead();
				InitWireframeVertexData(_gd, ActiveGraph);
			}

			ulong newBufSize = 0;
			if (ActiveGraph.mainnodesdata.DataChanged)
			{
				ActiveGraph.mainnodesdata.SignalDataRead();
				lastNodeBufferSize = InitNodeVertexData(_gd, ActiveGraph, lastNodeBufferSize);
			}
			if (ActiveGraph.mainlinedata.DataChanged)
			{
				ActiveGraph.mainlinedata.SignalDataRead();
				lastLineBufferSize = InitLineVertexData(_gd, ActiveGraph, lastLineBufferSize);
			}

			_cl.SetFramebuffer(_rgatState.ActiveGraph._outputFramebuffer);
			_cl.ClearColorTarget(0, RgbaFloat.Black);
			//_cl.ClearDepthStencil(1f);

			SetupView(_cl);
			DrawWireframe(_cl);
			DrawLines(_cl);
			DrawPoints(_cl);
		}


		private void SetupView(CommandList _cl)
		{


			_cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, 0, 200));
			_cl.UpdateBuffer(_projectionBuffer, 0, Matrix4x4.CreatePerspectiveFieldOfView(dbg_FOV, (float)graphWidgetSize.X / graphWidgetSize.Y, dbg_near, dbg_far));

			Vector3 cameraPosition = new Vector3(dbg_camX,dbg_camY,dbg_camZ);
			//_cl.UpdateBuffer(_viewBuffer, 0, Matrix4x4.CreateLookAt(new Vector3(0,0,-200), new Vector3(0, 0, 0), Vector3.UnitY));
			_cl.UpdateBuffer(_viewBuffer, 0, Matrix4x4.CreateTranslation(cameraPosition));

			//if autorotation...
			float _ticks = (System.DateTime.Now.Ticks - _startTime) / (1000f);
			float angle = _ticks / 10000;
			//else
			angle = dbg_rot;

			Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
			_cl.UpdateBuffer(_worldBuffer, 0, ref rotation);
		}


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
