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
		private bool inited1 = false;


		System.Timers.Timer IrregularActionTimer;
		bool IrregularActionTimerFired = false;

		Dictionary<PlottedGraph, VeldridGraphBuffers> graphBufferDict = new Dictionary<PlottedGraph, VeldridGraphBuffers>();
		VeldridGraphBuffers graphBuffers = null;



		private Vector2 graphWidgetSize;

		public float dbg_FOV = 1.0f;
		public float dbg_near = 0.5f;
		public float dbg_far = 2000f;
		public float dbg_camX = 0f;
		public float dbg_camY = 65f;
		public float dbg_camZ = -200f;
		public float dbg_rot = 0;



		public GraphPlotWidget(Vector2? initialSize = null)
        {
			graphWidgetSize = initialSize ?? new Vector2(400, 400);
			IrregularActionTimer = new System.Timers.Timer(600);
			IrregularActionTimer.Elapsed += FireIrregularTimer;
			IrregularActionTimer.AutoReset = true;
			IrregularActionTimer.Start();

		}

		public void SetActiveGraph(PlottedGraph graph, GraphicsDevice _gd) 
		{
			if (graph == null) {
				ActiveGraph = graph; 
				return;
			}
			
			if (!graphBufferDict.TryGetValue(graph, out graphBuffers))
            {
				graphBuffers = new VeldridGraphBuffers(graph);
				graphBufferDict.Add(graph, graphBuffers);
				ResourceFactory factory = _gd.ResourceFactory;
				graph.UpdateGraphicBuffers(graphWidgetSize, _gd);
					graphBuffers.InitPipelines(_gd, CreateGraphShaders(factory), graph._outputFramebuffer, true);
			}
			ActiveGraph = graph;
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


		public void Draw(Vector2 graphSize, ImGuiController _ImGuiController, GraphicsDevice _gd)
        {
			if (IrregularActionTimerFired) PerformIrregularActions();
			if (ActiveGraph == null || ActiveGraph.beingDeleted)
				return;

			ActiveGraph.UpdateGraphicBuffers(graphSize, _gd);
			if (scheduledGraphResize)
			{
				double TimeSinceLastResize = (DateTime.Now - lastResize).TotalMilliseconds;
				if (TimeSinceLastResize > 150)
				{
					graphWidgetSize = graphSize;
					ActiveGraph.InitMainGraphTexture(graphWidgetSize, _gd);
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
		}

		private static long _startTime = System.DateTime.Now.Ticks;




		ulong lastLineBufferSize = 0;
		ulong lastNodeBufferSize = 0;


		private static ShaderSetDescription CreateGraphShaders(ResourceFactory factory)
		{

			//create shaders
			VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
			VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
			VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

			ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(VertexCode), "main");
			ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(FragmentCode), "main");

			Shader[] _shaders = factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc);
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

				inited1 = true; 
			}

			if (ActiveGraph.wireframelines.DataChanged)
			{
				ActiveGraph.wireframelines.SignalDataRead();
				graphBuffers.InitWireframeVertexData(_gd);
			}

			ulong newBufSize = 0;
			if (ActiveGraph.mainnodesdata.DataChanged)
			{
				ActiveGraph.mainnodesdata.SignalDataRead();
				Console.WriteLine("Re-initing main nodes data with " + ActiveGraph.mainnodesdata.VertList.Count + " verts");
				graphBuffers.InitNodeVertexData(_gd, ActiveGraph.mainnodesdata);
			}
			if (ActiveGraph.mainlinedata.DataChanged)
			{
				ActiveGraph.mainlinedata.SignalDataRead();
				graphBuffers.InitLineVertexData(_gd, ActiveGraph.mainlinedata);
			}

			_cl.SetFramebuffer(ActiveGraph._outputFramebuffer);
			_cl.ClearColorTarget(0, RgbaFloat.Black);
			//_cl.ClearDepthStencil(1f);

			SetupView(_cl, graphBuffers);
			graphBuffers.DrawWireframe(_cl);
			graphBuffers.DrawLines(_cl);
			graphBuffers.DrawPoints(_cl);
		}


		private void SetupView(CommandList _cl, VeldridGraphBuffers graphBuffers)
		{


			_cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, 0, 200));
			_cl.UpdateBuffer(graphBuffers._projectionBuffer, 0, Matrix4x4.CreatePerspectiveFieldOfView(dbg_FOV, (float)graphWidgetSize.X / graphWidgetSize.Y, dbg_near, dbg_far));

			Vector3 cameraPosition = new Vector3(dbg_camX,dbg_camY,dbg_camZ);
			//_cl.UpdateBuffer(_viewBuffer, 0, Matrix4x4.CreateLookAt(new Vector3(0,0,-200), new Vector3(0, 0, 0), Vector3.UnitY));
			_cl.UpdateBuffer(graphBuffers._viewBuffer, 0, Matrix4x4.CreateTranslation(cameraPosition));

			//if autorotation...
			float _ticks = (System.DateTime.Now.Ticks - _startTime) / (1000f);
			float angle = _ticks / 10000;
			//else
			angle = dbg_rot;

			Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
			_cl.UpdateBuffer(graphBuffers._worldBuffer, 0, ref rotation);
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
			//if (ActiveGraph == null)
			//	return false;
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
            //bool haveDisplayGraph = chooseGraphToDisplay();
            if (ActiveGraph == null)
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

		

	}
}
