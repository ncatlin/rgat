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


        System.Timers.Timer FrameTimer;
        bool FrameTimerFired = false;

        TraceRecord ActiveTrace = null;


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

        public uint selectedGraphTID;
        public PlottedGraph clickedGraph { get; private set; }


        public PreviewGraphsWidget()
        {
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

        public void SetActiveTrace(TraceRecord trace) => ActiveTrace = trace;

        private void HandleClickedGraph(PlottedGraph graph)
        {
            clickedGraph = graph;
        }

        public void Draw(Vector2 widgetSize, ImGuiController _ImGuiController, GraphicsDevice _gd)
        {
            //if (FrameTimerFired) Update();

            clickedGraph = null;
            if (ActiveTrace == null)
                return;

            Vector2? ClickedPos = null;
            if (ImGui.IsMouseClicked(0))
            {
                Vector2 MousePos = ImGui.GetMousePos();
                Vector2 WidgetPos = ImGui.GetCursorScreenPos();

                if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + widgetSize.X))
                {
                    if (MousePos.Y >= (WidgetPos.Y + ImGui.GetScrollY()) && MousePos.Y < (WidgetPos.Y + widgetSize.Y + ImGui.GetScrollY()))
                    {
                        //ClickedPos = new Vector2(MousePos.X - WidgetPos.X, MousePos.Y - WidgetPos.Y);
                        ClickedPos = new Vector2(MousePos.X, MousePos.Y);
                    }
                }

            }

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 pos = ImGui.GetCursorScreenPos();
            pos.X += MarginWidth;
            float captionHeight = ImGui.CalcTextSize("123456789").Y;
            DrawnGraphs = ActiveTrace.GetPlottedGraphsList();
            foreach (PlottedGraph graph in DrawnGraphs)
            {
                if (graph.previewnodes.CountVerts() == 0 || graph._previewTexture == null) continue;
                ImGui.Text($"TID:{graph.tid} {graph.previewnodes.CountVerts()}vts");
                if (graph.tid == selectedGraphTID)
                    ImGui.Text("[Selected]");

                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._previewTexture);
                imdp.AddImage(CPUframeBufferTextureId,
                    pos,
                    new Vector2(pos.X + EachGraphWidth, pos.Y + EachGraphHeight), new Vector2(0, 1), new Vector2(1, 0));

                if (ClickedPos.HasValue && ClickedPos.Value.Y > pos.Y && ClickedPos.Value.Y < (pos.Y + EachGraphHeight))
                {
                    HandleClickedGraph(graph);
                }

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

        Dictionary<uint, VeldridGraphBuffers> graphicInfos = new Dictionary<uint, VeldridGraphBuffers>();


        private void SetupView(CommandList _cl, VeldridGraphBuffers graphRenderInfo)
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
                    graph.UpdatePreviewBuffers(_gd);
                }

                VeldridGraphBuffers graphRenderInfo = null;
                if (!graphicInfos.TryGetValue(graph.tid, out graphRenderInfo))
                {
                    graphicInfos.Add(graph.tid, new VeldridGraphBuffers(graph));
                    graphRenderInfo = graphicInfos[graph.tid];

                    graphRenderInfo.InitPipelines(_gd, CreateGraphShaders(_gd.ResourceFactory), graph._previewFramebuffer);
                }


                _cl.SetFramebuffer(graph._previewFramebuffer);
                _cl.ClearColorTarget(0, new RgbaFloat(1, 0, 0, 0.1f));
                //_cl.ClearDepthStencil(1f);
                SetupView(_cl, graphRenderInfo);
                graphRenderInfo.DrawLines(_cl, _gd, graph.previewlines);
                graphRenderInfo.DrawPoints(_cl, _gd, graph.previewnodes);
            }
        }

        public void SetSelectedGraph(PlottedGraph graph)
        {
            selectedGraphTID = graph.tid;
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
