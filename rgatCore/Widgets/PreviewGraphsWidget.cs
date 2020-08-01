using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Drawing;
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


        public PreviewGraphsWidget()
        {
            IrregularTimer = new System.Timers.Timer(600);
            IrregularTimer.Elapsed += FireTimer;
            IrregularTimer.AutoReset = true;
            IrregularTimer.Start();

        }

        private void FireTimer(object sender, ElapsedEventArgs e) { IrregularTimerFired = true; }

        public void SetActiveTrace(TraceRecord trace) => ActiveTrace = trace;

        public void SetSelectedGraph(PlottedGraph graph) => selectedGraphTID = graph.tid;

        private void HandleClickedGraph(PlottedGraph graph) => clickedGraph = graph;

        private Vector2? HandleInput(Vector2 widgetSize)
        {
            if (ImGui.IsMouseClicked(0))
            {
                Vector2 MousePos = ImGui.GetMousePos();
                Vector2 WidgetPos = ImGui.GetCursorScreenPos();

                if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + widgetSize.X))
                {
                    if (MousePos.Y >= (WidgetPos.Y + ImGui.GetScrollY()) && MousePos.Y < (WidgetPos.Y + widgetSize.Y + ImGui.GetScrollY()))
                    {
                        return new Vector2(MousePos.X, MousePos.Y);
                    }
                }
            }
            return null;
        }

        //we do it via Draw so events are handled by the same thread
        public void HandleFrameTimerFired()
        {
            //Console.WriteLine("Handling timer fired");
            IrregularTimerFired = false;
        }

        public void Draw(Vector2 widgetSize, ImGuiController _ImGuiController, GraphicsDevice _gd)
        {
            if (ActiveTrace == null) return;
            if (IrregularTimerFired) HandleFrameTimerFired();

            Vector2? ClickedPos = HandleInput(widgetSize);

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos();
            subGraphPosition.X += MarginWidth;

            float captionHeight = ImGui.CalcTextSize("123456789").Y;
            int cursorGap = (int)(EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING - captionHeight + 4f); //ideally want to draw the text in the texture itself

            DrawnPreviewGraphs = ActiveTrace.GetPlottedGraphsList(eRenderingMode.ePreview);
            for (var graphIdx = 0; graphIdx < DrawnPreviewGraphs.Count; graphIdx++)
            {
                PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                if (graph.NodesDisplayData.CountVerts() == 0 || graph._previewTexture == null) continue;

                ImGui.Text($"TID:{graph.tid} {graph.NodesDisplayData.CountVerts()}vts");
                if (graph.tid == selectedGraphTID)
                    ImGui.Text("[Selected]");

                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._previewTexture);
                imdp.AddImage(CPUframeBufferTextureId,
                    subGraphPosition,
                    new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight), new Vector2(0, 1), new Vector2(1, 0));

                if (ClickedPos.HasValue && ClickedPos.Value.Y > subGraphPosition.Y &&
                    ClickedPos.Value.Y < (subGraphPosition.Y + EachGraphHeight))
                {
                    var MainGraphs = ActiveTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                    HandleClickedGraph(MainGraphs[graphIdx]);
                }

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + cursorGap);
                subGraphPosition.Y += (EachGraphHeight + UI_Constants.PREVIEW_PANE_PADDING);
            }
        }


        private static long _startTime = System.DateTime.Now.Ticks;
        private static Shader[] _shaders;
        Dictionary<uint, VeldridGraphBuffers> graphicInfos = new Dictionary<uint, VeldridGraphBuffers>();


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




        public void AddGraphicsCommands(CommandList _cl, GraphicsDevice _gd)
        {
            foreach (PlottedGraph graph in DrawnPreviewGraphs)
            {
                if (graph == null) continue;
                if (graph.EdgesDisplayData.CountRenderedEdges == 0 || graph.NodesDisplayData.CountVerts() == 0) continue;

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
                RgbaFloat graphBackground = graph.internalProtoGraph.Terminated ?
                    new RgbaFloat(0.5f, 0, 0, 0.2f) :
                    new RgbaFloat(0, 0.5f, 0, 0.2f);

                _cl.ClearColorTarget(0, graphBackground);

                SetupView(_cl, graphRenderInfo, graph);
                graphRenderInfo.DrawEdges(_cl, _gd, graph.EdgesDisplayData);
                graphRenderInfo.DrawPoints(_cl, _gd, graph.NodesDisplayData);
            }
        }




        private static ShaderSetDescription CreateGraphShaders(ResourceFactory factory)
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexElementDescription AnimAlpha = new VertexElementDescription("ActiveAnimAlpha", VertexElementSemantic.Color, VertexElementFormat.Float1);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol, AnimAlpha);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(VertexCode), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(FragmentCode), "main");

            _shaders = factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc);
            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
            vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
            shaders: _shaders);

            return shaderSetDesc;
        }

        private const string VertexCode = @"
#version 450

layout(location = 0) in vec3 Position;
layout(location = 1) in vec4 Color;

layout(set = 0, binding = 0) uniform ViewBuffer
{
    mat4 View;
};


layout(location = 0) out vec4 fsin_Color;

void main()
{
    gl_PointSize = 3.0f;
    gl_Position = View * vec4(Position,1);
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

    }
}
