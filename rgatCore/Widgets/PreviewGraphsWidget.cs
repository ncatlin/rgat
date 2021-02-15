﻿using ImGuiNET;
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
        public void ResetClickedGraph() => clickedGraph = null;


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

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos();
            subGraphPosition.X += MarginWidth;

            float captionHeight = ImGui.CalcTextSize("123456789").Y + 3; //dunno where the 3 comes from but it works

            DrawnPreviewGraphs = ActiveTrace.GetPlottedGraphsList(eRenderingMode.ePreview);
            for (var graphIdx = 0; graphIdx < DrawnPreviewGraphs.Count; graphIdx++)
            {
                PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                if (graph == null) continue;
                if (graph.NodesDisplayData.CountVerts() == 0 || graph._outputTexture == null) continue;

                string Caption = $"TID:{graph.tid} {graph.NodesDisplayData.CountVerts()}vts {(graph.tid == selectedGraphTID ? "[Selected]" : "")}";

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 8);
                ImGui.Text(Caption);
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() - 8);

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - captionHeight);
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, graph._outputTexture);
                imdp.AddImage(CPUframeBufferTextureId,
                    subGraphPosition,
                    new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight), 
                    new Vector2(0, 1), 
                    new Vector2(1, 0));
                if(ImGui.InvisibleButton("PrevGraphBtn"+ graph.tid, new Vector2(EachGraphWidth, EachGraphHeight)))
                {
                    var MainGraphs = ActiveTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                    HandleClickedGraph(MainGraphs[graphIdx]);
                }

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

                if (graph._outputTexture == null)
                {
                    graph.UpdatePreviewBuffers(_gd);
                }

                VeldridGraphBuffers graphRenderInfo = null;
                if (!graphicInfos.TryGetValue(graph.tid, out graphRenderInfo))
                {
                    graphicInfos.Add(graph.tid, new VeldridGraphBuffers());
                    graphRenderInfo = graphicInfos[graph.tid];

                    graphRenderInfo.InitPipelines(_gd, CreateGraphShaders(_gd.ResourceFactory), graph._outputFramebuffer);
                }


                _cl.SetFramebuffer(graph._outputFramebuffer);
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

            byte[] nodeVertShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.ShaderStrings.vsnodeglsl);
            byte[] nodeFragShaderBytes = Encoding.UTF8.GetBytes(Shaders.SPIR_V.ShaderStrings.fsnodeglsl);
            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, nodeVertShaderBytes, "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, nodeFragShaderBytes, "main");

            _shaders = factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc);
            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
            vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
            shaders: _shaders);

            return shaderSetDesc;
        }





    }
}
