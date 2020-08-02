using ImGuiNET;
using Newtonsoft.Json.Bson;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
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
        public PlottedGraph ActiveGraph { get; private set; } = null;
        private bool inited1 = false;


        System.Timers.Timer IrregularActionTimer;
        bool IrregularActionTimerFired = false;

        Dictionary<PlottedGraph, VeldridGraphBuffers> graphBufferDict = new Dictionary<PlottedGraph, VeldridGraphBuffers>();
        VeldridGraphBuffers graphBuffers = null;
        ImGuiController _controller;


        private Vector2 graphWidgetSize;




        public GraphPlotWidget(ImGuiController controller, Vector2? initialSize = null)
        {
            _controller = controller;
            graphWidgetSize = initialSize ?? new Vector2(400, 400);
            IrregularActionTimer = new System.Timers.Timer(600);
            IrregularActionTimer.Elapsed += FireIrregularTimer;
            IrregularActionTimer.AutoReset = true;
            IrregularActionTimer.Start();

        }

        public void SetActiveGraph(PlottedGraph graph, GraphicsDevice _gd)
        {
            if (graph == null)
            {
                ActiveGraph = graph;
                return;
            }

            if (!graphBufferDict.TryGetValue(graph, out graphBuffers))
            {
                graphBuffers = new VeldridGraphBuffers();
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

        public void ApplyZoom(float direction)
        {
            if (ActiveGraph != null)
            {
                float newValue = ActiveGraph.CameraZoom - (direction * 100);
                if (newValue >= 100)
                    ActiveGraph.CameraZoom = newValue;
            }
        }

        static public bool IsMouseInWidget(Vector2 graphSize)
        {
            Vector2 MousePos = ImGui.GetMousePos();
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();

            if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + graphSize.X))
            {
                if (MousePos.Y >= WidgetPos.Y && MousePos.Y < (WidgetPos.Y + graphSize.Y))
                {
                    return true;
                }
            }
            return false;
        }

        public void HandleInput(Vector2 graphSize)
        {
            bool mouseInWidget = IsMouseInWidget(graphSize);


            if (mouseInWidget)
            {
                float scroll = ImGui.GetIO().MouseWheel;
                if (scroll != 0) ApplyZoom(scroll);

                if (ActiveGraph != null && ImGui.GetIO().MouseDown[0])
                {
                    ActiveGraph.CameraYOffset -= ImGui.GetIO().MouseDelta.Y * CamBoomFactor();
                    ActiveGraph.PlotRotation += ImGui.GetIO().MouseDelta.X * RotationFactor();
                }
            }


        }

        //how much to move the camera on the y axis per mouse movement
       static private float CamBoomFactor()
        {
            return 30f; //todo adjust to zoom, plot size
        }

        //how much to rotate our cylinder per mouse movent
        private float RotationFactor()
        {
            return 0.002f;//todo adjust to zoom, plot size
        }

        public void Draw(Vector2 graphSize, ImGuiController _ImGuiController, GraphicsDevice _gd)
        {

            HandleInput(graphSize);

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
                    ActiveGraph.InitGraphTexture(graphWidgetSize, _gd);
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

            Vector2 textpos = ImGui.GetCursorScreenPos();
            //textpos += txtitm.screenXY;

            GraphicsMaths.SCREENINFO scrn;
            scrn.X = 0;// ImGui.GetCursorScreenPos().X;
            scrn.Y = 0;// ImGui.GetCursorScreenPos().Y;
            scrn.Width = graphWidgetSize.X;
            scrn.Height = graphWidgetSize.Y;
            scrn.MaxDepth = ActiveGraph.scalefactors.plotSize;
            scrn.MinDepth = 1;
            scrn.CamZoom = ActiveGraph.CameraZoom;

            
            foreach (PlottedGraph.TEXTITEM txtitm in ActiveGraph.GetOnScreenTexts(scrn))
            {
                PlottedGraph.TEXTITEM txtitm2 = txtitm;
                txtitm2.screenXY.X += 5;
                txtitm2.screenXY.X += ImGui.GetCursorScreenPos().X;

                txtitm2.screenXY.Y += ImGui.GetCursorScreenPos().Y;
                txtitm2.screenXY.Y -= ImGui.CalcTextSize(txtitm.contents).Y / 2 ;
                imdp.AddText(_ImGuiController._unicodeFont, txtitm2.fontSize, txtitm2.screenXY, (uint)txtitm2.color.ToArgb(), txtitm2.contents);
            }
            

            //drawHUD();
        }


        public void AddGraphicsCommands(CommandList _cl, GraphicsDevice _gd)
        {
            if (ActiveGraph == null) return;

            ActiveGraph.InitGraphTexture(graphWidgetSize, _gd);

            _cl.SetFramebuffer(ActiveGraph._outputFramebuffer);
            _cl.ClearColorTarget(0, RgbaFloat.Black);
            //_cl.ClearDepthStencil(1f);

            SetupView(_cl, graphBuffers);

            VeldridGraphBuffers.AnimDataStruct animInfo;
            animInfo.animEnabled = ActiveGraph.IsAnimated ? 1 : 0;
            _cl.UpdateBuffer(graphBuffers._animBuffer, 0, ref animInfo, (uint)Marshal.SizeOf(animInfo));


            graphBuffers.DrawIllustrationLines(_cl, _gd, ActiveGraph);
            graphBuffers.DrawEdges(_cl, _gd, ActiveGraph.EdgesDisplayData);
            graphBuffers.DrawPoints(_cl, _gd, ActiveGraph.NodesDisplayData);
        }

        private void SetupView(CommandList _cl, VeldridGraphBuffers graphBuffers)
        {
            float angle = ActiveGraph.PlotRotation;
            float nearClip = ActiveGraph.CameraClippingNear;
            float farClip = nearClip + ActiveGraph.scalefactors.plotSize + ActiveGraph.CameraClippingFar;
            if (nearClip < 0) nearClip = 0f;
            if (farClip <= nearClip) farClip = nearClip + 1;

            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, 0, 200));

            Vector3 cameraPosition = new Vector3(ActiveGraph.CameraXOffset, ActiveGraph.CameraYOffset, (-1 * ActiveGraph.scalefactors.plotSize) - ActiveGraph.CameraZoom);
            Matrix4x4 view = Matrix4x4.CreateTranslation(cameraPosition);

            Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, angle);
            Matrix4x4 combined = rotation;
            combined = Matrix4x4.Multiply(combined, view);

            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(ActiveGraph.CameraFieldOfView, (float)graphWidgetSize.X / graphWidgetSize.Y, nearClip, farClip);
            combined = Matrix4x4.Multiply(combined, projection);
            _cl.UpdateBuffer(graphBuffers._viewBuffer, 0, combined);


            ActiveGraph.projection = projection;
            ActiveGraph.view = view;
            ActiveGraph.rotation = rotation;
        }


        private static ShaderSetDescription CreateGraphShaders(ResourceFactory factory)
        {

            //create shaders
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexElementDescription AnimAlpha = new VertexElementDescription("ActiveAnimAlpha", VertexElementSemantic.Color, VertexElementFormat.Float1);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol, AnimAlpha);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(VertexCode), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(FragmentCode), "main");

            Shader[] _shaders = factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc);
            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
            vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
            shaders: _shaders);

            return shaderSetDesc;
        }



        private const string VertexCode = @"
#version 450

layout(location = 0) in vec3 Position;
layout(location = 1) in vec4 Color;
layout(location = 2) in float ActiveAnimAlpha;


layout(set = 0, binding = 0) uniform ViewBuffer
{
    mat4 View;
};

layout(location = 0) out vec4 fsin_Color;
layout(location = 1) out float fsin_ActiveAnimAlpha;

void main()
{

    gl_PointSize = 5.0f;
    gl_Position = View * vec4(Position,1);
    fsin_Color = Color;
    fsin_ActiveAnimAlpha = ActiveAnimAlpha;
}";


        private const string FragmentCode = @"
#version 450

layout(location = 0) in vec4 fsin_Color;
layout(location = 1) in float fsin_ActiveAnimAlpha;
layout(location = 0) out vec4 fsout_Color;


layout(set = 1, binding = 0) uniform AnimBuffer
{
    int AnimEnabled;
};


void main()
{
  
    fsout_Color = (AnimEnabled == 1) ? vec4(fsin_Color.xyz, fsin_ActiveAnimAlpha) : fsin_Color;
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

            //highlight new nodes with highlighted address
            ActiveGraph.DoHighlightAddresses();

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.ePlaying)
            {
                //ui->replaySlider->setValue(1000 * ActiveGraph.getAnimationPercent());
            }

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.eEnded)
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
