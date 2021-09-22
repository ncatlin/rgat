using ImGuiNET;
using rgat.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Veldrid;
using static rgat.VeldridGraphBuffers;

namespace rgat.Widgets
{
    class VisualiserBar
    {
        public VisualiserBar(GraphicsDevice graphicsDev, ImGuiController controller)
        {
            _gd = graphicsDev;
            _factory = _gd.ResourceFactory;
            _controller = controller;
            InitGraphics();
        }

        readonly ImGuiController _controller;
        readonly GraphicsDevice _gd;
        readonly ResourceFactory _factory;
        Pipeline _lineListPipeline, _pointPipeline, _triPipeline;
        ResourceLayout _rsrcLayout;
        DeviceBuffer _pointsVertexBuffer, _pointsIndexBuffer;
        DeviceBuffer _linesVertexBuffer, _linesIndexBuffer;
        DeviceBuffer _trisVertexBuffer, _trisIndexBuffer;
        Texture _outputTexture;
        Framebuffer _outputFramebuffer;
        DeviceBuffer _paramsBuffer;
        ResourceSet _rsrcs;
        TextureView _iconsTextureView;

        public void InitGraphics()
        {
            //todo exceptions here quite early in loading
            _iconsTextureView = _controller.IconTexturesView;
            _paramsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<BarShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "VisBarShaderParams");
            _rsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
                new ResourceLayoutElementDescription("NodeTextures", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
               ));

            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
            pipelineDescription.BlendState = BlendStateDescription.SingleAlphaBlend;
            pipelineDescription.DepthStencilState = DepthStencilStateDescription.Disabled;
            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: false,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _rsrcLayout };
            pipelineDescription.ShaderSet = SPIRVShaders.CreateVisBarPointIconShader(_gd);

            CreateTextures(1, 1);

            _pointsVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarPointsVertexInitial");
            _linesVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarLinesVertexInitial");
            _trisVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarTrisVertexInitial");
            _pointsIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");
            _linesIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");
            _trisIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");



            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _lineListPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.TriangleList;
            _triPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            ResourceSetDescription rsrc_rsd = new ResourceSetDescription(_rsrcLayout, _paramsBuffer, _gd.PointSampler, _iconsTextureView);
            //_rsrcs?.Dispose();
            _rsrcs = _factory.CreateResourceSet(rsrc_rsd);
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct BarShaderParams
        {
            public bool useTexture;
            public float xShift;
            public float width;
            public float height;
        }

        float _width;
        float _height;
        float _newWidth = 400, _newHeight = 80;
        Position2DColour[] _pointVerts;
        Position2DColour[] _lineVerts;
        Position2DColour[] _triangleVerts;

        void CreateTextures(float width, float height)
        {
            Console.WriteLine("VisBarCreateTex Start");
            _width = Math.Max(50, width);
            _height = Math.Max(50, height);
            lock (_lock)
            {
                VeldridGraphBuffers.DoDispose(_outputTexture);
                VeldridGraphBuffers.DoDispose(_outputFramebuffer);
                _outputTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)_width, (uint)_height, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));
                _outputFramebuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));
            }
            Console.WriteLine("VisBarCreateTex end");
        }

        void MaintainBuffers()
        {
            //todo pointverts can be null?
            uint requiredSize = (uint)_pointVerts.Length * Position2DColour.SizeInBytes;
            if (_pointsVertexBuffer.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_pointsVertexBuffer);
                _pointsVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarPointsVertex");
                VeldridGraphBuffers.VRAMDispose(_pointsIndexBuffer);
                _pointsIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_pointVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarPointsIndex");

            }

            requiredSize = (uint)_lineVerts.Length * Position2DColour.SizeInBytes;
            if (_linesVertexBuffer.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_linesVertexBuffer);
                _linesVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarLinesVertex");
                VeldridGraphBuffers.VRAMDispose(_linesIndexBuffer);
                _linesIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_lineVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarLinesIndex");
            }

            requiredSize = (uint)_triangleVerts.Length * Position2DColour.SizeInBytes;
            if (_trisVertexBuffer.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_trisVertexBuffer);
                VeldridGraphBuffers.VRAMDispose(_trisIndexBuffer);
                _trisVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarTrisIndex");
                _trisIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_triangleVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarTrisIndex");
            }
        }


        public void Render()
        {
            BarShaderParams shaderParams = new BarShaderParams
            {
                useTexture = false,
                xShift = 0,
                width = _width,
                height = _height
            };


            MaintainBuffers();

            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();

            _cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _cl.UpdateBuffer(_pointsVertexBuffer, 0, _pointVerts);

            int[] pointIndices = Enumerable.Range(0, _pointVerts.Length).Select(i => (int)i).ToArray();
            _cl.UpdateBuffer(_pointsIndexBuffer, 0, pointIndices);
            _cl.UpdateBuffer(_linesVertexBuffer, 0, _lineVerts);

            int[] lineIndices = Enumerable.Range(0, _lineVerts.Length).Select(i => (int)i).ToArray();
            _cl.UpdateBuffer(_linesIndexBuffer, 0, lineIndices);
            _cl.UpdateBuffer(_trisVertexBuffer, 0, _triangleVerts);

            int[] triIndices = Enumerable.Range(0, _triangleVerts.Length).Select(i => (int)i).ToArray();
            _cl.UpdateBuffer(_trisIndexBuffer, 0, triIndices);
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, new WritableRgbaFloat(Themes.GetThemeColourUINT(Themes.eThemeColour.eVisBarBg)).ToRgbaFloat());

            _cl.SetPipeline(_triPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _trisVertexBuffer);
            _cl.SetIndexBuffer(_trisIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)triIndices.Length, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);


            _cl.SetPipeline(_lineListPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _linesVertexBuffer);
            _cl.SetIndexBuffer(_linesIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)lineIndices.Length, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);


            _cl.SetPipeline(_pointPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _pointsVertexBuffer);
            _cl.SetIndexBuffer(_pointsIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)pointIndices.Length, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);


            _cl.End();
            _gd.SubmitCommands(_cl);
            _gd.WaitForIdle();
            _cl.Dispose();
        }

        /// <summary>
        /// Draw the latest rendered visualiser bar
        /// Specified dimensions will be used in the next render
        /// </summary>
        /// <param name="width">Bar Width</param>
        /// <param name="height">Bar Height</param>
        public void Draw(float width, float height)
        {
            _newWidth = width;
            _newHeight = height;

            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList();
            lock (_lock)
            {
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, _outputTexture, "VisualiserBar"); //thread unsafe todo, can be disposed here

                imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: pos,
                    p_max: new Vector2(pos.X + _outputTexture.Width, pos.Y + _outputTexture.Height),
                    uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));
            }

            MODULE_LABEL[]? labels;
            lock (_lock)
            {
                labels = _moduleTexts.ToArray();
            }

            foreach (var mtxt in labels)
            {
                imdp.AddText(pos + new Vector2(mtxt.startX, 30), 0xffffffff, "start");
            }


            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + _height);
        }


        float _sliderPosX = -1;
        /// <summary>
        /// Draw a replay graph visualiser bar with animation sliders 
        /// </summary>
        /// <param name="width"></param>
        /// <param name="height"></param>
        /// <param name="graph"></param>
        public unsafe void DrawReplaySlider(float width, float height, PlottedGraph graph)
        {
            Vector2 progressBarSize = new Vector2(width, height);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            ImGui.PushStyleColor(ImGuiCol.Button, 0xff00ffff);
            ImGui.InvisibleButton("##ReplayProgressBtn", progressBarSize);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - progressBarSize.Y);
            ImGui.PopStyleVar();

            Vector2 AnimationProgressBarPos = ImGui.GetItemRectMin();

            Vector2 SliderRectStart = new Vector2(AnimationProgressBarPos.X, AnimationProgressBarPos.Y);
            Vector2 SliderRectEnd = new Vector2(AnimationProgressBarPos.X + progressBarSize.X, AnimationProgressBarPos.Y + progressBarSize.Y);

            if (ImGui.IsItemActive())
            {
                _sliderPosX = ImGui.GetIO().MousePos.X - ImGui.GetWindowPos().X;
            }
            else
            {

                if (graph != null)
                {
                    float animPercentage = graph.GetAnimationProgress();
                    _sliderPosX = animPercentage * (SliderRectEnd.X - SliderRectStart.X);
                }
            }

            Vector2 SliderArrowDrawPos = new Vector2(AnimationProgressBarPos.X + _sliderPosX, AnimationProgressBarPos.Y - 4);
            if (SliderArrowDrawPos.X < SliderRectStart.X) SliderArrowDrawPos.X = AnimationProgressBarPos.X;
            if (SliderArrowDrawPos.X > SliderRectEnd.X) SliderArrowDrawPos.X = SliderRectEnd.X;

            float sliderBarPosition = (SliderArrowDrawPos.X - SliderRectStart.X) / progressBarSize.X;
            if (sliderBarPosition <= 0.05) SliderArrowDrawPos.X += 1;
            if (sliderBarPosition >= 99.95) SliderArrowDrawPos.X -= 1;

            if (ImGui.IsItemActive())
            {
                if (graph != null)
                {
                    graph.SeekToAnimationPosition(sliderBarPosition);
                }
                Console.WriteLine($"User changed animation position to: {sliderBarPosition * 100}%");
            }


            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 0);

            Draw(progressBarSize.X, height);


            ImguiUtils.RenderArrowsForHorizontalBar(ImGui.GetForegroundDrawList(),
                SliderArrowDrawPos,
                new Vector2(3, 7), progressBarSize.Y, 240f);
        }


        /*
         * Creates a white symbol with a size depending on instruction count. Handles 1 - 194ish instructions length blocks.
         * Any higher will just be the max size symbol.
         */
        static void CreateExecTagSymbol(float Xoffset, uint insCount, ref List<Position2DColour> lines)
        {
            float remaining = insCount;
            float xMid = Xoffset + 1;
            float yStart = 2;
            float len = Math.Min(remaining, 9) + 1;
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid, yStart) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid, yStart + len) });

            remaining /= 2;
            if (remaining <= 7) return;

            len = Math.Min(remaining - 7, 9) + 1;
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 1, yStart) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 1, yStart + len) });

            remaining /= 2;
            if (remaining <= 14) return;

            len = Math.Min(remaining - 14, 5) + 1;
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid - 1, yStart + 2) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid - 1, yStart + 2 + len) });

            remaining /= 2;
            if (remaining <= 19) return;

            len = Math.Min(remaining - 19, 5) + 1;
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 2, yStart + 2) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 2, yStart + 2 + len) });
        }

        void CreateRect(WritableRgbaFloat colour, float leftX, float topY, float width, float height, ref List<Position2DColour> triangles)
        {
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX, topY) });
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX, topY + height) });
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX + width, topY + height) });
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX + width, topY) });
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX, topY) });
            triangles.Add(new Position2DColour() { Color = colour, Position = new Vector2(leftX + width, topY + height) });
        }

        void DrawAPIEntry(float Xoffset, float Yoffset, float width, int moduleID, string module, string symbol, ref List<Position2DColour> lines)
        {
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Pink), Position = new Vector2(Xoffset, Yoffset) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Pink), Position = new Vector2(Xoffset + width, Yoffset + 8) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Pink), Position = new Vector2(Xoffset + width, Yoffset) });
            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Pink), Position = new Vector2(Xoffset, Yoffset + 8) });
        }


        class MODULE_SEGMENT
        {
            public int firstIdx;
            public int lastIdx;
            public int modID;
            public string name;
        };
        struct MODULE_LABEL
        {
            public float startX;
            public float endX;
            public int modID;
            public string name;
        };

        int lastDrawnTagIdx = 0;
        float barScrollingPos = 0;
        readonly List<MODULE_LABEL> _moduleTexts = new List<MODULE_LABEL>();
        readonly object _lock = new object();


        //todo lots of opportunity for caching here
        public void GenerateLive(ProtoGraph graph)
        {
            if (_newWidth != _width || _newHeight != _height)
            {
                CreateTextures(_newWidth, _newHeight);
            }


            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();
            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();
            WritableRgbaFloat plotLineColour = Themes.GetThemeColourWRF(Themes.eThemeColour.eVisBarPlotLine);
            List<MODULE_SEGMENT> moduleAreas = new List<MODULE_SEGMENT>();

            //Draw Tag visualisation
            int entryCount = 100;
            int lastIdx = graph.GetRecentAnimationEntries(entryCount, out List<ANIMATIONENTRY> entries);
            if (barScrollingPos == 0 && lastDrawnTagIdx != lastIdx)
                barScrollingPos = 0.05f;
            lastDrawnTagIdx = lastIdx;

            float pSep = _width / entryCount;
            float tagWidth = 3;
            float scrollOffset = 0f;
            if (barScrollingPos != 0)
            {
                scrollOffset = (barScrollingPos * pSep) - pSep;
                barScrollingPos += 0.1f;
                if (barScrollingPos >= 1f) barScrollingPos = 0;
            }
            scrollOffset += _width % pSep;

            for (var i = 1; i < entries.Count + 1; i++)
            {
                int backIdx = entries.Count - i;
                ANIMATIONENTRY ae = entries[backIdx];
                float Xoffset = (_width - pSep * backIdx) - tagWidth;

                Xoffset -= scrollOffset;
                bool drawPlotLine;
                //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Cyan), Position = new Vector2(Xoffset, 0) });
                //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Cyan), Position = new Vector2(Xoffset, 50) });
                int blkID = (int)ae.blockID;

                if (blkID < 0 || blkID >= graph.BlocksFirstLastNodeList.Count) continue;

                var blockFirstLast = graph.BlocksFirstLastNodeList[blkID];


                if (blockFirstLast == null) continue; //happens on .idata jump thunks
                uint insCount = (blockFirstLast.Item2 - blockFirstLast.Item1) + 1;
                CreateExecTagSymbol(Xoffset + pSep / 2, insCount, ref lines);


                switch (ae.entryType)
                {
                    case eTraceUpdateType.eAnimExecTag:
                        drawPlotLine = true;
                        break;

                    case eTraceUpdateType.eAnimUnchained:
                        {
                            float symbase = 12f;
                            //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset + pSep, 2) });
                            //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset, 2) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset, 2) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset, symbase) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset, symbase) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Red), Position = new Vector2(Xoffset + pSep + 1, symbase) });
                        }
                        break;

                    case eTraceUpdateType.eAnimUnchainedResults:
                        {
                            drawPlotLine = true;
                            float symbase = 12f;
                            //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset, 2) });
                            //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset + pSep, 2) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset + pSep, 2) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset + pSep, symbase) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset + pSep, symbase) });
                            lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LimeGreen), Position = new Vector2(Xoffset, symbase) });
                        }
                        break;

                    case eTraceUpdateType.eAnimReinstrument:
                        //TODO
                        break;

                    case eTraceUpdateType.eAnimRepExec:
                        //probably not worth drawing
                        break;

                    default:
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset, 2) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 12f) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 2) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 12f) });

                        Logging.RecordLogEvent($"VisualiserBar:Live:Unhandled tag type {ae.entryType}");
                        break;
                }


                //Draw Heatmap visualisation
                int blockTailIdx = (int)blockFirstLast.Item2;
                WritableRgbaFloat heatColour;
                if (graph.NodeList.Count > blockTailIdx)
                {
                    // colour from heat ranking of final node
                    NodeData node = graph.NodeList[blockTailIdx];
                    Debug.Assert(node.heatRank >= 0 && node.heatRank <= 9);

                    heatColour = Themes.GetThemeColourWRF((Themes.eThemeColour)((float)Themes.eThemeColour.eHeat0Lowest + node.heatRank));

                    CreateRect(heatColour, Xoffset, 15, pSep, 10, ref triangles);

                    // plot line from edge counts
                    if (graph.BusiestBlockExecCount > 0)
                    {
                        //int blkct = blockTailIdx - (int)graph.BlocksFirstLastNodeList[(int)ae.blockID].Item1;
                        //Console.WriteLine($"NodeID: {node.index} BlockID: {ae.blockID} BlkSz: {blkct} ThisExecCt:{ae.count} TotlExecCount: {node.executionCount} heatrank: {node.heatRank}");
                        float ecountprop = 1 - ((float)ae.count / (float)graph.BusiestBlockExecCount);
                        if (busyCountLinePoints.Count > 0)
                        {
                            busyCountLinePoints.Add(busyCountLinePoints[^1]);
                            busyCountLinePoints.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LightGreen), Position = new Vector2(Xoffset, 15 + 10 * ecountprop) });
                        }
                        busyCountLinePoints.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LightGreen), Position = new Vector2(Xoffset, 16 + 10 * ecountprop) });
                        busyCountLinePoints.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LightGreen), Position = new Vector2(Xoffset + pSep / 2, 17 + 10 * ecountprop) });
                        busyCountLinePoints.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LightGreen), Position = new Vector2(Xoffset + pSep / 2, 17 + 10 * ecountprop) });
                        busyCountLinePoints.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.LightGreen), Position = new Vector2(Xoffset + pSep, 16 + 10 * ecountprop) });
                    }
                }
                else
                {
                    CreateRect(new WritableRgbaFloat(Color.Green), Xoffset + 2, 13, pSep, 8, ref triangles);
                }




                //Draw API icon - todo above i guess as it wont get here?
                if (blkID == -1)
                {
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.blockAddr, out int moduleID, out string? module, out string? symbol);
                    if (found)
                    {
                        DrawAPIEntry(Xoffset + 2, 33, pSep, moduleID, module, symbol, ref lines);
                    }
                }
                else
                {
                    //Draw Module location bits
                    int moduleID = graph.ProcessData.FindContainingModule(graph.ProcessData.GetAddressOfBlock((int)ae.blockID));
                    if (moduleAreas.Count > 0)
                    {
                        MODULE_SEGMENT lastRec = moduleAreas[^1];
                        if (lastRec.lastIdx == (backIdx + 1) && lastRec.modID == moduleID)
                        {
                            lastRec.lastIdx = backIdx;
                            continue;
                        }
                    }

                    moduleAreas.Add(new MODULE_SEGMENT()
                    {
                        firstIdx = backIdx,
                        lastIdx = backIdx,
                        modID = moduleID,
                        name = "todo"
                    });

                }
            }

            lock (_lock)
            {
                _moduleTexts.Clear();
                for (var i = 0; i < moduleAreas.Count; i++)
                {
                    MODULE_SEGMENT ms = moduleAreas[i];
                    WritableRgbaFloat segColour = new WritableRgbaFloat(Color.GhostWhite);

                    float startX = (ms.firstIdx + 1) * pSep;
                    float endX = ms.lastIdx * pSep + 1;
                    MODULE_LABEL label = new MODULE_LABEL
                    {
                        startX = (_width - startX) + 2,
                        endX = _width - (endX + 2),
                        modID = ms.modID,
                        name = ms.name
                    };
                    _moduleTexts.Add(label);

                    //left border
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - startX, 33f) });
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - startX, 48f) });
                    //top
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - startX, 33f) });
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - endX, 33f) });
                    //base
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - startX, 48f) });
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - endX, 48f) });
                    //right border
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - endX, 33f) });
                    lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(_width - endX, 48f) });
                }
            }

            _pointVerts = points.ToArray();
            _lineVerts = lines.Concat(busyCountLinePoints).ToArray();
            _triangleVerts = triangles.ToArray();
        }

        readonly Dictionary<ProtoGraph, Dictionary<int, double>> _cumuls = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        readonly Dictionary<ProtoGraph, Dictionary<int, double>> _avgs = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        readonly Dictionary<ProtoGraph, List<MODULE_SEGMENT>> _modSegs = new Dictionary<ProtoGraph, List<MODULE_SEGMENT>>();

        void MaxBlockWorkCount(ProtoGraph graph, float barWidth,
            out Dictionary<int, double> pixCumul,
            out Dictionary<int, double> pixAvg,
            out List<MODULE_SEGMENT> modSegs
            )
        {
            if (_cumuls.TryGetValue(graph, out pixCumul))
            {
                pixAvg = _avgs[graph];
                modSegs = _modSegs[graph];
                return;
            }

            List<ANIMATIONENTRY> animationData = graph.GetSavedAnimationData();

            ulong segmentBlockCount = 0;
            ulong segmentBlockInsCount = 0;
            pixCumul = new Dictionary<int, double>();
            pixAvg = new Dictionary<int, double>();
            modSegs = new List<MODULE_SEGMENT>();
            double highestSegmentAvg = 0;
            int lastPlotXPixel = -1;
            ulong cumulativeInsCount = 0;
            for (var i = 0; i < animationData.Count; i++)
            {
                var ae = animationData[i];
                ulong tagInsCount = 0;
                switch (ae.entryType)
                {
                    case eTraceUpdateType.eAnimExecTag:
                        if ((int)ae.blockID != -1)
                        {
                            int moduleID = graph.ProcessData.FindContainingModule(graph.ProcessData.GetAddressOfBlock((int)ae.blockID));
                            if (modSegs.Count > 0)
                            {
                                MODULE_SEGMENT lastRec = modSegs[^1];
                                if (lastRec.modID == moduleID)
                                {
                                    lastRec.lastIdx = i;
                                    continue;
                                }
                            }

                            modSegs.Add(new MODULE_SEGMENT()
                            {
                                firstIdx = i,
                                lastIdx = i,
                                modID = moduleID,
                                name = "todo"
                            });

                            if (ae.blockID >= graph.BlocksFirstLastNodeList.Count)
                                continue;
                            tagInsCount = (graph.BlocksFirstLastNodeList[(int)ae.blockID].Item2 -
                                graph.BlocksFirstLastNodeList[(int)ae.blockID].Item1) + 1;
                        }
                        break;
                    case eTraceUpdateType.eAnimUnchainedResults:
                        if (ae.edgeCounts is null) break;

                        foreach (var edge in ae.edgeCounts)
                        {
                            ulong block = edge.Item1;
                            if ((int)block < graph.BlocksFirstLastNodeList.Count)
                            {
                                var nodeRange = graph.BlocksFirstLastNodeList[(int)block];
                                if (nodeRange != null)
                                {
                                    uint blockInsCt = (nodeRange.Item2 - nodeRange.Item1) + 1;
                                    tagInsCount += blockInsCt * edge.Item2;
                                }
                            }
                            else break;
                        }
                        break;
                }

                cumulativeInsCount += tagInsCount;
                segmentBlockInsCount += tagInsCount;
                segmentBlockCount += 1;


                int currentPlotXPixel = (int)Math.Floor(barWidth * ((float)i / (float)animationData.Count));

                if (currentPlotXPixel > lastPlotXPixel)
                {

                    pixCumul[currentPlotXPixel] = (double)cumulativeInsCount / (double)graph.TotalInstructions;
                    double segmentAvg = (double)segmentBlockInsCount / (double)segmentBlockCount;
                    pixAvg[currentPlotXPixel] = segmentAvg;
                    if (segmentAvg > highestSegmentAvg)
                        highestSegmentAvg = segmentAvg;

                    segmentBlockInsCount = 0;
                    segmentBlockCount = 0;
                }
            }

            var keys = pixAvg.Keys.ToArray();
            foreach (int pix in keys)
            {
                pixAvg[pix] = pixAvg[pix] / highestSegmentAvg;
            }




            if (graph.Terminated)
            {
                _avgs[graph] = pixAvg;
                _cumuls[graph] = pixCumul;
                _modSegs[graph] = modSegs;
            }
        }

        ProtoGraph _lastGeneratedReplayGraph = null;

        //todo lots of opportunity for caching here
        public void GenerateReplay(ProtoGraph graph)
        {

            if (_newWidth != _width || _newHeight != _height)
            {
                CreateTextures(_newWidth, _newHeight);
            }
            else
            {
                if (graph == _lastGeneratedReplayGraph) return;
            }
            _lastGeneratedReplayGraph = graph;

            _moduleTexts.Clear();
            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();
            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();
            WritableRgbaFloat plotLineColour = Themes.GetThemeColourWRF(Themes.eThemeColour.eVisBarPlotLine);
            List<MODULE_SEGMENT> moduleAreas = new List<MODULE_SEGMENT>();

            List<ANIMATIONENTRY> animationData = graph.GetSavedAnimationData();
            if (animationData.Count == 0) return;

            //Draw cumulative instruction count plot
            ulong cumulativeInsCount = 0;
            int lastPlotXPixel = -1;
            float thirdHeight = (float)Math.Floor(_height / 3);
            Vector2 lastCumuLinePos = new Vector2(0, thirdHeight);
            Vector2 lastAvgLinePos = new Vector2(0, thirdHeight);

            MaxBlockWorkCount(graph, _width, out Dictionary<int, double> cumuls, out Dictionary<int, double> avgs, out List<MODULE_SEGMENT> modsegs);

            foreach (KeyValuePair<int, double> cumulativeInsLinePixel in cumuls)
            {
                int currentPlotXPixel = cumulativeInsLinePixel.Key;
                double cumulativeProportion = cumulativeInsLinePixel.Value;
                double avgProportion = avgs[currentPlotXPixel];

                //draw the cumulative instruction count line
                lines.Add(new Position2DColour()
                {
                    Color = plotLineColour,
                    Position = lastCumuLinePos
                });
                float yHeight = thirdHeight - ((thirdHeight - 1) * (float)cumulativeProportion);
                Vector2 thisLinePos = new Vector2(currentPlotXPixel, yHeight);
                lines.Add(new Position2DColour()
                {
                    Color = plotLineColour,
                    Position = thisLinePos
                });
                lastCumuLinePos = thisLinePos;


                //draw the avg instruction count line
                lastPlotXPixel = currentPlotXPixel;
                lines.Add(new Position2DColour()
                {
                    Color = new WritableRgbaFloat(Color.Gold),
                    Position = lastAvgLinePos
                });

                yHeight = thirdHeight - (float)((thirdHeight - 1) * avgProportion);
                thisLinePos = new Vector2(currentPlotXPixel, yHeight);
                lines.Add(new Position2DColour()
                {
                    Color = new WritableRgbaFloat(Color.Gold),
                    Position = thisLinePos
                });
                lastAvgLinePos = thisLinePos;
            }


            for (float x = 0; x < _width; x++)
            {
                int entryIdx = (int)Math.Floor((x / (float)_width) * animationData.Count);
                ANIMATIONENTRY sample = animationData[entryIdx];
                if ((int)sample.blockID != -1)
                {
                    if (sample.blockID >= graph.BlocksFirstLastNodeList.Count) continue;
                    Tuple<uint, uint> blockNodes = graph.BlocksFirstLastNodeList[(int)sample.blockID];
                    if (blockNodes == null)
                    {
                        continue; //.idata thunk
                    }
                    int blockTailIdx = (int)blockNodes.Item2;
                    if (graph.NodeList.Count > blockTailIdx)
                    {
                        // colour from heat ranking of final node
                        NodeData node = graph.NodeList[blockTailIdx];
                        Debug.Assert(node.heatRank >= 0 && node.heatRank <= 9);
                        WritableRgbaFloat heatColour = Themes.GetThemeColourWRF((Themes.eThemeColour)
                            ((float)Themes.eThemeColour.eHeat0Lowest + node.heatRank));
                        //Console.WriteLine($"x: {x}, animidx: {entryIdx} node:{node.index} rank:{node.heatRank}");
                        lines.Add(new Position2DColour()
                        {
                            Color = heatColour,
                            Position = new Vector2(x, thirdHeight + 1)
                        });
                        lines.Add(new Position2DColour()
                        {
                            Color = heatColour,
                            Position = new Vector2(x, thirdHeight * 2)
                        });
                    }

                }
            }

            float baseThirdStart = thirdHeight * 2 + 1;
            float baseThirdEnd = _height - 2;

            foreach (MODULE_SEGMENT seg in modsegs)
            {
                WritableRgbaFloat segColour = new WritableRgbaFloat(Color.White);
                float startX = _width * ((float)seg.firstIdx / (float)animationData.Count);
                float endX = _width * ((float)seg.lastIdx / (float)animationData.Count);

                //left border
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(startX, baseThirdStart) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(startX, baseThirdEnd) });
                //top
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(startX, baseThirdStart) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(endX, baseThirdStart) });
                //base
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(startX, baseThirdEnd) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(endX, baseThirdEnd) });
                //right border
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(endX, baseThirdStart) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(endX, baseThirdEnd) });

                MODULE_LABEL label = new MODULE_LABEL
                {
                    startX = startX + 2,
                    endX = endX - 2,
                    modID = seg.modID,
                    name = seg.name
                };
                _moduleTexts.Add(label);
            }

            /*
            for (var i = 1; i < entries.Count + 1; i++)
            {
                int backIdx = entries.Count - i;
                ANIMATIONENTRY ae = entries[backIdx];
                float Xoffset = (width - pSep * backIdx) - tagWidth;

                Xoffset -= scrollOffset;

                //Draw API icon
                if ((int)ae.blockID == -1)
                {
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.blockAddr, out int moduleID, out string? module, out string? symbol);
                    if (found)
                    {
                        DrawAPIEntry(Xoffset + 2, 33, pSep, moduleID, module, symbol, ref lines);

                    }

                }
                else
                {
                    //Draw Module location bits
                    int moduleID = graph.ProcessData.FindContainingModule(graph.ProcessData.GetAddressOfBlock((int)ae.blockID));
                    if (moduleAreas.Count > 0)
                    {
                        MODULE_SEGMENT lastRec = moduleAreas[^1];
                        if (lastRec.lastIdx == (backIdx + 1) && lastRec.modID == moduleID)
                        {
                            lastRec.lastIdx = backIdx;
                            continue;
                        }
                    }

                    moduleAreas.Add(new MODULE_SEGMENT()
                    {
                        firstIdx = backIdx,
                        lastIdx = backIdx,
                        modID = moduleID
                    });

                }
            }

            for (var i = 0; i < moduleAreas.Count; i++)
            {
                MODULE_SEGMENT ms = moduleAreas[i];
                WritableRgbaFloat segColour = new WritableRgbaFloat(Color.GhostWhite);


                float startX = (ms.firstIdx + 1) * pSep;
                float endX = ms.lastIdx * pSep + 1;
                MODULE_LABEL label = new MODULE_LABEL
                {
                    startX = (width - startX) + 2,
                    endX = width - (endX + 2),
                    modID = ms.modID,
                    name = ms.name
                };
                _moduleTexts.Add(label);

                //left border
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - startX, 33f) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - startX, 48f) });
                //top
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - startX, 33f) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - endX, 33f) });
                //base
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - startX, 48f) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - endX, 48f) });
                //right border
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - endX, 33f) });
                lines.Add(new Position2DColour() { Color = segColour, Position = new Vector2(width - endX, 48f) });
            }
            */

            _pointVerts = points.ToArray();
            _lineVerts = lines.Concat(busyCountLinePoints).ToArray();
            _triangleVerts = triangles.ToArray();
        }


    }
}
