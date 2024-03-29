﻿using ImGuiNET;
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
    /// <summary>
    /// Create an animation progress control bar which doubles as an extra visualiser
    /// </summary>
    internal class VisualiserBar
    {
        /// <summary>
        /// Create a visualiser bar for the specified device and controller
        /// </summary>
        /// <param name="graphicsDev">Veldrid GraphicsDevice to render on</param>
        /// <param name="controller">ImGui Controller</param>
        public VisualiserBar(GraphicsDevice graphicsDev, ImGuiController controller)
        {
            _gd = graphicsDev;
            _factory = _gd.ResourceFactory;
            _controller = controller;
            InitGraphics();
        }

        private readonly ImGuiController _controller;
        private readonly GraphicsDevice _gd;
        private readonly ResourceFactory _factory;
        private Pipeline? _lineListPipeline, _pointPipeline, _triPipeline;
        private ResourceLayout? _rsrcLayout;
        private DeviceBuffer? _pointsVertexBuffer, _pointsIndexBuffer;
        private DeviceBuffer? _linesVertexBuffer, _linesIndexBuffer;
        private DeviceBuffer? _trisVertexBuffer, _trisIndexBuffer;
        private Texture? _outputTexture;
        private Framebuffer? _outputFramebuffer;
        private DeviceBuffer? _paramsBuffer;
        private ResourceSet? _rsrcs;
        private TextureView? _iconsTextureView;
        private Position2DColour[]? _pointVerts;
        private Position2DColour[]? _lineVerts;
        private Position2DColour[]? _triangleVerts;

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
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription
            {
                BlendState = BlendStateDescription.SingleAlphaBlend,
                DepthStencilState = DepthStencilStateDescription.Disabled,
                RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: false,
                scissorTestEnabled: false),
                ResourceLayouts = new[] { _rsrcLayout },
                ShaderSet = SPIRVShaders.CreateVisBarPointIconShader(_gd)
            };

            CreateTextures(1, 1);

            _pointsVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarPointsVertexInitial");
            _linesVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarLinesVertexInitial");
            _trisVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.VertexBuffer, name: "VisBarTrisVertexInitial");
            _pointsIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");
            _linesIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");
            _trisIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 2, BufferUsage.IndexBuffer, name: "VisBarPointsIndexInitial");



            pipelineDescription.Outputs = _outputFramebuffer!.OutputDescription;

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

        private float _width;
        private float _height;
        private float _newWidth = 400, _newHeight = 80;

        private void CreateTextures(float width, float height)
        {
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
        }

        private void MaintainBuffers()
        {
            if (_pointVerts is null || _lineVerts is null || _triangleVerts is null)
            {
                return;//shouldnt be called before generatelive/generatereplay
            }

            uint requiredSize = (uint)_pointVerts.Length * Position2DColour.SizeInBytes;
            if (_pointsVertexBuffer!.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_pointsVertexBuffer);
                _pointsVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarPointsVertex");
                VeldridGraphBuffers.VRAMDispose(_pointsIndexBuffer);
                _pointsIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_pointVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarPointsIndex");

            }

            requiredSize = (uint)_lineVerts.Length * Position2DColour.SizeInBytes;
            if (_linesVertexBuffer!.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_linesVertexBuffer);
                _linesVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarLinesVertex");
                VeldridGraphBuffers.VRAMDispose(_linesIndexBuffer);
                _linesIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_lineVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarLinesIndex");
            }

            requiredSize = (uint)_triangleVerts.Length * Position2DColour.SizeInBytes;
            if (_trisVertexBuffer!.SizeInBytes < requiredSize)
            {
                VeldridGraphBuffers.VRAMDispose(_trisVertexBuffer);
                VeldridGraphBuffers.VRAMDispose(_trisIndexBuffer);
                _trisVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, requiredSize * 2, BufferUsage.VertexBuffer, name: "VisBarTrisIndex");
                _trisIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)_triangleVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer, name: "VisBarTrisIndex");
            }
        }


        public void Render()
        {
            if (_pointVerts is null || _lineVerts is null || _triangleVerts is null)
            {
                return; //shouldnt be called before generatelive/generatereplay
            }

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

            int[] pointIndices = Enumerable.Range(0, _pointVerts.Length).Select(i => i).ToArray();
            _cl.UpdateBuffer(_pointsIndexBuffer, 0, pointIndices);
            _cl.UpdateBuffer(_linesVertexBuffer, 0, _lineVerts);

            int[] lineIndices = Enumerable.Range(0, _lineVerts.Length).Select(i => i).ToArray();
            _cl.UpdateBuffer(_linesIndexBuffer, 0, lineIndices);
            _cl.UpdateBuffer(_trisVertexBuffer, 0, _triangleVerts);

            int[] triIndices = Enumerable.Range(0, _triangleVerts.Length).Select(i => i).ToArray();
            _cl.UpdateBuffer(_trisIndexBuffer, 0, triIndices);
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, new WritableRgbaFloat(Themes.GetThemeColourUINT(Themes.eThemeColour.VisBarBg)).ToRgbaFloat());

            _cl.SetPipeline(_triPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _trisVertexBuffer);
            _cl.SetIndexBuffer(_trisIndexBuffer, IndexFormat.UInt32);
            _cl.Draw((uint)triIndices.Length);


            _cl.SetPipeline(_lineListPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _linesVertexBuffer);
            _cl.SetIndexBuffer(_linesIndexBuffer, IndexFormat.UInt32);
            _cl.Draw((uint)lineIndices.Length);


            _cl.SetPipeline(_pointPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _pointsVertexBuffer);
            _cl.SetIndexBuffer(_pointsIndexBuffer, IndexFormat.UInt32);
            _cl.Draw((uint)pointIndices.Length);


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
            Debug.Assert(_outputTexture is not null);
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

            if (labels.Any())
            {
                float i = labels[0].startX;
                foreach (var mtxt in labels)
                {
                    if (mtxt.startX < i) continue; //discard instead of overlap
                    imdp.AddText(pos + new Vector2(mtxt.startX, 30), 0xffffffff, mtxt.name);
                    i = mtxt.startX + ImGui.CalcTextSize(mtxt.name).X;
                }
            }
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + _height);
        }


        private float _sliderPosX = -1;


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



            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 10);

            Vector2 AnimationProgressBarPos = ImGui.GetItemRectMin();

            Vector2 SliderRectStart = new Vector2(AnimationProgressBarPos.X, AnimationProgressBarPos.Y);
            Vector2 SliderRectEnd = new Vector2(AnimationProgressBarPos.X + progressBarSize.X, AnimationProgressBarPos.Y + progressBarSize.Y);

            if (ImGui.IsItemActive())
            {
                _sliderPosX = ImGui.GetIO().MousePos.X - ImGui.GetCursorScreenPos().X;
            }
            else
            {

                if (graph != null)
                {
                    float animPercentage = graph.GetAnimationProgress();
                    _sliderPosX = ImGui.GetCursorPosX() + animPercentage * (SliderRectEnd.X - SliderRectStart.X);
                }
            }

            Vector2 SliderArrowDrawPos = new Vector2(AnimationProgressBarPos.X + _sliderPosX, AnimationProgressBarPos.Y - 4);
            if (SliderArrowDrawPos.X < SliderRectStart.X)
            {
                SliderArrowDrawPos.X = AnimationProgressBarPos.X;
            }

            if (SliderArrowDrawPos.X > SliderRectEnd.X)
            {
                SliderArrowDrawPos.X = SliderRectEnd.X;
            }

            float sliderBarPosition = (SliderArrowDrawPos.X - SliderRectStart.X) / progressBarSize.X;
            if (sliderBarPosition <= 0.05)
            {
                SliderArrowDrawPos.X += 1;
            }

            if (sliderBarPosition >= 99.95)
            {
                SliderArrowDrawPos.X -= 1;
            }

            if (ImGui.IsItemActive())
            {
                if (graph != null)
                {
                    graph.SeekToAnimationPosition(sliderBarPosition);
                }
            }
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 0);

            Draw(progressBarSize.X, height);


            ImGuiUtils.RenderArrowsForHorizontalBar(ImGui.GetForegroundDrawList(),
                SliderArrowDrawPos,
                new Vector2(3, 7), progressBarSize.Y, 240f);
        }


        /*
         * Creates a white symbol with a size depending on instruction count. Handles 1 - 194ish instructions length blocks.
         * Any higher will just be the max size symbol.
         */
        private static void CreateExecTagSymbol(float Xoffset, uint insCount, ref List<Position2DColour> lines)
        {
            float remaining = insCount;
            float xMid = Xoffset + 1;
            float yStart = 2;
            float len = Math.Min(remaining, 9) + 1;
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid, yStart) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid, yStart + len) });

            remaining /= 2;
            if (remaining <= 7)
            {
                return;
            }

            len = Math.Min(remaining - 7, 9) + 1;
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 1, yStart) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 1, yStart + len) });

            remaining /= 2;
            if (remaining <= 14)
            {
                return;
            }

            len = Math.Min(remaining - 14, 5) + 1;
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid - 1, yStart + 2) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid - 1, yStart + 2 + len) });

            remaining /= 2;
            if (remaining <= 19)
            {
                return;
            }

            len = Math.Min(remaining - 19, 5) + 1;
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 2, yStart + 2) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.White), Position = new Vector2(xMid + 2, yStart + 2 + len) });
        }

        private static void CreateRect(WritableRgbaFloat colour, float leftX, float topY, float width, float height, ref List<Position2DColour> triangles)
        {
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX, topY) });
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX, topY + height) });
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX + width, topY + height) });
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX + width, topY) });
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX, topY) });
            triangles.Add(new Position2DColour() { Colour = colour, Position = new Vector2(leftX + width, topY + height) });
        }

        private static void DrawAPIEntry(float Xoffset, float Yoffset, float width, int moduleID, string module, string symbol, ref List<Position2DColour> lines)
        {
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Green), Position = new Vector2(Xoffset + 1, Yoffset) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Green), Position = new Vector2(Xoffset + width - 1, Yoffset) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Green), Position = new Vector2(Xoffset + width - 1, Yoffset + 8) });
            lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Green), Position = new Vector2(Xoffset + 1, Yoffset + 8) });
        }

        private class MODULE_SEGMENT
        {
            public int firstIdx;
            public int lastIdx;
            public int modID;
            public string name = "";
        };

        private struct MODULE_LABEL
        {
            public float startX;
            public float endX;
            public int modID;
            public string name;
        };

        private int lastDrawnTagIdx = 0;
        private float barScrollingPos = 0;
        private readonly List<MODULE_LABEL> _moduleTexts = new List<MODULE_LABEL>();
        private readonly object _lock = new object();


        //this is not good code
        public void GenerateLive(ProtoGraph graph)
        {
            const int entryCount = 100;

            if (_newWidth != _width || _newHeight != _height)
            {
                CreateTextures(_newWidth, _newHeight);
            }

            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();

            //Draw Tag visualisation
            int lastIdx = graph.GetRecentAnimationEntries(entryCount, out List<ANIMATIONENTRY> entries);
            if (barScrollingPos == 0 && lastDrawnTagIdx != lastIdx)
            {
                barScrollingPos = 0.05f;
            }

            lastDrawnTagIdx = lastIdx;

            float tagWidth = _width / entryCount;
            float scrollOffset = 0f;
            if (barScrollingPos != 0)
            {
                scrollOffset = (barScrollingPos * tagWidth) - tagWidth;
                barScrollingPos += 0.1f;
                if (barScrollingPos >= 1f)
                {
                    barScrollingPos = 0;
                }
            }

            scrollOffset += _width % tagWidth;
            DrawLiveMainLoop(entries, graph, lines, tagWidth, scrollOffset, out List<MODULE_SEGMENT> moduleAreas);
            DrawLiveModuleAreas(lines, moduleAreas, tagWidth, scrollOffset);


            _pointVerts = points.ToArray();
        }


        private void DrawLiveMainLoop(List<ANIMATIONENTRY> entries, ProtoGraph graph, List<Position2DColour> lines,
            float tagWidth, float scrollOffset, out List<MODULE_SEGMENT> moduleAreas)
        {
            moduleAreas = new List<MODULE_SEGMENT>();
            WritableRgbaFloat goodCol = Themes.GetThemeColourWRF(Themes.eThemeColour.GoodStateColour);
            WritableRgbaFloat badCol = Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour);
            WritableRgbaFloat emphasis = Themes.GetThemeColourWRF(Themes.eThemeColour.Emphasis2);

            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();

            for (var i = 1; i < entries.Count + 1; i++)
            {
                int backIdx = entries.Count - i;
                ANIMATIONENTRY ae = entries[backIdx];
                float Xoffset = (_width - tagWidth * backIdx) - tagWidth;
                Xoffset -= scrollOffset;
                int blkID = (int)ae.BlockID;

                if (blkID < 0 || blkID >= graph.ProcessData.BasicBlocksList.Count)
                {
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.Address, out int moduleID, out string module, out string symbol);
                    CreateRect(found ? goodCol : badCol, (i - 1) * tagWidth - scrollOffset, 32, tagWidth, 48 - 32, ref triangles);
                    continue;
                }

                var blockInstructions = graph.ProcessData.BasicBlocksList[blkID];
                if (blockInstructions is null)
                    continue;
                int insCount = blockInstructions.Item2.Count;

                CreateExecTagSymbol(Xoffset + tagWidth / 2, (uint)insCount, ref lines);
                DrawLiveSymbolBlock(ae, lines, Xoffset, tagWidth, goodCol, badCol);

                //Draw Heatmap visualisation
                if (blkID < graph.BlocksFirstLastNodeList.Count)
                {
                    Tuple<uint, uint>? blockFirstLast = graph.BlocksFirstLastNodeList[blkID];
                    if (blockFirstLast is not null)
                    {
                        int blockTailIdx = (int)blockFirstLast.Item2;
                        WritableRgbaFloat heatColour;
                        if (graph.NodeList.Count > blockTailIdx)
                        {
                            // colour from heat ranking of final node
                            NodeData node = graph.NodeList[blockTailIdx];
                            Debug.Assert(node.HeatRank >= 0 && node.HeatRank <= 9);

                            heatColour = Themes.GetThemeColourWRF((Themes.eThemeColour)((float)Themes.eThemeColour.Heat0Lowest + node.HeatRank));

                            CreateRect(heatColour, Xoffset, 15, tagWidth, 10, ref triangles);
                            DrawRelativeExecCountLine(graph, ae, Xoffset, tagWidth, emphasis, busyCountLinePoints);

                        }
                        else
                        {
                            CreateRect(new WritableRgbaFloat(Color.Green), Xoffset + 2, 13, tagWidth, 8, ref triangles);
                        }
                    }
                }

                _lineVerts = lines.Concat(busyCountLinePoints).ToArray();
                _triangleVerts = triangles.ToArray();



                //Draw API icon - todo above i guess as it wont get here?
                if (blkID == -1)
                {
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.Address, out int moduleID, out string module, out string symbol);
                    if (found)
                    {
                        DrawAPIEntry(Xoffset + 2, 33, tagWidth, moduleID, module, symbol, ref lines);
                    }
                }
                else
                {
                    //Draw Module location bits
                    ulong blockAddr = graph.ProcessData.GetAddressOfBlock((int)ae.BlockID);
                    bool found = graph.ProcessData.FindContainingModule(blockAddr, out int? moduleID);
                    if (!found)
                    {
                        continue;
                    }

                    Debug.Assert(moduleID is not null);

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
                        modID = moduleID.Value,
                        name = System.IO.Path.GetFileName(graph.ProcessData.GetModulePath(moduleID.Value))
                    });

                }
            }

        }

        void DrawLiveSymbolBlock(ANIMATIONENTRY ae, List<Position2DColour> lines, float Xoffset, float tagWidth, 
            WritableRgbaFloat goodCol, WritableRgbaFloat badCol)
        {
            switch (ae.entryType)
            {
                case eTraceUpdateType.eAnimExecTag:
                    break;

                case eTraceUpdateType.eAnimUnchained:
                    {
                        float symbase = 12f;
                        lines.Add(new Position2DColour() { Colour = badCol, Position = new Vector2(Xoffset, 2) });
                        lines.Add(new Position2DColour() { Colour = badCol, Position = new Vector2(Xoffset, symbase) });
                        lines.Add(new Position2DColour() { Colour = badCol, Position = new Vector2(Xoffset, symbase) });
                        lines.Add(new Position2DColour() { Colour = badCol, Position = new Vector2(Xoffset + tagWidth + 1, symbase) });
                    }
                    break;

                case eTraceUpdateType.eAnimUnchainedResults:
                    {
                        //drawPlotLine = true;
                        float symbase = 12f;
                        lines.Add(new Position2DColour() { Colour = goodCol, Position = new Vector2(Xoffset + tagWidth, 2) });
                        lines.Add(new Position2DColour() { Colour = goodCol, Position = new Vector2(Xoffset + tagWidth, symbase) });
                        lines.Add(new Position2DColour() { Colour = goodCol, Position = new Vector2(Xoffset + tagWidth, symbase) });
                        lines.Add(new Position2DColour() { Colour = goodCol, Position = new Vector2(Xoffset, symbase) });
                    }
                    break;

                case eTraceUpdateType.eAnimReinstrument:
                case eTraceUpdateType.eAnimRepExec:
                    //probably not worth drawing
                    break;

                case eTraceUpdateType.eAnimExecException:
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.LightCyan), Position = new Vector2(Xoffset, 2) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.LightCyan), Position = new Vector2(Xoffset + tagWidth, 12f) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.LightCyan), Position = new Vector2(Xoffset + tagWidth, 2) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.LightCyan), Position = new Vector2(Xoffset + tagWidth, 12f) });
                    break;

                default:
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset, 2) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + tagWidth, 12f) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + tagWidth, 2) });
                    lines.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + tagWidth, 12f) });

                    Logging.RecordLogEvent($"VisualiserBar:Live:Unhandled tag type {ae.entryType}");
                    break;
            }

        }

        void DrawRelativeExecCountLine(ProtoGraph graph, ANIMATIONENTRY ae, float Xoffset, float tagWidth, WritableRgbaFloat colour, List<Position2DColour> busyCountLinePoints)
        {
            // plot line from edge counts
            float lineY = 19;
            float lineMax = 2;
            if (graph.BusiestBlockExecCount > 0 && (ae.Count is not 0 || ae.edgeCounts is not null))
            {
                //int blkct = blockTailIdx - (int)graph.BlocksFirstLastNodeList[(int)ae.blockID].Item1;
                //Logging.WriteConsole($"NodeID: {node.index} BlockID: {ae.blockID} BlkSz: {blkct} ThisExecCt:{ae.count} TotlExecCount: {node.executionCount} heatrank: {node.heatRank}");
                float ecountprop = (ae.Count / (float)graph.BusiestBlockExecCount);

                if (busyCountLinePoints.Count > 0)
                {
                    busyCountLinePoints.Add(busyCountLinePoints[^1]);
                    busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset, lineY - lineMax * ecountprop) });
                }
                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset, lineY - lineMax * ecountprop) });
                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + tagWidth / 3, lineY + -(1 + lineMax * ecountprop)) });

                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + tagWidth / 3, lineY - (1 + lineMax * ecountprop)) });
                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + tagWidth / 2, lineY - (2 + lineMax * ecountprop)) });

                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + tagWidth / 2, lineY - (2 + lineMax * ecountprop)) });
                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + 2 * (tagWidth / 3), lineY - (1 + lineMax * ecountprop)) });

                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + 2 * (tagWidth / 3), lineY - (1 + lineMax * ecountprop)) });
                busyCountLinePoints.Add(new Position2DColour() { Colour = colour, Position = new Vector2(Xoffset + tagWidth, lineY - lineMax * ecountprop) });
            }
            else
            {
                if (busyCountLinePoints.Count > 0)
                {
                    busyCountLinePoints.Add(busyCountLinePoints[^1]);
                    busyCountLinePoints.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Gray), Position = new Vector2(Xoffset, lineY + 10) });
                }
                busyCountLinePoints.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Gray), Position = new Vector2(Xoffset, lineY + 10) });
                busyCountLinePoints.Add(new Position2DColour() { Colour = new WritableRgbaFloat(Color.Gray), Position = new Vector2(Xoffset + tagWidth, lineY + 10) });
            }
        }


        void DrawLiveModuleAreas(List<Position2DColour> lines, List<MODULE_SEGMENT> moduleAreas, float tagWidth, float scrollOffset)
        {
            lock (_lock)
            {
                _moduleTexts.Clear();
                for (var i = 0; i < moduleAreas.Count; i++)
                {
                    MODULE_SEGMENT ms = moduleAreas[i];
                    WritableRgbaFloat segColour = new WritableRgbaFloat(Color.GhostWhite);

                    float startX = (ms.firstIdx + 1) * tagWidth + scrollOffset;
                    float endX = ms.lastIdx * tagWidth + 1 + scrollOffset;
                    MODULE_LABEL label = new MODULE_LABEL
                    {
                        startX = (_width - startX) + 2,
                        endX = _width - (endX + 2),
                        modID = ms.modID,
                        name = ms.name
                    };
                    _moduleTexts.Add(label);

                    //left border
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - startX, 33f) });
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - startX, 48f) });
                    //top
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - startX, 33f) });
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - endX, 33f) });
                    //base
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - startX, 48f) });
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - endX, 48f) });
                    //right border
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - endX, 33f) });
                    lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(_width - endX, 48f) });
                }
            }
        }

        private readonly Dictionary<ProtoGraph, Dictionary<int, double>> _cumuls = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        private readonly Dictionary<ProtoGraph, Dictionary<int, double>> _avgs = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        private readonly Dictionary<ProtoGraph, float> _widths = new Dictionary<ProtoGraph, float>();
        private readonly Dictionary<ProtoGraph, List<MODULE_SEGMENT>> _modSegs = new Dictionary<ProtoGraph, List<MODULE_SEGMENT>>();

        private void MaxBlockWorkCount(ProtoGraph graph, float barWidth,
            out Dictionary<int, double> pixCumul,
            out Dictionary<int, double> pixAvg,
            out List<MODULE_SEGMENT> modSegs
            )
        {
            if (_widths.TryGetValue(graph, out float lastWidth) && lastWidth == _width)
            {
                pixCumul = _cumuls[graph];
                pixAvg = _avgs[graph];
                modSegs = _modSegs[graph];
                return;
            }

            List<ANIMATIONENTRY> animationData = graph.GetSavedAnimationDataReference();

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
                        {
                            if ((int)ae.BlockID != -1)
                            {
                                ulong blockAddr = graph.ProcessData.GetAddressOfBlock((int)ae.BlockID);
                                bool found = graph.ProcessData.FindContainingModule(blockAddr, out int? moduleID);
                                if (!found)
                                {
                                    continue;
                                }

                                bool boundary = true;
                                if (modSegs.Count > 0)
                                {
                                    MODULE_SEGMENT lastRec = modSegs[^1];
                                    if (lastRec.modID == moduleID)
                                    {
                                        lastRec.lastIdx = i;
                                        boundary = false;
                                    }
                                }
                                if (boundary)
                                {
                                    modSegs.Add(new MODULE_SEGMENT()
                                    {
                                        firstIdx = i,
                                        lastIdx = i,
                                        modID = moduleID!.Value,
                                        name = System.IO.Path.GetFileName(graph.ProcessData.GetModulePath(moduleID.Value))
                                    });
                                }

                                if (ae.BlockID >= graph.ProcessData.BasicBlocksList.Count)
                                {
                                    continue;
                                }

                                var block = graph.ProcessData.BasicBlocksList[(int)ae.BlockID];
                                if (block is null)
                                {
                                    continue;
                                }
                                tagInsCount = (ulong)block.Item2.Count;
                            }
                        }
                        break;
                    case eTraceUpdateType.eAnimUnchainedResults:
                        {
                            if (ae.edgeCounts is null)
                            {
                                break;
                            }

                            var block = graph.ProcessData.BasicBlocksList[(int)ae.BlockID];
                            if (block is null)
                            {
                                continue;
                            }
                            // add (number of ins in this block * number of edges leaving this node)
                            ulong blockInsCt = (ulong)block.Item2.Count;
                            foreach (var edge in ae.edgeCounts)
                            {
                                tagInsCount += blockInsCt * edge.Item2;
                            }
                        }
                        break;
                }

                cumulativeInsCount += tagInsCount;
                segmentBlockInsCount += tagInsCount;
                segmentBlockCount += 1;


                int currentPlotXPixel = (int)Math.Floor(barWidth * (i / (float)animationData.Count));

                if (currentPlotXPixel > lastPlotXPixel)
                {

                    pixCumul[currentPlotXPixel] = cumulativeInsCount / (double)graph.TotalInstructions;
                    double segmentAvg = segmentBlockInsCount / (double)segmentBlockCount;
                    pixAvg[currentPlotXPixel] = segmentAvg;
                    if (segmentAvg > highestSegmentAvg)
                    {
                        highestSegmentAvg = segmentAvg;
                    }

                    segmentBlockInsCount = 0;
                    segmentBlockCount = 0;
                }
            }

            graph.ReleaseSavedAnimationDataReference();

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
                _widths[graph] = _width;
            }
        }

        private ProtoGraph? _lastGeneratedReplayGraph = null;

        public void GenerateReplay(ProtoGraph graph)
        {

            if (_newWidth != _width || _newHeight != _height)
            {
                CreateTextures(_newWidth, _newHeight);
            }
            else
            {
                if (graph == _lastGeneratedReplayGraph)
                {
                    return;
                }
            }
            _lastGeneratedReplayGraph = graph;

            _moduleTexts.Clear();
            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();
            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();

            //Draw cumulative instruction count plot
            float thirdHeight = (float)Math.Floor(_height / 3);

            List<ANIMATIONENTRY> animationData = graph.GetSavedAnimationDataReference();
            float lineLength = _width * ((float)animationData.Count / (float)graph.UpdateCount);
            MaxBlockWorkCount(graph, lineLength, out Dictionary<int, double> cumuls, out Dictionary<int, double> avgs, out List<MODULE_SEGMENT> modsegs);

            DrawReplayCountLines(lines, thirdHeight, cumuls, avgs);
            if (animationData.Count is not 0)
            {
                GenerateReplayHeatmap(animationData, graph, lines, thirdHeight);
                GenerateReplayModules(graph, lines, thirdHeight, modsegs);
            }

            // Grey out any area of unsaved trace data
            if ((ulong)animationData.Count < graph.UpdateCount)
            {
                WritableRgbaFloat discardedColour = Themes.GetThemeColourWRF((Themes.eThemeColour)((float)Themes.eThemeColour.Dull1));
                float Xoffset = _width * (animationData.Count / (float)graph.UpdateCount);
                float width = _width - Xoffset;
                CreateRect(discardedColour, Xoffset, 0, width, _height, ref triangles);
            }

            _pointVerts = points.ToArray();
            _lineVerts = lines.Concat(busyCountLinePoints).ToArray();
            _triangleVerts = triangles.ToArray();

            graph.ReleaseSavedAnimationDataReference();
        }


        void GenerateReplayHeatmap(List<ANIMATIONENTRY> animationData, ProtoGraph graph, List<Position2DColour> lines, float thirdHeight)
        {
            // Draw heatmap
            for (float x = 0; x < _width; x++)
            {
                int entryIdx = (int)Math.Floor((x / _width) * graph.UpdateCount);
                if (entryIdx >= animationData.Count) break;

                ANIMATIONENTRY sample = animationData[entryIdx];
                if ((int)sample.BlockID != -1)
                {
                    if (sample.BlockID >= graph.BlocksFirstLastNodeList.Count)
                    {
                        continue;
                    }

                    Tuple<uint, uint>? blockNodes = graph.BlocksFirstLastNodeList[(int)sample.BlockID];
                    if (blockNodes == null)
                    {
                        continue; //.idata thunk
                    }
                    int blockTailIdx = (int)blockNodes.Item2;
                    if (graph.NodeList.Count > blockTailIdx)
                    {
                        // colour from heat ranking of final node
                        NodeData node = graph.NodeList[blockTailIdx];
                        Debug.Assert(node.HeatRank >= 0 && node.HeatRank <= 9);
                        WritableRgbaFloat heatColour = Themes.GetThemeColourWRF((Themes.eThemeColour)
                            ((float)Themes.eThemeColour.Heat0Lowest + node.HeatRank));

                        lines.Add(new Position2DColour()
                        {
                            Colour = heatColour,
                            Position = new Vector2(x, thirdHeight + 1)
                        });
                        lines.Add(new Position2DColour()
                        {
                            Colour = heatColour,
                            Position = new Vector2(x, thirdHeight * 2)
                        });
                    }

                }
            }
        }

        void GenerateReplayModules(ProtoGraph graph, List<Position2DColour> lines, float thirdHeight, List<MODULE_SEGMENT> modsegs)
        {
            float baseThirdStart = thirdHeight * 2 + 1;
            float baseThirdEnd = _height - 2;

            //Draw modules
            foreach (MODULE_SEGMENT seg in modsegs)
            {
                WritableRgbaFloat segColour = new WritableRgbaFloat(Color.White);
                float startX = _width * (seg.firstIdx / (float)graph.UpdateCount);
                float endX = _width * (seg.lastIdx / (float)graph.UpdateCount);

                //left border
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(startX, baseThirdStart) });
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(startX, baseThirdEnd) });
                //top
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(startX, baseThirdStart) });
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(endX, baseThirdStart) });
                //base
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(startX, baseThirdEnd) });
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(endX, baseThirdEnd) });
                //right border
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(endX, baseThirdStart) });
                lines.Add(new Position2DColour() { Colour = segColour, Position = new Vector2(endX, baseThirdEnd) });

                MODULE_LABEL label = new MODULE_LABEL
                {
                    startX = startX + 2,
                    endX = endX - 2,
                    modID = seg.modID,
                    name = seg.name
                };
                _moduleTexts.Add(label);
            }
        }

        void DrawReplayCountLines(List<Position2DColour> lines, float thirdHeight, Dictionary<int, double> cumuls, Dictionary<int, double> avgs)
        {
            WritableRgbaFloat plotLineColour = Themes.GetThemeColourWRF(Themes.eThemeColour.VisBarPlotLine);
            Vector2 lastCumuLinePos = new Vector2(0, thirdHeight);
            Vector2 lastAvgLinePos = new Vector2(0, thirdHeight);


            foreach (KeyValuePair<int, double> cumulativeInsLinePixel in cumuls)
            {
                int currentPlotXPixel = cumulativeInsLinePixel.Key;
                double cumulativeProportion = cumulativeInsLinePixel.Value;
                double avgProportion = avgs[currentPlotXPixel];

                //draw the cumulative instruction count line
                lines.Add(new Position2DColour()
                {
                    Colour = plotLineColour,
                    Position = lastCumuLinePos
                });
                float yHeight = thirdHeight - ((thirdHeight - 1) * (float)cumulativeProportion);
                Vector2 thisLinePos = new Vector2(currentPlotXPixel, yHeight);
                lines.Add(new Position2DColour()
                {
                    Colour = plotLineColour,
                    Position = thisLinePos
                });
                lastCumuLinePos = thisLinePos;

                //draw the avg instruction count line
                lines.Add(new Position2DColour()
                {
                    Colour = new WritableRgbaFloat(Color.Gold),
                    Position = lastAvgLinePos
                });

                yHeight = thirdHeight - (float)((thirdHeight - 1) * avgProportion);
                thisLinePos = new Vector2(currentPlotXPixel, yHeight);
                lines.Add(new Position2DColour()
                {
                    Colour = new WritableRgbaFloat(Color.Gold),
                    Position = thisLinePos
                });
                lastAvgLinePos = thisLinePos;
            }
        }
    }
}
