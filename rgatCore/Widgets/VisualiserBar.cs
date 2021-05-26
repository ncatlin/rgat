using ImGuiNET;
using rgatCore.Shaders.SPIR_V;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Veldrid;
using static rgatCore.VeldridGraphBuffers;

namespace rgatCore.Widgets
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

        ImGuiController _controller;
        GraphicsDevice _gd;
        ResourceFactory _factory;
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

        void InitGraphics()
        {

            _iconsTextureView = _controller.IconTexturesView;
            _paramsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<BarShaderParams>(), BufferUsage.UniformBuffer));
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
            pipelineDescription.ShaderSet = SPIRVShaders.CreateVisBarPointIconShader(_factory);

            CreateTextures(1, 1);

            _pointsVertexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.VertexBuffer));
            _linesVertexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.VertexBuffer));
            _trisVertexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.VertexBuffer));
            _pointsIndexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.IndexBuffer));
            _linesIndexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.IndexBuffer));
            _trisIndexBuffer = _factory.CreateBuffer(new BufferDescription(2, BufferUsage.IndexBuffer));



            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _lineListPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.TriangleList;
            _triPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);
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
        Position2DColour[] _pointVerts;
        Position2DColour[] _lineVerts;
        Position2DColour[] _triangleVerts;

        void CreateTextures(float width, float height)
        {
            _width = Math.Max(50, width);
            _height = Math.Max(50, height);
            _outputTexture?.Dispose();
            _outputTexture = _factory.CreateTexture(TextureDescription.Texture2D((uint)_width, (uint)_height, 1, 1,
                PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _outputFramebuffer?.Dispose();
            _outputFramebuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));
        }

        void MaintainBuffers()
        {
            uint requiredSize = (uint)_pointVerts.Length * Position2DColour.SizeInBytes;
            if (_pointsVertexBuffer.SizeInBytes < requiredSize)
            {
                _pointsVertexBuffer?.Dispose();
                _pointsVertexBuffer = _factory.CreateBuffer(new BufferDescription(requiredSize * 2, BufferUsage.VertexBuffer));
                _pointsIndexBuffer?.Dispose();
                _pointsIndexBuffer = _factory.CreateBuffer(new BufferDescription((uint)_pointVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer));

            }

            requiredSize = (uint)_lineVerts.Length * Position2DColour.SizeInBytes;
            if (_linesVertexBuffer.SizeInBytes < requiredSize)
            {
                _linesVertexBuffer?.Dispose();
                _linesVertexBuffer = _factory.CreateBuffer(new BufferDescription(requiredSize * 2, BufferUsage.VertexBuffer));
                _linesIndexBuffer?.Dispose();
                _linesIndexBuffer = _factory.CreateBuffer(new BufferDescription((uint)_lineVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer));
            }

            requiredSize = (uint)_triangleVerts.Length * Position2DColour.SizeInBytes;
            if (_trisVertexBuffer.SizeInBytes < requiredSize)
            {
                _trisVertexBuffer?.Dispose();
                _trisVertexBuffer = _factory.CreateBuffer(new BufferDescription(requiredSize * 2, BufferUsage.VertexBuffer));
                _trisIndexBuffer?.Dispose();
                _trisIndexBuffer = _factory.CreateBuffer(new BufferDescription((uint)_triangleVerts.Length * 2 * sizeof(uint), BufferUsage.IndexBuffer));
            }
        }

        public void Draw()
        {

            BarShaderParams shaderParams = new BarShaderParams
            {
                useTexture = false,
                xShift = 0,
                width = _width,
                height = _height
            };
            _gd.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _gd.WaitForIdle();

            MaintainBuffers();

            _gd.UpdateBuffer(_pointsVertexBuffer, 0, _pointVerts);
            _gd.WaitForIdle();

            int[] pointIndices = Enumerable.Range(0, _pointVerts.Length).Select(i => (int)i).ToArray();
            _gd.UpdateBuffer(_pointsIndexBuffer, 0, pointIndices);
            _gd.WaitForIdle();


            _gd.UpdateBuffer(_linesVertexBuffer, 0, _lineVerts);
            _gd.WaitForIdle();

            int[] lineIndices = Enumerable.Range(0, _lineVerts.Length).Select(i => (int)i).ToArray();
            _gd.UpdateBuffer(_linesIndexBuffer, 0, lineIndices);
            _gd.WaitForIdle();


            _gd.UpdateBuffer(_trisVertexBuffer, 0, _triangleVerts);
            _gd.WaitForIdle();

            int[] triIndices = Enumerable.Range(0, _triangleVerts.Length).Select(i => (int)i).ToArray();
            _gd.UpdateBuffer(_trisIndexBuffer, 0, triIndices);
            _gd.WaitForIdle();



            ResourceSetDescription rsrc_rsd = new ResourceSetDescription(_rsrcLayout, _paramsBuffer, _gd.PointSampler, _iconsTextureView);
            _rsrcs?.Dispose();
            _rsrcs = _factory.CreateResourceSet(rsrc_rsd);

            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, new WritableRgbaFloat(GlobalConfig.GetThemeColour(GlobalConfig.eThemeColour.eVisBarBg)).ToRgbaFloat());


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

            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList();
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, _outputTexture);
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: pos,
                p_max: new Vector2(pos.X + _outputTexture.Width, pos.Y + _outputTexture.Height),
                uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));

            foreach (var mtxt in _moduleTexts)
            {
                imdp.AddText(pos + new Vector2(mtxt.startX, 30), 0xffffffff, "start");
            }

            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + _height);
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

        List<MODULE_LABEL> _moduleTexts = new List<MODULE_LABEL>();



        //todo lots of opportunity for caching here
        public void GenerateLive(float width, float height, ProtoGraph graph)
        {

            if (width != _width || height != _height)
            {
                CreateTextures(width, height);
            }

            _moduleTexts.Clear();
            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();
            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();
            WritableRgbaFloat plotLineColour = GlobalConfig.GetThemeColourB(GlobalConfig.eThemeColour.eVisBarPlotLine);
            List<MODULE_SEGMENT> moduleAreas = new List<MODULE_SEGMENT>();

            //Draw Tag visualisation
            int entryCount = 100;
            int lastIdx = graph.GetRecentAnimationEntries(entryCount, out List<ANIMATIONENTRY> entries);
            if (barScrollingPos == 0 && lastDrawnTagIdx != lastIdx)
                barScrollingPos = 0.05f;
            lastDrawnTagIdx = lastIdx;

            float pSep = width / entryCount;
            float tagWidth = 3;
            float scrollOffset = 0f;
            if (barScrollingPos != 0)
            {
                scrollOffset = (barScrollingPos * pSep) - pSep;
                barScrollingPos += 0.1f;
                if (barScrollingPos >= 1f) barScrollingPos = 0;
            }
            scrollOffset += width % pSep;

            for (var i = 1; i < entries.Count + 1; i++)
            {
                int backIdx = entries.Count - i;
                ANIMATIONENTRY ae = entries[backIdx];
                float Xoffset = (width - pSep * backIdx) - tagWidth;

                Xoffset -= scrollOffset;
                bool drawPlotLine;
                //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Cyan), Position = new Vector2(Xoffset, 0) });
                //lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Cyan), Position = new Vector2(Xoffset, 50) });
                if ((int)ae.blockID != -1)
                {
                    var blockFirstLast = graph.BlocksFirstLastNodeList[(int)ae.blockID];
                    uint insCount = (blockFirstLast.Item2 - blockFirstLast.Item1) + 1;
                    CreateExecTagSymbol(Xoffset + pSep / 2, insCount, ref lines);
                }

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

                    default:
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset, 2) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 12f) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 2) });
                        lines.Add(new Position2DColour() { Color = new WritableRgbaFloat(Color.Magenta), Position = new Vector2(Xoffset + pSep, 12f) });

                        Console.WriteLine($"Unhandled tag type {ae.entryType}");
                        break;
                }


                //Draw Heatmap visualisation

                if ((int)ae.blockID != -1)
                {
                    int blockTailIdx = (int)graph.BlocksFirstLastNodeList[(int)ae.blockID].Item2;
                    WritableRgbaFloat heatColour;
                    if (graph.NodeList.Count > blockTailIdx)
                    {
                        // colour from heat ranking of final node
                        NodeData node = graph.NodeList[blockTailIdx];
                        Debug.Assert(node.heatRank >= 0 && node.heatRank <= 9);
                        heatColour = GlobalConfig.GetThemeColourB((GlobalConfig.eThemeColour)((float)GlobalConfig.eThemeColour.eHeat0Lowest + node.heatRank));

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

                }


                //Draw API icon
                if ((int)ae.blockID == -1)
                {
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.blockAddr, out int moduleID, out string module, out string symbol);
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


            _pointVerts = points.ToArray();
            _lineVerts = lines.Concat(busyCountLinePoints).ToArray();
            _triangleVerts = triangles.ToArray();
        }


        Dictionary<ProtoGraph, Dictionary<int, double>> _cumuls = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        Dictionary<ProtoGraph, Dictionary<int, double>> _avgs = new Dictionary<ProtoGraph, Dictionary<int, double>>();
        Dictionary<ProtoGraph, List<MODULE_SEGMENT>> _modSegs = new Dictionary<ProtoGraph, List<MODULE_SEGMENT>>();

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
            int currentModule = -1;
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


                            tagInsCount = (graph.BlocksFirstLastNodeList[(int)ae.blockID].Item2 -
                                graph.BlocksFirstLastNodeList[(int)ae.blockID].Item1) + 1;
                        }
                        break;
                    case eTraceUpdateType.eAnimUnchainedResults:
                        foreach (var edge in ae.edgeCounts)
                        {
                            ulong block = edge.Item1;
                            var nodeRange = graph.BlocksFirstLastNodeList[(int)block];
                            uint blockInsCt = (nodeRange.Item2 - nodeRange.Item1) + 1;
                            tagInsCount += blockInsCt * edge.Item2;
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


        //todo lots of opportunity for caching here
        public void GenerateReplay(float width, float height, ProtoGraph graph)
        {
            
            if (width != _width || height != _height)
            {
                CreateTextures(width, height);
            }

            _moduleTexts.Clear();
            List<Position2DColour> points = new List<Position2DColour>();
            List<Position2DColour> lines = new List<Position2DColour>();
            List<Position2DColour> triangles = new List<Position2DColour>();
            List<Position2DColour> busyCountLinePoints = new List<Position2DColour>();
            WritableRgbaFloat plotLineColour = GlobalConfig.GetThemeColourB(GlobalConfig.eThemeColour.eVisBarPlotLine);
            List<MODULE_SEGMENT> moduleAreas = new List<MODULE_SEGMENT>();

            List<ANIMATIONENTRY> animationData = graph.GetSavedAnimationData();
            if (animationData.Count == 0) return;

            //Draw cumulative instruction count plot
            ulong cumulativeInsCount = 0;
            int lastPlotXPixel = -1;
            float thirdHeight = (float)Math.Floor(height/3);
            Vector2 lastCumuLinePos = new Vector2(0, thirdHeight);
            Vector2 lastAvgLinePos = new Vector2(0, thirdHeight);

            MaxBlockWorkCount(graph, width, out Dictionary<int, double> cumuls, out Dictionary<int, double> avgs, out List<MODULE_SEGMENT> modsegs);

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


            for (float x = 0; x < width; x++)
            {
                int entryIdx = (int)Math.Floor((x / (float)width) * animationData.Count);
                ANIMATIONENTRY sample = animationData[entryIdx];
                if ((int)sample.blockID != -1)
                {
                    int blockTailIdx = (int)graph.BlocksFirstLastNodeList[(int)sample.blockID].Item2;
                    if (graph.NodeList.Count > blockTailIdx)
                    {
                        // colour from heat ranking of final node
                        NodeData node = graph.NodeList[blockTailIdx];
                        Debug.Assert(node.heatRank >= 0 && node.heatRank <= 9);
                        WritableRgbaFloat heatColour = GlobalConfig.GetThemeColourB((GlobalConfig.eThemeColour)
                            ((float)GlobalConfig.eThemeColour.eHeat0Lowest + node.heatRank));
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

            float baseThirdStart = thirdHeight*2 + 1;
            float baseThirdEnd = height - 2;

            foreach (MODULE_SEGMENT seg in modsegs)
            {
                WritableRgbaFloat segColour = new WritableRgbaFloat(Color.White);
                float startX = width * ((float)seg.firstIdx / (float)animationData.Count);
                float endX = width * ((float)seg.lastIdx / (float)animationData.Count);

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
                    endX = endX -2,
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
                    bool found = graph.ProcessData.ResolveSymbolAtAddress(ae.blockAddr, out int moduleID, out string module, out string symbol);
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
