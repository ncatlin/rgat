using ImGuiNET;
using rgatCore.Shaders.SPIR_V;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
        Pipeline _edgesPipelineRaw, _pointsPipeline;
        ResourceLayout _rsrcLayout;
        DeviceBuffer _NodeVertexBuffer, _NodeIndexBuffer;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
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
            pipelineDescription.DepthStencilState = DepthStencilStateDescription.DepthOnlyLessEqual;
            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: false,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _rsrcLayout };
            pipelineDescription.ShaderSet = SPIRVShaders.CreateVisBarPointIconShader(_factory, out _NodeVertexBuffer, out _NodeIndexBuffer);

            _NodeIndexBuffer = _factory.CreateBuffer(new BufferDescription((uint)100 * sizeof(uint), BufferUsage.IndexBuffer));
            _NodeVertexBuffer = _factory.CreateBuffer(new BufferDescription((uint)100 * sizeof(uint), BufferUsage.VertexBuffer));


            Debug.Assert(_outputTexture == null);
            Debug.Assert(_outputFramebuffer == null);

            _outputTexture?.Dispose();
            _outputTexture = _factory.CreateTexture(TextureDescription.Texture2D(600, 50, 1, 1,
                PixelFormat.R32_G32_B32_A32_Float, TextureUsage.RenderTarget | TextureUsage.Sampled));

            _outputFramebuffer?.Dispose();
            _outputFramebuffer = _factory.CreateFramebuffer(new FramebufferDescription(null, _outputTexture));

            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRawShaders(_factory, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipelineRaw = _factory.CreateGraphicsPipeline(pipelineDescription);
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct BarShaderParams
        {
            public bool useTexture;
            public float xShift;
            public float width;
            public float height;
        }

        public void Generate(float width, ProtoGraph graph)
        {
            float height = 50;

            Matrix4x4 proj =  Matrix4x4.CreatePerspectiveFieldOfView(1f, (float)600 / 50, 1, 2);

            BarShaderParams shaderParams = new BarShaderParams
            {
                useTexture = false,
                xShift = 0,
                width = 600,
                height = 50
            };
            _gd.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _gd.WaitForIdle();

            Random rnd = new Random();
            TextureOffsetColour[] NodeVerts = new TextureOffsetColour[5];
            NodeVerts[0] = new TextureOffsetColour { Color = new WritableRgbaFloat(Color.Red), TexPosition = new Vector2(0, 0 )};

            NodeVerts[1] = new TextureOffsetColour { Color = new WritableRgbaFloat(Color.LightCyan), TexPosition = new Vector2(50, 20) };
            NodeVerts[2] = new TextureOffsetColour { Color = new WritableRgbaFloat(Color.White), TexPosition = new Vector2(400, 30) };
            NodeVerts[3] = new TextureOffsetColour { Color = new WritableRgbaFloat(Color.Coral), TexPosition = new Vector2(150, 40) };
            NodeVerts[4] = new TextureOffsetColour { Color = new WritableRgbaFloat(Color.PaleGreen), TexPosition = new Vector2(190, 45) };

            _gd.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            _gd.WaitForIdle();

            List<uint> nodeIndices = new List<uint>() { 0 , 1, 2, 3, 4 };
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());
            _gd.WaitForIdle();

            ResourceSetDescription rsrc_rsd = new ResourceSetDescription(_rsrcLayout, _paramsBuffer, _gd.PointSampler, _iconsTextureView);
            _rsrcs?.Dispose();
            _rsrcs = _factory.CreateResourceSet(rsrc_rsd);

            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, new WritableRgbaFloat(Color.Black).ToRgbaFloat());//  GlobalConfig.mainColours.background.ToRgbaFloat());

            _cl.SetPipeline(_pointsPipeline);
            _cl.SetGraphicsResourceSet(0, _rsrcs);
            _cl.SetVertexBuffer(0, _NodeVertexBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            _cl.End();
            _gd.SubmitCommands(_cl);
            _gd.WaitForIdle();

            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList();
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, _outputTexture);
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId, p_min: pos,
                p_max: new Vector2(pos.X + _outputTexture.Width, pos.Y + _outputTexture.Height),
                uv_min: new Vector2(0, 1), uv_max: new Vector2(1, 0));


            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + height + 14);
        }


        int lastDrawnTagIdx = 0;
        float barScrollingPos = 0;
        public void Draw(float width, ProtoGraph graph)
        {

            float height = 30;
            Vector2 start = ImGui.GetItemRectMin();
            Vector2 end = start + new Vector2(width, 30);
            ImGui.GetWindowDrawList().AddRectFilled(start, end, 0xff000000);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + height + 14);

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
                scrollOffset = (barScrollingPos * pSep);
                barScrollingPos += 0.1f;
                if (barScrollingPos >= 1f) barScrollingPos = 0;
            }

            int prevBlockID = -1;
            for (var i = 1; i < entries.Count + 1; i++)
            {
                int backIdx = entries.Count - i;
                ANIMATIONENTRY ae = entries[backIdx];
                float Xoffset = (end.X - pSep * backIdx) - tagWidth;
                Xoffset -= scrollOffset;

                switch (ae.entryType)
                {
                    case eTraceUpdateType.eAnimExecTag:
                        ImGui.GetWindowDrawList().AddCircleFilled(new Vector2(Xoffset + tagWidth / 2, start.Y + 4f),
                           2.5f, new WritableRgbaFloat(Color.White).ToUint());
                        break;
                    case eTraceUpdateType.eAnimUnchained:
                        Vector2[] points = { new Vector2(Xoffset + 6f, start.Y + 1f),
                                             new Vector2(Xoffset,     start.Y + 1f),
                                             new Vector2(Xoffset,     start.Y + 8f),
                                             new Vector2(Xoffset + 6f, start.Y + 8f) };
                        ImGui.GetWindowDrawList().AddPolyline(ref points[0], 4, new WritableRgbaFloat(Color.Red).ToUint(), false, 1);
                        ImGui.GetWindowDrawList().AddBezierCurve(points[0], points[1], points[2], points[3], new WritableRgbaFloat(Color.Red).ToUint(), 1);
                        break;
                    case eTraceUpdateType.eAnimUnchainedDone:
                        Vector2[] points2 = { new Vector2(Xoffset,     start.Y + 1f),
                                              new Vector2(Xoffset + 6f, start.Y + 1f),
                                              new Vector2(Xoffset + 6f, start.Y + 8f),
                                              new Vector2(Xoffset,     start.Y + 8f) };
                        ImGui.GetWindowDrawList().AddPolyline(ref points2[0], 4, new WritableRgbaFloat(Color.Orange).ToUint(), false, 1);
                        break;
                    case eTraceUpdateType.eAnimUnchainedResults:
                        Vector2[] points3 = { new Vector2(Xoffset,   start.Y + 1f),
                                            new Vector2(Xoffset + 6f, start.Y + 1f),
                                            new Vector2(Xoffset + 6f, start.Y + 8f),
                                            new Vector2(Xoffset,     start.Y + 8f) };
                        ImGui.GetWindowDrawList().AddPolyline(ref points3[0], 4, new WritableRgbaFloat(Color.LimeGreen).ToUint(), false, 1);
                        ImGui.GetWindowDrawList().AddBezierCurve(points3[0], points3[1], points3[2], points3[3], new WritableRgbaFloat(Color.Red).ToUint(), 1);
                        break;
                    default:
                        ImGui.GetWindowDrawList().AddRectFilled(new Vector2(Xoffset, start.Y + 1),
                            new Vector2(Xoffset + tagWidth, start.Y + 6),
                            new WritableRgbaFloat(Color.Orange).ToUint());
                        Console.WriteLine($"Unhandled tag type {ae.entryType}");
                        break;

                }

                if (ae.entryType == eTraceUpdateType.eAnimExecTag)
                {
                    if (prevBlockID != -1 && (int)ae.blockID != -1)
                    {
                        uint lastblockEnd = graph.BlocksFirstLastNodeList[prevBlockID].Item2;
                        uint blockStart = graph.BlocksFirstLastNodeList[(int)ae.blockID].Item1;
                        Tuple<uint, uint> edgeTup = new Tuple<uint, uint>(lastblockEnd, blockStart);
                        WritableRgbaFloat heatColour;
                        if (graph.edgeDict.TryGetValue(edgeTup, out EdgeData edge))
                        {
                            switch (edge.heatRank)
                            {
                                case 0:
                                    heatColour = new WritableRgbaFloat(0, 0, 1, 0.7f);
                                    break;
                                case 1:
                                    heatColour = new WritableRgbaFloat(0.1f, 0, 0.9f, 1);
                                    break;
                                case 2:
                                    heatColour = new WritableRgbaFloat(0.3f, 0, 0.7f, 1);
                                    break;
                                case 3:
                                    heatColour = new WritableRgbaFloat(0.5f, 0, 0.5f, 1);
                                    break;
                                case 4:
                                    heatColour = new WritableRgbaFloat(0.3f, 0, 0.7f, 1);
                                    break;
                                case 5:
                                    heatColour = new WritableRgbaFloat(0.9f, 0, 0.1f, 1);
                                    break;
                                case 6:
                                    heatColour = new WritableRgbaFloat(1, 0, 1, 1);
                                    break;
                                case 7:
                                    heatColour = new WritableRgbaFloat(1, 0.3f, 1, 1);
                                    break;
                                case 8:
                                    heatColour = new WritableRgbaFloat(1, 0.7f, 1, 1);
                                    break;
                                case 9:
                                    heatColour = new WritableRgbaFloat(1, 1, 1, 1);
                                    break;
                                default:
                                    heatColour = new WritableRgbaFloat(Color.Green);
                                    break;
                            }
                        }
                        else heatColour = new WritableRgbaFloat(Color.Green);
                        ImGui.GetWindowDrawList().AddRectFilled(
                            new Vector2(Xoffset - 4, start.Y + 11), new Vector2(Xoffset - 4 + tagWidth + pSep, start.Y + 15), heatColour.ToUint());
                    }
                    prevBlockID = (int)ae.blockID;
                }

            }

            //Draw Heatmap visualisation
            // colour from heat ranking of edge(s)



            // plot line from edge counts


            //Draw Module location bit


            //Draw API icons


        }
    }
}
