using rgat.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using Veldrid;
using static rgat.VeldridGraphBuffers;

namespace rgat.Threads
{
    /// <summary>
    /// A worker for rendering the preview graphs of all threads in a trace record
    /// </summary>
    public class PreviewRendererThread : TraceProcessorWorker
    {
        private readonly PreviewGraphsWidget _graphWidget;

        private readonly static Queue<PlottedGraph> renderQueue = new Queue<PlottedGraph>();
        private readonly static Queue<PlottedGraph> priorityQueue = new Queue<PlottedGraph>();

        private readonly static object _lock = new();
        private readonly static ManualResetEventSlim _waitEvent = new();
        private readonly int _idNum;
        private readonly bool _background;

        private readonly rgatState _rgatState;
        private readonly GraphLayoutEngine _layoutEngine;

        private ResourceFactory? _factory;
        private ResourceLayout? _coreRsrcLayout, _nodesEdgesRsrclayout;
        private DeviceBuffer? _paramsBuffer;
        private DeviceBuffer? _EdgeVertBuffer, _EdgeIndexBuffer;
        private DeviceBuffer? _NodeVertexBuffer, _NodeIndexBuffer;
        private readonly TextureView _NodeCircleSpriteview;
        private Pipeline? _edgesPipeline, _pointsPipeline;


        /// <summary>
        /// Fetch the next graph to render
        /// It will first fetch priority graphs (ie: those in the active trace) 
        /// unless the background flag is set
        /// </summary>
        /// <param name="graph"></param>
        public static void AddGraphToPreviewRenderQueue(PlottedGraph graph)
        {
            lock (_lock)
            {
                if (graph.InternalProtoGraph.TraceData == rgatState.ActiveTrace)
                {
                    priorityQueue.Enqueue(graph);
                }
                else
                {
                    renderQueue.Enqueue(graph);
                }

                if (_waitEvent.IsSet is false)
                    _waitEvent.Set();
            }
        }

        /// <summary>
        /// Fetch the next graph to render
        /// </summary>
        /// <returns></returns>
        public static PlottedGraph? FetchRenderTask(bool background)
        {
            try
            {
                lock (_lock)
                {
                    if (background is false)
                    {
                        if (priorityQueue.Count > 0)
                            return priorityQueue.Dequeue();
                    }

                    if (renderQueue.Count > 0)
                    {
                        return renderQueue.Dequeue();
                    }

                    if (background is true)
                    {
                        if (priorityQueue.Count > 0)
                            return priorityQueue.Dequeue();
                    }

                    //Checked all queues, someone else took the task
                    //Sleep so we don't thrash on locks
                    Thread.Sleep(50);
                }
                _waitEvent.Wait(rgatState.ExitToken);

                lock (_lock)
                {
                    if (_waitEvent.IsSet)
                        _waitEvent.Reset();
                }
            }
            catch (Exception e)
            {
                if (rgatState.rgatIsExiting is false)
                    Logging.RecordError($"Preview renderer encountered error fetching new task: {e.Message}");
            }
            return null;
        }

        GraphicsDevice _gdev;

        /// <summary>
        /// Create a preview renderer
        /// </summary>
        public PreviewRendererThread(int workerID, PreviewGraphsWidget widget, ImGuiNET.ImGuiController controller, 
            rgatState clientState,  bool background)
        {
            _idNum = workerID;
            _graphWidget = widget;
            _background = background;
            _rgatState = clientState;
            _gdev = controller.GraphicsDevice;
            _NodeCircleSpriteview = controller.IconTexturesView;
            _factory = _gdev.ResourceFactory;

            _layoutEngine = background ? widget.BackgroundLayoutEngine : widget.ForegroundLayoutEngine;

            SetupRenderingResources();
        }

        /// <summary>
        /// Start this worker
        /// </summary>
        public override void Begin()
        {

            base.Begin();
            WorkerThread = new Thread(ThreadProc)
            {
                Name = $"PreviewWrk_{_idNum}_{(_background ? "BG" : "FG")}"
            };
            WorkerThread.Start();
        }

        bool _stopFlag = false;

        /// <summary>
        /// Exit. This is a placeholder for if/when worker counts 
        /// are changed at runtime
        /// </summary>
        public void Stop()
        {
            lock (_lock)
            {
                _stopFlag = true;
                if (_waitEvent.IsSet is false)
                    _waitEvent.Set();
            }
        }

        /// <summary>
        /// The worker thread entry point
        /// </summary>
        public void ThreadProc()
        {
            Logging.RecordLogEvent($"PreviewRenderThread ThreadProc START", Logging.LogFilterType.BulkDebugLogFile);

            Veldrid.CommandList cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();

            while (!rgatState.rgatIsExiting && _graphWidget == null)
            {
                Thread.Sleep(50);
            }

            while (!rgatState.rgatIsExiting && _stopFlag is false)
            {
                PlottedGraph? graph = FetchRenderTask(_background);
                if (graph is null) continue;


                if (graph != rgatState.ActiveGraph)
                {
                    graph.RenderGraph();
                }

                if (graph.DrawnEdgesCount > 0)
                {
                    if (graph != rgatState.ActiveGraph)
                    {
                        _layoutEngine.Compute(cl, graph, -1, false);
                    }
                    RenderPreview(cl, graph);
                }

                AddGraphToPreviewRenderQueue(graph);
            }
            Finished();
        }


        private void RenderPreview(CommandList cl, PlottedGraph graph)
        {
            if (graph == null || _stopFlag)
            {
                return;
            }

            if (graph._previewFramebuffer1 == null)
            {
                graph.InitPreviewTexture(new Vector2(PreviewGraphsWidget.EachGraphWidth, CONSTANTS.UI.PREVIEW_PANE_GRAPH_HEIGHT), _gdev);
            }


            Logging.RecordLogEvent("render preview 1", filter: Logging.LogFilterType.BulkDebugLogFile);
            bool needsCentering = true;
            if (!_graphWidget.IsCenteringRequired(graph))
            {
                _graphWidget.StartCentering(graph);
            }


            if (needsCentering)
            {
                bool done = CenterGraphInFrameStep(out float maxremaining, _layoutEngine, graph);
                if (done)
                {
                    _graphWidget.StopCentering(graph);
                }
            }

            Position2DColour[] EdgeLineVerts = graph.GetEdgeLineVerts(CONSTANTS.eRenderingMode.eStandardControlFlow,
                out List<uint> edgeDrawIndexes,
                out int edgeVertCount,
                out int drawnEdgeCount);
            if (drawnEdgeCount == 0 || !graph.LayoutState.Initialised)
            {
                return;
            }

            //Logging.RecordLogEvent("render preview 2", filter: Logging.LogFilterType.BulkDebugLogFile);
            cl.Begin();

            var textureSize = graph.LinearIndexTextureSize();
            updateShaderParams(textureSize, graph, cl);

            Position2DColour[] NodeVerts = graph.GetPreviewgraphNodeVerts(CONSTANTS.eRenderingMode.eStandardControlFlow, out List<uint> nodeIndices);

            Debug.Assert(_NodeVertexBuffer!.IsDisposed is false);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * Position2DColour.SizeInBytes ||
                (_NodeIndexBuffer!.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                VeldridGraphBuffers.VRAMDispose(_NodeVertexBuffer);
                _NodeVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewNodeVertexBuffer");

                VeldridGraphBuffers.VRAMDispose(_NodeIndexBuffer);
                _NodeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "PreviewNodeIndexBuffer");
            }
            Debug.Assert((_NodeVertexBuffer.SizeInBytes >= NodeVerts.Length * Position2DColour.SizeInBytes) &&
                (_NodeIndexBuffer!.SizeInBytes >= nodeIndices.Count * sizeof(uint)));

            cl.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            cl.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());

            if (((edgeVertCount * Position2DColour.SizeInBytes) > _EdgeVertBuffer!.SizeInBytes) ||
                (edgeDrawIndexes.Count * sizeof(uint)) > _EdgeIndexBuffer!.SizeInBytes)
            {
                Logging.RecordLogEvent("disposeremake edgeverts", filter: Logging.LogFilterType.BulkDebugLogFile);

                VeldridGraphBuffers.VRAMDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)EdgeLineVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewEdgeVertexBuffer");

                VeldridGraphBuffers.VRAMDispose(_EdgeIndexBuffer);
                _EdgeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "PreviewEdgeIndexBuffer");
            }

            Debug.Assert(((edgeVertCount * sizeof(uint)) <= _EdgeIndexBuffer!.SizeInBytes));

            Logging.RecordLogEvent("render preview 3", filter: Logging.LogFilterType.BulkDebugLogFile);
            cl.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            cl.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gdev.PointSampler,
                graph.LayoutState.PositionsVRAM1, graph.LayoutState.AttributesVRAM1);
            ResourceSet crscore = _factory!.CreateResourceSet(crs_core_rsd);


            Logging.RecordLogEvent($"render preview {graph.TID} creating rsrcset ", filter: Logging.LogFilterType.BulkDebugLogFile);
            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _NodeCircleSpriteview);
            ResourceSet crsnodesedge = _factory.CreateResourceSet(crs_nodesEdges_rsd);



            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / sizeof(uint)));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / sizeof(uint)));

            graph.GetPreviewFramebuffer(out Framebuffer drawtarget);

            cl.SetFramebuffer(drawtarget);

            cl.ClearColorTarget(0, PreviewGraphsWidget.GetGraphBackgroundColour(graph).ToRgbaFloat());
            cl.SetViewport(0, new Viewport(0, 0, PreviewGraphsWidget.EachGraphWidth, PreviewGraphsWidget.EachGraphHeight, -2200, 1000));

            //draw nodes
            cl.SetPipeline(_pointsPipeline);
            cl.SetGraphicsResourceSet(0, crscore);
            cl.SetGraphicsResourceSet(1, crsnodesedge);
            cl.SetVertexBuffer(0, _NodeVertexBuffer);
            cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            cl.DrawIndexed(indexCount: (uint)nodesToDraw, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            //draw edges
            cl.SetPipeline(_edgesPipeline);
            cl.SetVertexBuffer(0, _EdgeVertBuffer);
            cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
            cl.DrawIndexed(indexCount: (uint)edgeVertCount, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            cl.End();
            if (!_stopFlag)
            {
                Logging.RecordLogEvent($"render preview start commands {graph.TID}. Pos{graph.LayoutState.PositionsVRAM1!.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gdev.SubmitCommands(cl);
                Logging.RecordLogEvent($"render preview finished commands {graph.TID}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gdev.WaitForIdle(); //needed?
            }


            graph.ReleasePreviewFramebuffer();

            //Debug.Assert(!_NodeVertexBuffer.IsDisposed);
            crscore.Dispose();
            //Logging.RecordLogEvent($"render preview {graph.TID} disposing rsrcset {nodeAttributesBuffer.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
            crsnodesedge.Dispose();

            Logging.RecordLogEvent("render preview Done", filter: Logging.LogFilterType.BulkDebugLogFile);
        }



        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// </summary>
        private static bool CenterGraphInFrameStep(out float MaxRemaining, GraphLayoutEngine computeEngine, PlottedGraph graph)
        {
            Vector2 size = new Vector2(PreviewGraphsWidget.EachGraphWidth, PreviewGraphsWidget.EachGraphHeight);
            if (!GraphLayoutEngine.GetWidgetFitOffsets(size, graph, isPreview:true, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets))
            {
                MaxRemaining = 0;
                return false;
            }

            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 10, targYpadding = 8;

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < 0)
            {
               // Console.WriteLine("CPG- Zoom to foreground");
                //delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                //float maxdelta = Math.Max(delta, 35);
                //graph.PreviewCameraZoom -= maxdelta;
                //MaxRemaining = maxdelta;
                MaxRemaining = 1;
                graph.CameraState.PreviewCameraZoom = -1 * graphDepth;
                return false;
            }

            //too zoomed in, zoom out
            if ((xoffsets.X < targXpadding && xoffsets.Y < targXpadding) || (yoffsets.X < targYpadding && yoffsets.Y < targYpadding))
            {
                //Console.WriteLine("CPG- Zoom out");
                if (xoffsets.X < targXpadding)
                {
                    delta = Math.Min(targXpadding / 2, (targXpadding - xoffsets.X) / 3f);
                }
                else
                {
                    delta = Math.Min(targYpadding / 2, (targYpadding - yoffsets.Y) / 1.3f);
                }

                //graph.PreviewCameraZoom = -1 * graphDepth;
                
                if (delta > 1)
                {
                    graph.CameraState.PreviewCameraZoom -= graphDepth;
                    MaxRemaining = Math.Abs(delta);
                    return false;
                }
                else
                {
                    zdelta = -1 * delta;
                }
            }

            //too zoomed out, zoom in
            if ((xoffsets.X > targXpadding && xoffsets.Y > targXpadding) && (yoffsets.X > targYpadding && yoffsets.Y > targYpadding))
            {
                //Console.WriteLine("CPG- Zoom in");
                if (zoffsets.X > graphDepth)
                {
                    float distance = zoffsets.X - graphDepth;
                    zdelta += Math.Max(distance / 8, 50);
                }
            }

            //too far left, move right
            if (xoffsets.X < targXpadding)
            {
                Console.WriteLine("CPG- move right");
                float diff = targXpadding - xoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta += delta;
            }

            //too far right, move left
            if (xoffsets.Y < targXpadding)
            {
                Console.WriteLine("CPG- move left");
                float diff = targXpadding - xoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta -= delta;
            }

            //off center, center it
            float XDiff = xoffsets.X - xoffsets.Y;
            if (Math.Abs(XDiff) > 40)
            {
                //Console.WriteLine("CPG- offcenter x1");
                delta = Math.Max(Math.Abs(XDiff / 2), 15);
                if (XDiff > 0)
                {
                    xdelta -= delta;
                }
                else
                {
                    xdelta += delta;
                }
            }


            if (yoffsets.X < targYpadding)
            {
                //Console.WriteLine("CPG- offcenter x2");
                float diff = targYpadding - yoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta += delta;
            }

            if (yoffsets.Y < targYpadding)
            {
//Console.WriteLine("CPG- offcenter y1");
                float diff = targYpadding - yoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta -= delta;
            }

            float YDiff = yoffsets.X - yoffsets.Y;
            if (Math.Abs(YDiff) > 40)
            {
                //Console.WriteLine("CPG- offcenter y2");
                delta = Math.Max(Math.Abs(YDiff / 2), 15);
                if (YDiff > 0)
                {
                    ydelta -= delta;
                }
                else
                {
                    ydelta += delta;
                }
            }


            float actualXdelta = Math.Abs(xdelta);
            if (xdelta > 0)
            {
                graph.CameraState.PreviewCameraXOffset += actualXdelta;
            }
            else
            {
                graph.CameraState.PreviewCameraXOffset -= actualXdelta;
            }

            float actualYdelta = Math.Abs(ydelta);
            if (ydelta > 0)
            {
                graph.CameraState.PreviewCameraYOffset += actualYdelta;
            }
            else
            {
                graph.CameraState.PreviewCameraYOffset -= actualYdelta;
            }

            float actualZdelta = Math.Abs(zdelta);
            if (zdelta > 0)
            {
                graph.CameraState.PreviewCameraZoom += actualZdelta;
            }
            else
            {
                graph.CameraState.PreviewCameraZoom -= actualZdelta;
            }

           

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));


            return Math.Abs(xdelta) < 10 && Math.Abs(ydelta) < 10 && Math.Abs(zdelta) < 10;
        }


        private void SetupRenderingResources()
        {
            Debug.Assert(_gdev is not null, "Init not called");
            _paramsBuffer = TrackedVRAMAlloc(_gdev, (uint)Unsafe.SizeOf<GraphPlotWidget.GraphShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "PreviewPlotparamsBuffer");

            _coreRsrcLayout = _factory!.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));

            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription
            {
                BlendState = BlendStateDescription.SingleAlphaBlend,
                DepthStencilState = new DepthStencilStateDescription(
                depthTestEnabled: true,
                depthWriteEnabled: true,
                comparisonKind: ComparisonKind.LessEqual),
                RasterizerState = new RasterizerStateDescription(
                    cullMode: FaceCullMode.Back,
                    fillMode: PolygonFillMode.Solid,
                    frontFace: FrontFace.Clockwise,
                    depthClipEnabled: false,
                    scissorTestEnabled: false),
                    ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout },
                    ShaderSet = SPIRVShaders.CreateNodeShaders(_gdev, out _NodeVertexBuffer, out _NodeIndexBuffer
                    )
                };

            OutputAttachmentDescription[] oads = { new OutputAttachmentDescription(PixelFormat.R32_G32_B32_A32_Float) };
            pipelineDescription.Outputs = new OutputDescription
            {
                DepthAttachment = null,
                SampleCount = TextureSampleCount.Count1,
                ColorAttachments = oads
            };

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gdev, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);
        }

        private GraphPlotWidget.GraphShaderParams updateShaderParams(uint textureSize, PlottedGraph graph, CommandList cl)
        {
            GraphPlotWidget.GraphShaderParams shaderParams = new GraphPlotWidget.GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = -1,
                isAnimated = false
            };

            shaderParams.nonRotatedView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            shaderParams.proj = PreviewGraphsWidget.PreviewProjection;
            shaderParams.world = graph.CameraState.RotationMatrix;
            shaderParams.view = graph.CameraState.PreviewCameraTranslation;


            cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);

            return shaderParams;
        }

    }
}
