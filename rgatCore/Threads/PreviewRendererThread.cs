using rgat.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
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
        private readonly static List<PlottedGraph> _emptyGraphList = new List<PlottedGraph>();

        private readonly static object _lock = new();
        private readonly static ManualResetEventSlim _waitEvent = new();
        private readonly int _idNum;
        private readonly bool _background;

        private readonly GraphLayoutEngine _layoutEngine;
        private readonly GraphicsDevice _gdev;

        private readonly ResourceFactory? _factory;
        private ResourceLayout? _coreRsrcLayout, _nodesEdgesRsrclayout;
        private DeviceBuffer? _paramsBuffer;
        private DeviceBuffer? _EdgeVertBuffer;
        private DeviceBuffer? _NodeVertexBuffer;
        private readonly TextureView _NodeCircleSpriteview;
        private Pipeline? _edgesPipeline, _pointsPipeline;
        private static Task? _emptyGraphMonitor;
        private Veldrid.CommandList cl;


        /// <summary>
        /// Fetch the next graph to render
        /// It will first fetch priority graphs (ie: those in the active trace) 
        /// unless the background flag is set
        /// </summary>
        /// <param name="plot"></param>
        public static void AddGraphToPreviewRenderQueue(PlottedGraph plot)
        {
            lock (_lock)
            {
                Debug.Assert(priorityQueue.Contains(plot) is false);
                Debug.Assert(renderQueue.Contains(plot) is false);
                Debug.Assert(_emptyGraphList.Contains(plot) is false);

                if (plot.InternalProtoGraph.TraceData == rgatState.ActiveTrace && plot.InternalProtoGraph.EdgeCount > 0)
                {
                    priorityQueue.Enqueue(plot);
                }
                else
                {
                    renderQueue.Enqueue(plot);
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
                        {
                            return priorityQueue.Dequeue();
                        }
                    }

                    if (renderQueue.Count > 0)
                    {
                        return renderQueue.Dequeue();
                    }

                    if (background is true)
                    {
                        if (priorityQueue.Count > 0)
                        {
                            return priorityQueue.Dequeue();
                        }
                    }

                }
                //Checked all queues, someone else took the task
                //Sleep so we don't thrash on locks
                Thread.Sleep(50);
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
                    Logging.RecordException($"Preview renderer encountered error fetching new task: {e.Message}", e);
            }
            return null;
        }


        /// <summary>
        /// Create a preview renderer
        /// </summary>
        public PreviewRendererThread(int workerID, PreviewGraphsWidget widget, ImGuiNET.ImGuiController controller, bool background)
        {
            _idNum = workerID;
            _graphWidget = widget;
            _background = background;
            _gdev = controller.GraphicsDevice;
            _NodeCircleSpriteview = controller.IconTexturesView;
            _factory = _gdev.ResourceFactory;

            _layoutEngine = background ? widget.BackgroundLayoutEngine : widget.ForegroundLayoutEngine;
            cl = _factory.CreateCommandList();
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
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"PreviewRenderThread ThreadProc START", Logging.LogFilterType.BulkDebugLogFile);

            Veldrid.CommandList cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();

            while (!rgatState.rgatIsExiting && _graphWidget == null)
            {
                Thread.Sleep(50);
            }
            lock (_lock)
            {
                if (_emptyGraphMonitor is null)
                {
                    _emptyGraphMonitor = System.Threading.Tasks.Task.Run(() => EmptyGraphTask());
                }
            }

            while (!rgatState.rgatIsExiting && _stopFlag is false)
            {
                PlottedGraph? graph = FetchRenderTask(_background);
                if (graph is null) continue;

                Debug.Assert(priorityQueue.Contains(graph) is false);
                Debug.Assert(renderQueue.Contains(graph) is false);
                Debug.Assert(_emptyGraphList.Contains(graph) is false);


                if (graph != rgatState.ActiveGraph)
                {
                    graph.RenderGraph();
                }

                if (graph.DrawnEdgesCount > 0)
                {
                    if (graph != rgatState.ActiveGraph)
                    {
                        try
                        {
                            _layoutEngine.Compute(cl, graph, -1, false);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Preview Compute Error: {e.Message}", e);
                        }

                    }

                    try
                    {
                        RenderPreview(graph);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Preview Render Error: {e.Message}", e);
                    }
                }
                else
                {
                    if (graph.InternalProtoGraph.EdgeCount == 0)
                    {
                        lock (_lock)
                        {
                            _emptyGraphList.Add(graph);
                        }
                        continue; //don't add this graph back to the queue, nothing to render
                    }
                }

                AddGraphToPreviewRenderQueue(graph);

            }
            Finished();
        }


        /// <summary>
        /// Graphs with no processing to do cause horrible spinning, so have a sleepy 
        /// task queue them occasionally. If they gain some instrumented code they will enter
        /// regular rotation
        /// </summary>
        private async void EmptyGraphTask()
        {
            Stopwatch s = new Stopwatch();
            while (_stopFlag is false && !rgatState.rgatIsExiting)
            {
                PlottedGraph[] graphPlots;
                if (_emptyGraphList.Count > 0)
                {
                    lock (_lock)
                    {
                        graphPlots = _emptyGraphList.ToArray();
                    }
                    foreach (PlottedGraph plot in graphPlots)
                    {
                        if (plot.InternalProtoGraph.EdgeCount > 0)
                        {
                            lock (_lock)
                            {
                                _emptyGraphList.Remove(plot);
                            }
                            AddGraphToPreviewRenderQueue(plot);
                        }
                    }
                }

                try
                {
                    await System.Threading.Tasks.Task.Delay(50, rgatState.ExitToken);
                }
                catch { }
            }
            _emptyGraphList.Clear();
        }


        private unsafe void RenderPreview(PlottedGraph plot)
        {
            if (plot == null || _stopFlag)
            {
                return;
            }

            if (plot._previewFramebuffer1 == null)
            {
                plot.InitPreviewTexture(new Vector2(PreviewGraphsWidget.EachGraphWidth, CONSTANTS.UI.PREVIEW_PANE_GRAPH_HEIGHT), _gdev);
            }

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("render preview 1", filter: Logging.LogFilterType.BulkDebugLogFile);
            bool needsCentering = true;
            if (!_graphWidget.IsCenteringRequired(plot))
            {
                _graphWidget.StartCentering(plot);
            }


            if (needsCentering)
            {
                bool done = CenterGraphInFrameStep(out float maxremaining, plot);
                if (done)
                {
                    _graphWidget.StopCentering(plot);
                }
            }

            Position1DColourMultiVert[] EdgeLineVerts = plot.GetEdgeLineVerts(CONSTANTS.eRenderingMode.eStandardControlFlow,  out int edgeVertCount, preview: true);
            if (edgeVertCount == 0 || !plot.LayoutState.Initialised)
            {
                return;
            }

            //Logging.RecordLogEvent("render preview 2", filter: Logging.LogFilterType.BulkDebugLogFile);

            cl.Begin();

            var textureSize = plot.LinearIndexTextureSize();
            updateShaderParams(textureSize, plot, cl);

            Position1DColour[] NodeVerts = plot.GetPreviewgraphNodeVerts(CONSTANTS.eRenderingMode.eStandardControlFlow, out int nodeCount);
            Debug.Assert(NodeVerts.Length >= nodeCount);

            if (_NodeVertexBuffer!.SizeInBytes < NodeVerts.Length * Position1DColour.SizeInBytes)
            {
                VeldridGraphBuffers.VRAMDispose(_NodeVertexBuffer);
                _NodeVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)NodeVerts.Length * Position1DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewNodeVertexBuffer");
            }
            Debug.Assert(_NodeVertexBuffer.SizeInBytes >= NodeVerts.Length * Position1DColour.SizeInBytes);

            //todo only on change
            fixed (Position1DColour* vertsPtr = NodeVerts)
            {
                cl.UpdateBuffer(_NodeVertexBuffer, 0, (IntPtr)vertsPtr, (uint)nodeCount * Position1DColour.SizeInBytes);
            }

            if ((edgeVertCount * Position1DColourMultiVert.SizeInBytes) > _EdgeVertBuffer!.SizeInBytes)
            {
                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("disposeremake edgeverts", filter: Logging.LogFilterType.BulkDebugLogFile);

                VeldridGraphBuffers.VRAMDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gdev, (uint)EdgeLineVerts.Length * Position1DColourMultiVert.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewEdgeVertexBuffer");
            }

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("render preview 3", filter: Logging.LogFilterType.BulkDebugLogFile);


            //todo - only do this on changes
            fixed (Position1DColourMultiVert* vertsPtr = EdgeLineVerts)
            {
                cl.UpdateBuffer(_EdgeVertBuffer, 0, (IntPtr)vertsPtr, (uint)edgeVertCount * Position1DColourMultiVert.SizeInBytes); 
            }

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gdev.PointSampler,
                plot.LayoutState.PositionsVRAM1, plot.LayoutState.AttributesVRAM1);
            ResourceSet crscore = _factory!.CreateResourceSet(crs_core_rsd);


            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"render preview {plot.TID} creating rsrcset ", filter: Logging.LogFilterType.BulkDebugLogFile);
            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _NodeCircleSpriteview);
            ResourceSet crsnodesedge = _factory.CreateResourceSet(crs_nodesEdges_rsd);

            plot.GetPreviewFramebuffer(out Framebuffer drawtarget);

            cl.SetFramebuffer(drawtarget);

            cl.ClearColorTarget(0, PreviewGraphsWidget.GetGraphBackgroundColour(plot).ToRgbaFloat());
            cl.SetViewport(0, new Viewport(0, 0, PreviewGraphsWidget.EachGraphWidth, PreviewGraphsWidget.EachGraphHeight, -2200, 1000));

            //draw nodes
            cl.SetPipeline(_pointsPipeline);
            cl.SetGraphicsResourceSet(0, crscore);
            cl.SetGraphicsResourceSet(1, crsnodesedge);
            cl.SetVertexBuffer(0, _NodeVertexBuffer);
            cl.Draw((uint)nodeCount);

            //draw edges
            cl.SetPipeline(_edgesPipeline);
            cl.SetVertexBuffer(0, _EdgeVertBuffer);
            cl.Draw((uint)edgeVertCount);

            cl.End();
            if (!_stopFlag)
            {
                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"render preview start commands {plot.TID}. Pos{plot.LayoutState.PositionsVRAM1!.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gdev.SubmitCommands(cl);
                if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"render preview finished commands {plot.TID}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gdev.WaitForIdle(); //needed?
            }


            plot.ReleasePreviewFramebuffer();
            rounds += 1;
            if (rounds % 1 == 0)
            {
                //clear staging buffers
                //https://github.com/mellinoe/veldrid/issues/411
                cl.Dispose();
                cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();
                rounds = 0;
            }
            //Debug.Assert(!_NodeVertexBuffer.IsDisposed);
            crscore.Dispose();
            //Logging.RecordLogEvent($"render preview {graph.TID} disposing rsrcset {nodeAttributesBuffer.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
            crsnodesedge.Dispose();

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent("render preview Done", filter: Logging.LogFilterType.BulkDebugLogFile);
        }
        int rounds = 0;


        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// </summary>
        private static bool CenterGraphInFrameStep(out float MaxRemaining, PlottedGraph plot)
        {
            Vector2 size = new Vector2(PreviewGraphsWidget.EachGraphWidth, PreviewGraphsWidget.EachGraphHeight);
            if (!GraphLayoutEngine.GetWidgetFitOffsets(size, plot, isPreview: true, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets))
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
                plot.CameraState.PreviewCameraZoom = -1 * graphDepth;
                return false;
            }
            float zoomFactor = Math.Abs(plot.CameraState.PreviewCameraZoom) /20;

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
                    plot.CameraState.PreviewCameraZoom -= graphDepth;
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
                //Console.WriteLine("CPG- move right");
                float diff = targXpadding - xoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta += delta;
            }

            //too far right, move left
            if (xoffsets.Y < targXpadding)
            {
                //Console.WriteLine("CPG- move left");
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
                plot.CameraState.PreviewCameraXOffset += actualXdelta;
            }
            else
            {
                plot.CameraState.PreviewCameraXOffset -= actualXdelta;
            }

            float actualYdelta = Math.Abs(ydelta);
            if (ydelta > 0)
            {
                plot.CameraState.PreviewCameraYOffset += actualYdelta;
            }
            else
            {
                plot.CameraState.PreviewCameraYOffset -= actualYdelta;
            }

            float actualZdelta = Math.Abs(zdelta);
            if (zdelta > 0)
            {
                plot.CameraState.PreviewCameraZoom += actualZdelta;
            }
            else
            {
                plot.CameraState.PreviewCameraZoom -= actualZdelta;
            }

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));
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
                ShaderSet = SPIRVShaders.CreateNodeShaders(_gdev, out _NodeVertexBuffer)
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
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gdev, out _EdgeVertBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);
        }

        private GraphPlotWidget.GraphShaderParams updateShaderParams(uint textureSize, PlottedGraph plot, CommandList cl)
        {
            GraphPlotWidget.GraphShaderParams shaderParams = new GraphPlotWidget.GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = -1,
                nodeSize = 300f,
                isAnimated = false
            };

            shaderParams.nonRotatedView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            shaderParams.proj = PreviewGraphsWidget.PreviewProjection;
            shaderParams.world = plot.CameraState.RotationMatrix;
            shaderParams.view = plot.CameraState.PreviewCameraTranslation;

            cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);

            return shaderParams;
        }

    }
}
