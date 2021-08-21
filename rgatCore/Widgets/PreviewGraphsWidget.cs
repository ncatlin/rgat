using ImGuiNET;
using rgat.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Timers;
using Veldrid;
using static rgat.VeldridGraphBuffers;

namespace rgat
{
    public class PreviewGraphsWidget : IDisposable
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

        public float EachGraphWidth = RGAT_CONSTANTS.UI.PREVIEW_PANE_WIDTH - (2 * RGAT_CONSTANTS.UI.PREVIEW_PANE_X_PADDING + 2); //-2 for border
        public float EachGraphHeight = RGAT_CONSTANTS.UI.PREVIEW_PANE_GRAPH_HEIGHT;
        bool Exiting = false;
        public uint selectedGraphTID;
        public PlottedGraph clickedGraph { get; private set; }

        ImGuiController _ImGuiController;
        GraphicsDevice _gd;
        ResourceFactory _factory;
        rgatState _rgatState;


        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout;
        ResourceSet _crs_core, _crs_nodesEdges;
        DeviceBuffer _paramsBuffer;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodeIndexBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;
        Pipeline _edgesPipeline, _pointsPipeline;

        GraphLayoutEngine _layoutEngine;
        public GraphLayoutEngine LayoutEngine => _layoutEngine;

        public PreviewGraphsWidget(ImGuiController controller, GraphicsDevice gdev, rgatState clientState)
        {
            IrregularTimer = new System.Timers.Timer(600);
            IrregularTimer.Elapsed += FireTimer;
            IrregularTimer.AutoReset = true;
            IrregularTimer.Start();
            _rgatState = clientState;
            _ImGuiController = controller;
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _layoutEngine = new GraphLayoutEngine(gdev, controller, "Preview");
            SetupRenderingResources();
        }

        public void Dispose()
        {
            Exiting = true;
            IrregularTimer.Stop();
        }


        private void FireTimer(object sender, ElapsedEventArgs e) { IrregularTimerFired = true; }

        public void SetActiveTrace(TraceRecord trace) => ActiveTrace = trace;

        public void SetSelectedGraph(PlottedGraph graph)
        {
            selectedGraphTID = graph.tid;
        }

        private void HandleClickedGraph(PlottedGraph graph) => clickedGraph = graph;
        public void ResetClickedGraph() => clickedGraph = null;


        //we do it via Draw so events are handled by the same thread
        public void HandleFrameTimerFired()
        {
            //Console.WriteLine("Handling timer fired");
            IrregularTimerFired = false;
            foreach (PlottedGraph graph in _centeringRequired.Keys.ToList())
            {
                _centeringRequired[graph] = true;
            }
        }


        public void SetupRenderingResources()
        {
            _paramsBuffer = TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<GraphPlotWidget.GraphShaderParams>(), BufferUsage.UniformBuffer | BufferUsage.Dynamic, name: "PreviewPlotparamsBuffer");

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));


            _NodeCircleSprite = _ImGuiController.GetImage("VertCircle");
            _NodeCircleSpritetview = _ImGuiController.IconTexturesView;


            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));


            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
            pipelineDescription.BlendState = BlendStateDescription.SingleAlphaBlend;
            pipelineDescription.DepthStencilState = new DepthStencilStateDescription(
                depthTestEnabled: true,
                depthWriteEnabled: true,
                comparisonKind: ComparisonKind.LessEqual);

            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: true,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout };
            pipelineDescription.ShaderSet = SPIRVShaders.CreateNodeShaders(_gd, out _NodeVertexBuffer, out _NodeIndexBuffer);

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
            pipelineDescription.ShaderSet = SPIRVShaders.CreateEdgeRelativeShaders(_gd, out _EdgeVertBuffer, out _EdgeIndexBuffer);
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);
        }


        /// <summary>
        /// Adjust the camera offset and zoom so that every node of the graph is in the frame
        /// </summary>
        bool CenterGraphInFrameStep(out float MaxRemaining, PlottedGraph graph)
        {
            Vector2 size = new Vector2(EachGraphWidth, EachGraphHeight);
            if (!_layoutEngine.GetPreviewFitOffsets(size, graph, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets))
            {
                MaxRemaining = 0;
                return false;
            }

            float delta;
            float xdelta = 0, ydelta = 0, zdelta = 0;
            float targXpadding = 80, targYpadding = 35;

            float graphDepth = zoffsets.Y - zoffsets.X;

            //graph being behind camera causes problems, deal with zoom first
            if (zoffsets.X < graphDepth)
            {
                delta = Math.Abs(Math.Min(zoffsets.X, zoffsets.Y)) / 2;
                float maxdelta = Math.Max(delta, 35);
                graph.PreviewCameraZoom -= maxdelta;
                MaxRemaining = maxdelta;
                return false;
            }

            //too zoomed in, zoom out
            if ((xoffsets.X < targXpadding && xoffsets.Y < targXpadding) || (yoffsets.X < targYpadding && yoffsets.Y < targYpadding))
            {
                if (xoffsets.X < targXpadding)
                    delta = Math.Min(targXpadding / 2, (targXpadding - xoffsets.X) / 3f);
                else
                    delta = Math.Min(targYpadding / 2, (targYpadding - yoffsets.Y) / 1.3f);

                if (delta > 50)
                {
                    graph.PreviewCameraZoom -= delta;
                    MaxRemaining = Math.Abs(delta);
                    return false;
                }
                else
                    zdelta = -1 * delta;
            }

            //too zoomed out, zoom in
            if ((xoffsets.X > targXpadding && xoffsets.Y > targXpadding) && (yoffsets.X > targYpadding && yoffsets.Y > targYpadding))
            {
                if (zoffsets.X > graphDepth)
                    zdelta += Math.Max((zoffsets.X - graphDepth) / 8, 50);
            }

            //too far left, move right
            if (xoffsets.X < targXpadding)
            {
                float diff = targXpadding - xoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta += delta;
            }

            //too far right, move left
            if (xoffsets.Y < targXpadding)
            {
                float diff = targXpadding - xoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                xdelta -= delta;
            }

            //off center, center it
            float XDiff = xoffsets.X - xoffsets.Y;
            if (Math.Abs(XDiff) > 40)
            {
                delta = Math.Max(Math.Abs(XDiff / 2), 15);
                if (XDiff > 0)
                    xdelta -= delta;
                else
                    xdelta += delta;
            }


            if (yoffsets.X < targYpadding)
            {
                float diff = targYpadding - yoffsets.X;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta += delta;
            }

            if (yoffsets.Y < targYpadding)
            {
                float diff = targYpadding - yoffsets.Y;
                delta = Math.Max(-1 * (diff / 5), 15);
                delta = Math.Min(delta, diff);
                ydelta -= delta;
            }

            float YDiff = yoffsets.X - yoffsets.Y;
            if (Math.Abs(YDiff) > 40)
            {
                delta = Math.Max(Math.Abs(YDiff / 2), 15);
                if (YDiff > 0) ydelta -= delta;
                else ydelta += delta;
            }


            float actualXdelta = Math.Min(Math.Abs(xdelta), 150);
            if (xdelta > 0)
                graph.PreviewCameraXOffset += actualXdelta;
            else
                graph.PreviewCameraXOffset -= actualXdelta;

            float actualYdelta = Math.Min(Math.Abs(ydelta), 150);
            if (ydelta > 0)
                graph.PreviewCameraYOffset += actualYdelta;
            else
                graph.PreviewCameraYOffset -= actualYdelta;

            float actualZdelta = Math.Min(Math.Abs(zdelta), 300);
            if (zdelta > 0)
                graph.PreviewCameraZoom += actualZdelta;
            else
                graph.PreviewCameraZoom -= actualZdelta;

            //weight the offsets higher
            MaxRemaining = Math.Max(Math.Max(Math.Abs(xdelta) * 4, Math.Abs(ydelta) * 4), Math.Abs(zdelta));


            return Math.Abs(xdelta) < 10 && Math.Abs(ydelta) < 10 && Math.Abs(zdelta) < 10;
        }



        enum PreviewSortMethod { StartOrder, InstructionCount, ThreadID, LastUpdated }
        PreviewSortMethod _activeSortMethod = PreviewSortMethod.StartOrder;
        Dictionary<TraceRecord, List<int>> _cachedSorts = new Dictionary<TraceRecord, List<int>>();
        DateTime lastSort = DateTime.MinValue;

        public void DrawWidget()
        {

            bool showToolTip = false;
            PlottedGraph latestHoverGraph = null;
            TraceRecord activeTrace = ActiveTrace;
            if (activeTrace == null) return;

            if (IrregularTimerFired) HandleFrameTimerFired();

            float captionHeight = ImGui.CalcTextSize("123456789").Y;

            DrawnPreviewGraphs = activeTrace.GetPlottedGraphs();
            List<int> indexes = GetGraphOrder(trace: ActiveTrace, graphs: DrawnPreviewGraphs);
            uint captionBackgroundcolor = Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewTextBackground);

            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, RGAT_CONSTANTS.UI.PREVIEW_PANE_Y_SEP));

            //Graph drawing loop
            if (ImGui.BeginTable("PrevGraphsTable", 1, ImGuiTableFlags.Borders, new Vector2(RGAT_CONSTANTS.UI.PREVIEW_PANE_WIDTH, ImGui.GetContentRegionAvail().Y)))
            {
                foreach (int graphIdx in indexes)
                {
                    PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                    float xPadding = RGAT_CONSTANTS.UI.PREVIEW_PANE_X_PADDING;
                    if (graph == null || graph.GraphNodeCount() == 0) continue;
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(0);

                    if (DrawPreviewGraph(graph, xPadding, captionHeight, captionBackgroundcolor))
                    {
                        var MainGraphs = graph.InternalProtoGraph.TraceData.GetPlottedGraphs();
                        HandleClickedGraph(MainGraphs[graphIdx]);
                    }

                    if (ImGui.IsItemHovered(ImGuiHoveredFlags.None) && !(ImGui.IsMouseDown(ImGuiMouseButton.Left)))
                    {
                        latestHoverGraph = graph;
                        showToolTip = true;
                    }
                }
                ImGui.EndTable();
            }
            ImGui.PopStyleVar();


            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(5, 5));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(5, 5));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(5, 5));
            ImGui.PushStyleColor(ImGuiCol.Border, 0x77999999);

            HoveredGraph = latestHoverGraph;
            bool showedCtx = HandlePreviewGraphContextMenu();

            bool veryRecentPopup = showedCtx || _lastCtxMenu.AddMilliseconds(250) > DateTime.Now;
            if (showToolTip && !veryRecentPopup)
            {
                DrawGraphTooltip(latestHoverGraph);
            }
            ImGui.PopStyleVar(3);
            ImGui.PopStyleColor();

        }

        List<int> GetGraphOrder(TraceRecord trace, List<PlottedGraph> graphs)
        {
            int SORT_UPDATE_RATE_MS = 750;
            List<int> indexes;

            if (lastSort.AddMilliseconds(SORT_UPDATE_RATE_MS) < DateTime.Now ||
                !_cachedSorts.TryGetValue(trace, out indexes) ||
                (indexes.Count < graphs.Count))
            {
                indexes = SortGraphs(graphs, _activeSortMethod);
                _cachedSorts[trace] = indexes;
            }
            return indexes;
        }

        List<int> SortGraphs(List<PlottedGraph> graphs, PreviewSortMethod order)
        {
            List<int> result = new List<int>();

            switch (order)
            {
                case PreviewSortMethod.InstructionCount:
                    result = graphs.ToList().OrderByDescending(x => x.InternalProtoGraph.TotalInstructions).Select(x => graphs.IndexOf(x)).ToList();
                    break;
                case PreviewSortMethod.LastUpdated:
                    result = graphs.ToList().OrderByDescending(x => x.InternalProtoGraph.LastUpdated).Select(x => graphs.IndexOf(x)).ToList();
                    break;
                case PreviewSortMethod.ThreadID:
                    result = graphs.ToList().OrderBy(x => x.tid).Select(x => graphs.IndexOf(x)).ToList();
                    break;
                case PreviewSortMethod.StartOrder:
                    result = Enumerable.Range(0, DrawnPreviewGraphs.Count).ToList();
                    break;
                default:
                    Logging.RecordLogEvent($"Bad preview sort order: {order.ToString()}");
                    break;
            }

            return result;
        }


        void DrawGraphTooltip(PlottedGraph graph)
        {
            ImGui.SetNextWindowPos(ImGui.GetMousePos() + new Vector2(0, 20));

            ImGui.BeginTooltip();
            string runningState;
            //todo a 'blocked' option when i get around to detecting/displaying the blocked state
            if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eSuspended)
            {
                runningState = "Suspended";
            }
            else
            {
                if (graph.InternalProtoGraph.Terminated)
                {
                    runningState = "Terminated";
                }
                else
                {
                    runningState = "Running";
                }
            }

            if (_threadStartCache.ContainsKey(graph))
            {
                ImGui.Text(_threadStartCache[graph]);
            }
            else
            {
                if (graph.InternalProtoGraph.SavedAnimationData.Count > 0)
                {
                    ulong blockaddr = graph.InternalProtoGraph.SavedAnimationData[0].blockAddr;
                    int module = graph.InternalProtoGraph.ProcessData.FindContainingModule(blockaddr);
                    string path = graph.InternalProtoGraph.ProcessData.GetModulePath(module);
                    string pathSnip = Path.GetFileName(path);
                    if (pathSnip.Length > 50)
                        pathSnip = pathSnip.Substring(pathSnip.Length - 50, pathSnip.Length);
                    string val = $"Start Address: {pathSnip}:0x{blockaddr:X}";
                    _threadStartCache[graph] = val;
                    ImGui.Text(val);
                }
            }

            ImGui.Text($"Graph TID: {graph.tid} [{runningState}]");
            ImGui.Text($"Graph PID: {graph.pid}");
            ImGui.Text($"Unique Instructions: {graph.InternalProtoGraph.NodeList.Count}");
            ImGui.Text($"Total Instructions: {graph.InternalProtoGraph.TotalInstructions}");
            ImGui.Text($"Animation Entries: {graph.InternalProtoGraph.SavedAnimationData.Count}");


            ImGui.Separator();
            ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
            string ctxtiptext = "Right click for options";
            ImGui.SetCursorPosX((ImGui.GetContentRegionAvail().X / 2) - ImGui.CalcTextSize(ctxtiptext).X / 2);
            ImGui.Text(ctxtiptext);
            ImGui.PopStyleColor();
            ImGui.EndTooltip();

        }

        Dictionary<PlottedGraph, string> _threadStartCache = new Dictionary<PlottedGraph, string>();



        /*
         * No working PIN api for this, have to do from rgat
         */
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ulong dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);


        DateTime _lastCtxMenu = DateTime.MinValue;
        bool HandlePreviewGraphContextMenu()
        {
            if (ImGui.BeginPopupContextItem("GraphWidgetCtxMenu", ImGuiPopupFlags.MouseButtonRight))
            {
                _lastCtxMenu = DateTime.Now;
                ImGui.Text($"Sort ({_activeSortMethod})");
                ImGui.Separator();
                if (ImGui.MenuItem("Start Order", "S", _activeSortMethod == PreviewSortMethod.StartOrder, true))
                {
                    _cachedSorts.Remove(ActiveTrace);
                    _activeSortMethod = PreviewSortMethod.StartOrder;
                }
                if (ImGui.MenuItem("Instruction Count", "I", _activeSortMethod == PreviewSortMethod.InstructionCount, true))
                {
                    _cachedSorts.Remove(ActiveTrace);
                    _activeSortMethod = PreviewSortMethod.InstructionCount;
                }
                if (ImGui.MenuItem("Recent Activity", "A", _activeSortMethod == PreviewSortMethod.LastUpdated, true))
                {
                    _cachedSorts.Remove(ActiveTrace);
                    _activeSortMethod = PreviewSortMethod.LastUpdated;
                }
                if (ImGui.MenuItem("Thread ID", "T", _activeSortMethod == PreviewSortMethod.ThreadID, true))
                {
                    _cachedSorts.Remove(ActiveTrace);
                    _activeSortMethod = PreviewSortMethod.ThreadID;
                }


                PlottedGraph hoverGraph = HoveredGraph;
                if (hoverGraph != null || PreviewPopupGraph != null)
                {
                    if (hoverGraph != null)
                        PreviewPopupGraph = hoverGraph;

                    ImGui.Separator();
                    ImGui.Text($"Graph {PreviewPopupGraph.tid}");
                    if (!PreviewPopupGraph.InternalProtoGraph.Terminated && ImGui.MenuItem("Terminate"))
                    {
                        PreviewPopupGraph.InternalProtoGraph.TraceData.SendDebugCommand(PreviewPopupGraph.tid, "KILL");
                    }
                    if (!PreviewPopupGraph.InternalProtoGraph.Terminated && ImGui.MenuItem("Force Terminate"))
                    {
                        //todo - rgat doesn't detect this because pin threads still run, keeping pipes open
                        IntPtr handle = OpenThread(1, false, PreviewPopupGraph.tid);
                        if (handle != (IntPtr)0)
                        {
                            TerminateThread(handle, 0);
                            CloseHandle(handle);
                        }
                    }
                }

                ImGui.EndPopup();
                return true;
            }
            PreviewPopupGraph = null;
            return false;

        }


        PlottedGraph PreviewPopupGraph = null;
        public PlottedGraph HoveredGraph { get; private set; } = null;


        void DrawPreviewZoomEnvelope(PlottedGraph graph, Vector2 subGraphPosition)
        {
            ImDrawListPtr imdp = ImGui.GetWindowDrawList();
            float previewBaseY = subGraphPosition.Y + EachGraphHeight;

            graph.GetPreviewVisibleRegion(new Vector2(EachGraphWidth, EachGraphHeight), PreviewProjection, out Vector2 TopLeft, out Vector2 BaseRight);

            float C1X = subGraphPosition.X + TopLeft.X;
            float C2X = subGraphPosition.X + BaseRight.X;
            float C1Y = previewBaseY - TopLeft.Y;
            float C2Y = previewBaseY - BaseRight.Y;

            uint colour = Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewZoomEnvelope);

            C1Y = Math.Min(previewBaseY - 1, C1Y);
            C2Y = Math.Max(subGraphPosition.Y, C2Y);

            if (C1Y > subGraphPosition.Y && C1Y < previewBaseY)
                imdp.AddLine(new Vector2(C1X, C1Y), new Vector2(C2X, C1Y), colour);

            if (C2Y > subGraphPosition.Y && C2Y < previewBaseY)
                imdp.AddLine(new Vector2(C2X, C2Y), new Vector2(C1X, C2Y), colour);

            if (C2Y < previewBaseY && C1Y > subGraphPosition.Y)
            {
                imdp.AddLine(new Vector2(C2X, C1Y), new Vector2(C2X, C2Y), colour);
                imdp.AddLine(new Vector2(C1X, C2Y), new Vector2(C1X, C1Y), colour);
            }

        }


        public void GeneratePreviewGraph(CommandList cl, PlottedGraph graph)
        {
            Logging.RecordLogEvent($"GeneratePreviewGraph Preview updating pos caches {graph.tid} start", Logging.LogFilterType.BulkDebugLogFile);

            if (graph != _rgatState.ActiveGraph)
            {
                _layoutEngine.Compute(cl, graph, -1, false);
            }

            Logging.RecordLogEvent($"GeneratePreviewGraph starting render {graph.tid}", Logging.LogFilterType.BulkDebugLogFile);
            renderPreview(cl, graph: graph);


        }


        public bool DrawPreviewGraph(PlottedGraph graph, float xPadding, float captionHeight, uint captionBackgroundcolor)
        {
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            bool clicked = false;
            if (graph == null) return clicked;
            int graphNodeCount = graph.GraphNodeCount();
            if (graphNodeCount == 0) return clicked;
            graph.GetLatestTexture(out Texture previewTexture);
            if (previewTexture == null) return clicked;
            bool isSelected = graph.tid == selectedGraphTID;


            //copy in the actual rendered graph
            ImGui.SetCursorPosY(ImGui.GetCursorPosY());
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos() + new Vector2(xPadding, 0);

            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, previewTexture, $"PreviewPlot{graph.tid}");
            imdp.AddImage(user_texture_id: CPUframeBufferTextureId,
                p_min: subGraphPosition,
                p_max: new Vector2(subGraphPosition.X + EachGraphWidth, subGraphPosition.Y + EachGraphHeight),
                uv_min: new Vector2(0, 1),
                uv_max: new Vector2(1, 0));

            float borderThickness = Themes.GetThemeSize(Themes.eThemeSize.ePreviewSelectedBorder);
            float halfBorderThickness = (float)Math.Floor(borderThickness / 2f);

            if (isSelected)
            {
                DrawPreviewZoomEnvelope(graph, subGraphPosition);

                if (borderThickness > 0)
                {
                    imdp.AddRect(
                        p_min: new Vector2(subGraphPosition.X + halfBorderThickness, subGraphPosition.Y + halfBorderThickness),
                        p_max: new Vector2((subGraphPosition.X + EachGraphWidth - halfBorderThickness), subGraphPosition.Y + EachGraphHeight - halfBorderThickness),
                        col: GetGraphBorderColour(graph), 0, ImDrawFlags.None, borderThickness);
                }
            }

            //write the caption
            string Caption = $"TID:{graph.tid} {graphNodeCount}nodes {(isSelected ? "[Selected]" : "")}";
            ImGui.SetCursorPosX(ImGui.GetCursorPosX());
            Vector2 captionBGStart = subGraphPosition + new Vector2(borderThickness, borderThickness);
            Vector2 captionBGEnd = new Vector2((captionBGStart.X + EachGraphWidth - borderThickness * 2), captionBGStart.Y + captionHeight);
            imdp.AddRectFilled(p_min: captionBGStart, p_max: captionBGEnd, col: captionBackgroundcolor);
            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewText));
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + RGAT_CONSTANTS.UI.PREVIEW_PANE_X_PADDING + borderThickness + 1);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + borderThickness);
            ImGui.Text(Caption);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + EachGraphWidth - 48);

            //live thread activity plot
            if (!ActiveTrace.WasLoadedFromSave)
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - captionHeight);

                float maxVal;
                float[] values = null;
                if (graph.InternalProtoGraph.TraceReader != null)
                {
                    values = graph.InternalProtoGraph.TraceReader.RecentMessageRates();
                }
                if (values == null || values.Length == 0)
                {
                    values = new List<float>() { 0, 0, 0, 0, 0 }.ToArray();
                    maxVal = 100;
                }
                else
                {
                    maxVal = values.Max(); // should instead do the max of all the values from all the threads?
                }
                ImGui.PushStyleColor(ImGuiCol.FrameBg, captionBackgroundcolor);
                ImGui.PlotLines("", ref values[0], values.Length, 0, "", 0, maxVal, new Vector2(40, captionHeight));
                ImGui.PopStyleColor();
            }


            //invisible button to detect graph click

            ImGui.SetCursorPos(new Vector2(1, ImGui.GetCursorPosY() - (float)(captionHeight)));
            if (ImGui.InvisibleButton("PrevGraphBtn" + graph.tid, new Vector2(EachGraphWidth, EachGraphHeight - 2)) || ImGui.IsItemActive())
            {
                clicked = true;
                if (isSelected)
                {
                    Vector2 clickPos = ImGui.GetMousePos();
                    Vector2 clickOffset = clickPos - subGraphPosition;
                    clickOffset.Y = EachGraphHeight - clickOffset.Y;
                    graph.MoveCameraToPreviewClick(clickOffset, new Vector2(EachGraphWidth, EachGraphHeight), new Vector2(884, 454), PreviewProjection);//todo widget size
                }

            }
            return clicked;

        }



        Matrix4x4 PreviewProjection => Matrix4x4.CreatePerspectiveFieldOfView(1.0f, EachGraphWidth / EachGraphHeight, 1, 50000);


        GraphPlotWidget.GraphShaderParams updateShaderParams(uint textureSize, PlottedGraph graph, CommandList cl)
        {
            GraphPlotWidget.GraphShaderParams shaderParams = new GraphPlotWidget.GraphShaderParams
            {
                TexWidth = textureSize,
                pickingNode = -1,
                isAnimated = false
            };

            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(new Vector3(graph.PreviewCameraXOffset, graph.PreviewCameraYOffset, graph.PreviewCameraZoom));


            shaderParams.nonRotatedView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            shaderParams.proj = PreviewProjection;
            shaderParams.world = graph.RotationMatrix;
            shaderParams.view = cameraTranslation;


            cl.UpdateBuffer(_paramsBuffer, 0, shaderParams);

            return shaderParams;
        }

        Dictionary<PlottedGraph, bool> _centeringRequired = new Dictionary<PlottedGraph, bool>();

        WritableRgbaFloat GetGraphBackgroundColour(PlottedGraph graph)
        {
            if (graph.InternalProtoGraph.Terminated)
                return GlobalConfig.mainColours.terminatedPreview;

            switch (graph.InternalProtoGraph.TraceData.TraceState)
            {
                case TraceRecord.eTraceState.eTerminated:
                    return GlobalConfig.mainColours.terminatedPreview;
                case TraceRecord.eTraceState.eRunning:
                    return GlobalConfig.mainColours.runningPreview;
                case TraceRecord.eTraceState.eSuspended:
                    return GlobalConfig.mainColours.suspendedPreview;
                default:
                    return new WritableRgbaFloat(0, 0, 0, 0);
            }
        }

        uint GetGraphBorderColour(PlottedGraph graph)
        {
            if (graph.InternalProtoGraph.Terminated)
                return 0xff0000ff;

            switch (graph.InternalProtoGraph.TraceData.TraceState)
            {
                case TraceRecord.eTraceState.eTerminated:
                    return 0x4f00004f;
                case TraceRecord.eTraceState.eRunning:
                    return 0xff00ff00;
                case TraceRecord.eTraceState.eSuspended:
                    return 0xff47A3f0;
                default:
                    return 0;
            }
        }


        void renderPreview(CommandList cl, PlottedGraph graph)
        {
            if (graph == null || Exiting) return;
            if (graph._previewFramebuffer1 == null)
            {
                graph.InitPreviewTexture(new Vector2(EachGraphWidth, RGAT_CONSTANTS.UI.PREVIEW_PANE_GRAPH_HEIGHT), _gd);
            }


            Logging.RecordLogEvent("render preview 1", filter: Logging.LogFilterType.BulkDebugLogFile);
            bool needsCentering = true;
            if (!_centeringRequired.TryGetValue(graph, out needsCentering))
            {
                _centeringRequired.Add(graph, true);
            }


            if (needsCentering)
            {
                bool done = CenterGraphInFrameStep(out float maxremaining, graph);
                if (done)
                {
                    _centeringRequired[graph] = false;
                }
            }

            Position2DColour[] EdgeLineVerts = graph.GetEdgeLineVerts(RGAT_CONSTANTS.eRenderingMode.eStandardControlFlow, 
                out List<uint> edgeDrawIndexes, 
                out int edgeVertCount, 
                out int drawnEdgeCount);
            if (drawnEdgeCount == 0 || !graph.LayoutState.Initialised) return;

            //Logging.RecordLogEvent("render preview 2", filter: Logging.LogFilterType.BulkDebugLogFile);
            cl.Begin();

            var textureSize = graph.LinearIndexTextureSize();
            updateShaderParams(textureSize, graph, cl);

            Position2DColour[] NodeVerts = graph.GetPreviewgraphNodeVerts(out List<uint> nodeIndices, RGAT_CONSTANTS.eRenderingMode.eStandardControlFlow);

            Debug.Assert(!_NodeVertexBuffer.IsDisposed);

            if (_NodeVertexBuffer.SizeInBytes < NodeVerts.Length * Position2DColour.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {

                Logging.RecordLogEvent("disposeremake nodeverts", filter: Logging.LogFilterType.BulkDebugLogFile);

                VeldridGraphBuffers.DoDispose(_NodeVertexBuffer);
                _NodeVertexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)NodeVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewNodeVertexBuffer");

                VeldridGraphBuffers.DoDispose(_NodeIndexBuffer);
                _NodeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "PreviewNodeIndexBuffer");
            }

            cl.UpdateBuffer(_NodeVertexBuffer, 0, NodeVerts);
            cl.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());

            if (((edgeVertCount * sizeof(uint)) > _EdgeIndexBuffer.SizeInBytes))
            {
                Logging.RecordLogEvent("disposeremake edgeverts", filter: Logging.LogFilterType.BulkDebugLogFile);

                VeldridGraphBuffers.DoDispose(_EdgeVertBuffer);
                _EdgeVertBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)EdgeLineVerts.Length * Position2DColour.SizeInBytes, BufferUsage.VertexBuffer, name: "PreviewEdgeVertexBuffer");

                VeldridGraphBuffers.DoDispose(_EdgeIndexBuffer);
                _EdgeIndexBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeDrawIndexes.Count * sizeof(uint), BufferUsage.IndexBuffer, name: "PreviewEdgeIndexBuffer");
            }

            Logging.RecordLogEvent("render preview 3", filter: Logging.LogFilterType.BulkDebugLogFile);
            cl.UpdateBuffer(_EdgeVertBuffer, 0, EdgeLineVerts);
            cl.UpdateBuffer(_EdgeIndexBuffer, 0, edgeDrawIndexes.ToArray());

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, graph.LayoutState.PositionsVRAM1);
            ResourceSet crscore = _factory.CreateResourceSet(crs_core_rsd);


            Logging.RecordLogEvent($"render preview {graph.tid} creating rsrcset ", filter: Logging.LogFilterType.BulkDebugLogFile);
            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout,
                graph.LayoutState.AttributesVRAM1, _NodeCircleSpritetview);
            ResourceSet crsnodesedge = _factory.CreateResourceSet(crs_nodesEdges_rsd);



            Debug.Assert(nodeIndices.Count <= (_NodeIndexBuffer.SizeInBytes / sizeof(uint)));
            int nodesToDraw = Math.Min(nodeIndices.Count, (int)(_NodeIndexBuffer.SizeInBytes / sizeof(uint)));

            graph.GetPreviewFramebuffer(out Framebuffer drawtarget);

            cl.SetFramebuffer(drawtarget);

            cl.ClearColorTarget(0, GetGraphBackgroundColour(graph).ToRgbaFloat());
            cl.SetViewport(0, new Viewport(0, 0, EachGraphWidth, EachGraphHeight, -2200, 1000));

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
            if (!Exiting)
            {
                Logging.RecordLogEvent($"render preview start commands {graph.tid}. Pos{graph.LayoutState.PositionsVRAM1.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gd.SubmitCommands(cl);
                Logging.RecordLogEvent($"render preview finished commands {graph.tid}", filter: Logging.LogFilterType.BulkDebugLogFile);
                _gd.WaitForIdle(); //needed?
            }


            graph.ReleasePreviewFramebuffer();

            //Debug.Assert(!_NodeVertexBuffer.IsDisposed);
            crscore.Dispose();
            //Logging.RecordLogEvent($"render preview {graph.tid} disposing rsrcset {nodeAttributesBuffer.Name}", filter: Logging.LogFilterType.BulkDebugLogFile);
            crsnodesedge.Dispose();

            Logging.RecordLogEvent("render preview Done", filter: Logging.LogFilterType.BulkDebugLogFile);
        }


    }
}
