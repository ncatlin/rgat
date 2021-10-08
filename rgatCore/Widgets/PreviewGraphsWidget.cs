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
    /// <summary>
    /// A widget for rendering small versions of each recorded graph
    /// </summary>
    public class PreviewGraphsWidget : IDisposable
    {
        private List<PlottedGraph> DrawnPreviewGraphs = new List<PlottedGraph>();
        private readonly System.Timers.Timer IrregularTimer;
        private TraceRecord? ActiveTrace = null;

        /// <summary>
        /// Width of each preview graph
        /// </summary>
        public static readonly float EachGraphWidth = CONSTANTS.UI.PREVIEW_PANE_WIDTH - (2 * CONSTANTS.UI.PREVIEW_PANE_X_PADDING + 2); //-2 for border

        /// <summary>
        /// Height of each preview graph
        /// </summary>
        public static readonly float EachGraphHeight = CONSTANTS.UI.PREVIEW_PANE_GRAPH_HEIGHT;

        private uint selectedGraphTID;
        /// <summary>
        /// The graph the user clicked
        /// </summary>
        public PlottedGraph? clickedGraph { get; private set; }

        private readonly ImGuiController? _ImGuiController;
        private GraphicsDevice? _gd;
        /// <summary>
        /// Preview layout engine that prioritises graphs of trace being viewed in visualiser
        /// </summary>
        public GraphLayoutEngine ForegroundLayoutEngine;
        /// <summary>
        /// Preview layout engine that prioritises graphs of trace not being viewed in visualiser
        /// </summary>
        public GraphLayoutEngine BackgroundLayoutEngine;

        /// <summary>
        /// Create a preview graph widget
        /// </summary>
        /// <param name="controller">ImGui controller</param>
        /// <param name="clientState">rgat state object</param>
        public PreviewGraphsWidget(ImGuiController controller, rgatState clientState)
        {
            IrregularTimer = new System.Timers.Timer(600);
            IrregularTimer.Elapsed += FireTimer;
            IrregularTimer.AutoReset = true;
            IrregularTimer.Start();
            _ImGuiController = controller;

            ForegroundLayoutEngine = new GraphLayoutEngine($"Preview_Foreground");
            ForegroundLayoutEngine.Init(controller.GraphicsDevice);
            BackgroundLayoutEngine = new GraphLayoutEngine($"Preview_Background");
            BackgroundLayoutEngine.Init(controller.GraphicsDevice);
        }


        /// <summary>
        /// Init the grapihcs device/controller
        /// </summary>
        /// <param name="gdev">Graphics device for GPU access</param>
        public void Init(GraphicsDevice gdev)
        {
            _gd = gdev;
        }


        /// <summary>
        /// Destructor
        /// </summary>
        public void Dispose()
        {
            IrregularTimer.Stop();
        }


        private void FireTimer(object sender, ElapsedEventArgs e) { HandleFrameTimerFired(); }

        /// <summary>
        /// Set the trace of the active graph
        /// </summary>
        /// <param name="trace"></param>
        public void SetActiveTrace(TraceRecord? trace) => ActiveTrace = trace;

        /// <summary>
        /// Set the active graph
        /// </summary>
        /// <param name="graph"></param>
        public void SetSelectedGraph(PlottedGraph? graph)
        {
            selectedGraphTID = graph is not null ? graph.TID : uint.MaxValue;
        }

        private void HandleClickedGraph(PlottedGraph graph) => clickedGraph = graph;

        /// <summary>
        /// We have dealt with the graph click, clear it
        /// </summary>
        public void ResetClickedGraph() => clickedGraph = null;

        /// <summary>
        /// do it via Draw so events are handled by the same thread
        /// </summary>
        private void HandleFrameTimerFired()
        {
            //Logging.WriteConsole("Handling timer fired");
            lock (_lock)
            {
                foreach (PlottedGraph graph in _centeringRequired.Keys.ToList())
                {
                    _centeringRequired[graph] = true;
                }
            }
        }


        private enum PreviewSortMethod { StartOrder, InstructionCount, ThreadID, LastUpdated }

        private PreviewSortMethod _activeSortMethod = PreviewSortMethod.StartOrder;
        private readonly Dictionary<TraceRecord, List<int>> _cachedSorts = new Dictionary<TraceRecord, List<int>>();
        private readonly DateTime lastSort = DateTime.MinValue;

        /// <summary>
        /// Draw the preview graph widget
        /// </summary>
        public void DrawWidget()
        {

            bool showToolTip = false;
            PlottedGraph? latestHoverGraph = null;
            TraceRecord? activeTrace = ActiveTrace;
            if (activeTrace == null)
            {
                return;
            }


            float captionHeight = ImGui.CalcTextSize("123456789").Y;

            DrawnPreviewGraphs = activeTrace.GetPlottedGraphs();
            List<int> indexes = GetGraphOrder(trace: activeTrace, graphs: DrawnPreviewGraphs);
            uint captionBackgroundcolor = Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewTextBackground);

            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, CONSTANTS.UI.PREVIEW_PANE_Y_SEP));

            //Graph drawing loop
            if (ImGui.BeginTable("PrevGraphsTable", 1, ImGuiTableFlags.Borders, new Vector2(CONSTANTS.UI.PREVIEW_PANE_WIDTH, ImGui.GetContentRegionAvail().Y)))
            {
                foreach (int graphIdx in indexes)
                {
                    PlottedGraph graph = DrawnPreviewGraphs[graphIdx];
                    float xPadding = CONSTANTS.UI.PREVIEW_PANE_X_PADDING;
                    if (graph == null || graph.GraphNodeCount() == 0)
                    {
                        continue;
                    }

                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(0);

                    if (DrawPreviewGraph(graph, xPadding, captionHeight, captionBackgroundcolor, out bool canHover))
                    {
                        var MainGraphs = graph.InternalProtoGraph.TraceData.GetPlottedGraphs();
                        HandleClickedGraph(MainGraphs[graphIdx]);
                    }

                    if (canHover && ImGui.IsItemHovered(ImGuiHoveredFlags.None) && !(ImGui.IsMouseDown(ImGuiMouseButton.Left)))
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
            if (showToolTip && !veryRecentPopup && HoveredGraph is not null)
            {
                DrawGraphTooltip(HoveredGraph);
            }
            ImGui.PopStyleVar(3);
            ImGui.PopStyleColor();

        }

        private List<int> GetGraphOrder(TraceRecord trace, List<PlottedGraph> graphs)
        {
            int SORT_UPDATE_RATE_MS = 750;
            List<int>? indexes;

            if (lastSort.AddMilliseconds(SORT_UPDATE_RATE_MS) < DateTime.Now ||
                !_cachedSorts.TryGetValue(trace, out indexes) ||
                (indexes.Count < graphs.Count))
            {
                indexes = SortGraphs(graphs, _activeSortMethod);
                _cachedSorts[trace] = indexes;
            }
            return indexes;
        }

        private List<int> SortGraphs(List<PlottedGraph> graphs, PreviewSortMethod order)
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
                    result = graphs.ToList().OrderBy(x => x.TID).Select(x => graphs.IndexOf(x)).ToList();
                    break;
                case PreviewSortMethod.StartOrder:
                    result = Enumerable.Range(0, DrawnPreviewGraphs.Count).ToList();
                    break;
                default:
                    Logging.RecordLogEvent($"Bad preview sort order: {order}");
                    break;
            }

            return result;
        }

        private void DrawGraphTooltip(PlottedGraph graph)
        {
            ImGui.SetNextWindowPos(ImGui.GetMousePos() + new Vector2(0, 20));

            ImGui.BeginTooltip();
            string runningState;
            //todo a 'blocked' option when i get around to detecting/displaying the blocked state
            if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.ProcessState.eSuspended)
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
                if (graph.InternalProtoGraph.NodeCount > 0)
                {
                    ulong blockaddr = graph.InternalProtoGraph.NodeList[0].address;
                    bool found = graph.InternalProtoGraph.ProcessData.FindContainingModule(blockaddr, out int? module);
                    if (found)
                    {
                        string path = graph.InternalProtoGraph.ProcessData.GetModulePath(module!.Value);
                        string pathSnip = Path.GetFileName(path);
                        if (pathSnip.Length > 50)
                        {
                            pathSnip = pathSnip.Substring(pathSnip.Length - 50, pathSnip.Length);
                        }

                        string val = $"Start Address: {pathSnip}:0x{blockaddr:X}";
                        _threadStartCache[graph] = val;
                        ImGui.Text(val);
                    }
                    else
                    {
                        ImGui.Text("[No Module?]");
                    }

                }
            }

            ImGui.Text($"Graph TID: {graph.TID} [{runningState}]");
            ImGui.Text($"Graph PID: {graph.PID}");
            ImGui.Text($"Unique Instructions: {graph.InternalProtoGraph.NodeList.Count}");
            ImGui.Text($"Total Instructions: {graph.InternalProtoGraph.TotalInstructions}");
            ImGui.Text($"Animation Entries: {graph.InternalProtoGraph.UpdateCount}");
            ImGui.Text($"Exceptions: {graph.InternalProtoGraph.ExceptionCount}");


            ImGui.Separator();
            ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
            string ctxtiptext = "Right click for options";
            ImGui.SetCursorPosX((ImGui.GetContentRegionAvail().X / 2) - ImGui.CalcTextSize(ctxtiptext).X / 2);
            ImGui.Text(ctxtiptext);
            ImGui.PopStyleColor();
            ImGui.EndTooltip();

        }

        private readonly Dictionary<PlottedGraph, string> _threadStartCache = new Dictionary<PlottedGraph, string>();



        /*
         * No working PIN api for this, have to do from rgat
         */
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ulong dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        private DateTime _lastCtxMenu = DateTime.MinValue;

        private bool HandlePreviewGraphContextMenu()
        {
            if (ActiveTrace is null)
            {
                return false;
            }

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


                PlottedGraph? hoverGraph = HoveredGraph;
                if (hoverGraph != null || PreviewPopupGraph != null)
                {
                    if (hoverGraph != null)
                    {
                        PreviewPopupGraph = hoverGraph;
                    }

                    ImGui.Separator();
                    ImGui.Text($"Graph {PreviewPopupGraph!.TID}");
                    if (!PreviewPopupGraph.InternalProtoGraph.Terminated && ImGui.MenuItem("Terminate"))
                    {
                        PreviewPopupGraph.InternalProtoGraph.TraceData.SendDebugCommand(PreviewPopupGraph.TID, "KILL");
                    }
                    if (!PreviewPopupGraph.InternalProtoGraph.Terminated && ImGui.MenuItem("Force Terminate"))
                    {
                        //todo - rgat doesn't detect this because pin threads still run, keeping pipes open
                        IntPtr handle = OpenThread(1, false, PreviewPopupGraph.TID);
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

        /// <summary>
        /// The last recorded preview the mouse was hovering over
        /// </summary>
        private PlottedGraph? PreviewPopupGraph = null;

        /// <summary>
        /// The preview graph the mouse is hovering over
        /// </summary>
        public PlottedGraph? HoveredGraph { get; private set; } = null;

        private static void DrawPreviewZoomEnvelope(PlottedGraph graph, Vector2 subGraphPosition)
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
            {
                imdp.AddLine(new Vector2(C1X, C1Y), new Vector2(C2X, C1Y), colour);
            }

            if (C2Y > subGraphPosition.Y && C2Y < previewBaseY)
            {
                imdp.AddLine(new Vector2(C2X, C2Y), new Vector2(C1X, C2Y), colour);
            }

            if (C2Y < previewBaseY && C1Y > subGraphPosition.Y)
            {
                imdp.AddLine(new Vector2(C2X, C1Y), new Vector2(C2X, C2Y), colour);
                imdp.AddLine(new Vector2(C1X, C2Y), new Vector2(C1X, C1Y), colour);
            }

        }


        /// <summary>
        /// Draw a preview graph texture on the preview pane
        /// </summary>
        /// <param name="graph">The graph being drawn</param>
        /// <param name="xPadding">horizontal padding</param>
        /// <param name="captionHeight">height of the caption</param>
        /// <param name="captionBackgroundcolor">contrast background colour of the caption</param>
        /// <param name="canHover">output flag states if we can safely draw a mouseover tooltip</param>
        /// <returns>The graph was clicked</returns>
        private bool DrawPreviewGraph(PlottedGraph graph, float xPadding, float captionHeight, uint captionBackgroundcolor, out bool canHover)
        {
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            bool clicked = false;
            canHover = false;
            if (graph == null)
            {
                return clicked;
            }

            int graphNodeCount = graph.GraphNodeCount();
            if (graphNodeCount == 0)
            {
                return clicked;
            }

            graph.GetLatestTexture(out Texture previewTexture);
            if (previewTexture == null)
            {
                return clicked;
            }

            bool isSelected = graph.TID == selectedGraphTID;
            canHover = true;

            //copy in the actual rendered graph
            ImGui.SetCursorPosY(ImGui.GetCursorPosY());
            Vector2 subGraphPosition = ImGui.GetCursorScreenPos() + new Vector2(xPadding, 0);

            IntPtr CPUframeBufferTextureId = _ImGuiController!.GetOrCreateImGuiBinding(_gd!.ResourceFactory, previewTexture, $"PreviewPlot{graph.TID}");
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
            string Caption = $"TID:{graph.TID} {graphNodeCount} nodes {(isSelected ? "[Selected]" : "")}";
            ImGui.SetCursorPosX(ImGui.GetCursorPosX());
            Vector2 captionBGStart = subGraphPosition + new Vector2(borderThickness, borderThickness);
            Vector2 captionBGEnd = new Vector2((captionBGStart.X + EachGraphWidth - borderThickness * 2), captionBGStart.Y + captionHeight);
            imdp.AddRectFilled(p_min: captionBGStart, p_max: captionBGEnd, col: captionBackgroundcolor);
            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewText));
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + CONSTANTS.UI.PREVIEW_PANE_X_PADDING + borderThickness + 1);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + borderThickness);
            ImGui.Text(Caption);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + EachGraphWidth - 48);

            //live thread activity plot
            if (ActiveTrace is not null && !ActiveTrace.WasLoadedFromSave)
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - captionHeight);

                float maxVal;
                float[]? invalues = null;
                if (graph.InternalProtoGraph.TraceReader != null)
                {
                    graph.InternalProtoGraph.TraceReader.RecentMessageRates(out invalues);
                }
                if (invalues == null || invalues.Length == 0)
                {
                    invalues = new List<float>() { 0, 0, 0, 0, 0 }.ToArray();
                    maxVal = 100;
                }
                else
                {
                    maxVal = invalues.Max(); 
                }
                ImGui.PushStyleColor(ImGuiCol.FrameBg, captionBackgroundcolor);
                ImGui.PlotLines("", ref invalues[0], invalues.Length, 0, "", 0, maxVal, new Vector2(40, captionHeight));
                if (ImGui.IsItemHovered()) 
                    canHover = false; //The PlotLines widget doesn't allow disabling the mouseover, so have to prevent our mousover to avoid a merged tooltip
                ImGui.PopStyleColor();
            }


            //invisible button to detect graph click

            ImGui.SetCursorPos(new Vector2(1, ImGui.GetCursorPosY() - (float)(captionHeight)));
            if (ImGui.InvisibleButton("PrevGraphBtn" + graph.TID, new Vector2(EachGraphWidth, EachGraphHeight - 2)) || ImGui.IsItemActive())
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

        /// <summary>
        /// Get the projection matrix of a preview graph
        /// </summary>
        public static Matrix4x4 PreviewProjection => Matrix4x4.CreatePerspectiveFieldOfView(1.0f, EachGraphWidth / EachGraphHeight, 1, 50000);

        readonly object _lock = new();

        /// <summary>
        /// Check if a graph is queued for preview centering
        /// </summary>
        /// <param name="graph">The graph</param>
        /// <returns></returns>
        public bool IsCenteringRequired(PlottedGraph graph)
        {
            lock(_lock)
            {
                return _centeringRequired.TryGetValue(graph, out bool required) && required;
            }
        }

        /// <summary>
        /// Set a graph as requiring preview centering
        /// </summary>
        /// <param name="graph">The graph</param>
        public void StartCentering(PlottedGraph graph)
        {
            lock(_lock)
            {
                _centeringRequired[graph] = true;
            }
        }


        /// <summary>
        /// Stop preview graph centering on a graph
        /// </summary>
        /// <param name="graph">The graph</param>
        public void StopCentering(PlottedGraph graph)
        {
            lock(_lock)
            {
                _centeringRequired[graph] = false;
            }
        }


        private readonly Dictionary<PlottedGraph, bool> _centeringRequired = new Dictionary<PlottedGraph, bool>();

        /// <summary>
        /// Get the background colour of a preview graph
        /// </summary>
        /// <param name="graph">The graph</param>
        /// <returns>The colour</returns>
        public static WritableRgbaFloat GetGraphBackgroundColour(PlottedGraph graph)
        {
            if (graph.InternalProtoGraph.Terminated)
            {
                return Themes.GetThemeColourWRF(Themes.eThemeColour.PreviewBGTerminated);
            }

            switch (graph.InternalProtoGraph.TraceData.TraceState)
            {
                case TraceRecord.ProcessState.eTerminated:
                    return Themes.GetThemeColourWRF(Themes.eThemeColour.PreviewBGTerminated);
                case TraceRecord.ProcessState.eRunning:
                    return Themes.GetThemeColourWRF(Themes.eThemeColour.PreviewBGRunning);
                case TraceRecord.ProcessState.eSuspended:
                    return Themes.GetThemeColourWRF(Themes.eThemeColour.PreviewBGSuspended);
                default:
                    return new WritableRgbaFloat(0, 0, 0, 0);
            }
        }


        /// <summary>
        /// Get the border colour of a preview graph
        /// </summary>
        /// <param name="graph">The Graph</param>
        /// <returns></returns>
        public static uint GetGraphBorderColour(PlottedGraph graph)
        {
            if (graph.InternalProtoGraph.Terminated)
            {
                return 0xff0000ff;
            }

            switch (graph.InternalProtoGraph.TraceData.TraceState)
            {
                case TraceRecord.ProcessState.eTerminated:
                    return 0x4f00004f;
                case TraceRecord.ProcessState.eRunning:
                    return 0xff00ff00;
                case TraceRecord.ProcessState.eSuspended:
                    return 0xff47A3f0;
                default:
                    return 0;
            }
        }



    }
}
