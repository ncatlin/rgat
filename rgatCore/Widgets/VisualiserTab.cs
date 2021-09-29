using Humanizer;
using ImGuiNET;
using rgat.Threads;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Numerics;
using Veldrid;
using static rgat.CONSTANTS;

namespace rgat
{
    internal class VisualiserTab
    {
        private readonly GraphPlotWidget MainGraphWidget;
        public PreviewGraphsWidget PreviewGraphWidget { get; private set; }

        private VisualiserBar? _visualiserBar;
        private readonly rgatState _rgatState;
        private readonly ImGuiController _controller;

        //threads
        private Threads.VisualiserBarRendererThread? visbarRenderThreadObj = null;
        private Threads.MainGraphRenderThread? mainRenderThreadObj = null;

        public double UIFrameAverage = 0;

        public VisualiserTab(rgatState state, ImGuiController controller)
        {
            _rgatState = state;
            _controller = controller;
            MainGraphWidget = new GraphPlotWidget(state, controller, new Vector2(1000, 500));
            PreviewGraphWidget = new PreviewGraphsWidget(controller, state);
        }


        List<PreviewRendererThread> previewRenderers = new();

        public void Init(GraphicsDevice gd, IProgress<float> progress)
        {
            MainGraphWidget.Init(gd);//1000~ ms
            PreviewGraphWidget.Init(gd);
            _visualiserBar = new VisualiserBar(gd, _controller!); //200~ ms
            progress.Report(0.2f);

            //time depends on how many workers
            StartPreviewWorkers(progress);

            mainRenderThreadObj = new MainGraphRenderThread(MainGraphWidget);
            mainRenderThreadObj.Begin();

            visbarRenderThreadObj = new VisualiserBarRendererThread(_visualiserBar);
            visbarRenderThreadObj.Begin();
            progress.Report(1f);
        }


        /// <summary>
        /// Could do this at runtime instead of requiring a restart
        /// </summary>
        private void StartPreviewWorkers(IProgress<float> progress)
        {
            int count = Math.Max(GlobalConfig.Settings.UI.PreviewWorkers, CONSTANTS.UI.MINIMUM_PREVIEW_WORKERS);
            count = Math.Min(count, CONSTANTS.UI.MAXIMUM_PREVIEW_WORKERS);

            if (count == GlobalConfig.Settings.UI.PreviewWorkers)
            {
                Logging.RecordLogEvent($"Starting {count} preview workers", Logging.LogFilterType.TextDebug);
            }
            else
            {
                Logging.RecordLogEvent($"Starting {count} preview workers because the requested [{GlobalConfig.Settings.UI.PreviewWorkers}] was outside the limits");
            }


            /*
             * Always create a background worker that prioritises low priority threads so
             * traces that are not selected in the visualiser are not starved of rendering
             */
            PreviewRendererThread prev = new PreviewRendererThread(0, PreviewGraphWidget, _controller, _rgatState, background: true);
            previewRenderers.Add(prev);
            prev.Begin();

            for (var i = 1; i < count; i++)
            {
                prev = new PreviewRendererThread(i, PreviewGraphWidget, _controller, _rgatState, background: false);
                previewRenderers.Add(prev);
                prev.Begin();
                progress.Report(0.2f + ((float)i / (float)count));
            }
        }



        /// <summary>
        /// Called whenever the widget opens/closes an inner dialog
        /// </summary>
        /// <param name="callback">Function to call when dialog is opened/closed. Param is open/closed state.</param>
        public void SetDialogStateChangeCallback(Action<bool> callback)
        {
            _dialogStateChangeCallback = callback;
            MainGraphWidget.SetStateChangeCallback(callback);
        }

        private Action<bool>? _dialogStateChangeCallback = null;


        public void Draw()
        {
            Logging.RecordLogEvent("EEV");
            if (MainGraphWidget != null && PreviewGraphWidget != null)
            {
                Logging.RecordLogEvent("ESE");
                ManageActiveGraph();

                float controlsHeight = 230;

                Logging.RecordLogEvent("VEE");
                DrawVisualiserGraphs((ImGui.GetWindowContentRegionMax().Y - 16) - controlsHeight);
                Logging.RecordLogEvent("BB");
                DrawVisualiserControls(controlsHeight);
                Logging.RecordLogEvent("EE");
            }
        }


        private void DrawVisualiserGraphs(float height)
        {
            Vector2 graphSize = new Vector2(ImGui.GetContentRegionAvail().X - UI.PREVIEW_PANE_WIDTH, height);
            //ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(0, 0));
            if (ImGui.BeginChild(ImGui.GetID("MainGraphWidget"), graphSize))
            {
                MainGraphWidget.Draw(graphSize, _rgatState.ActiveGraph);

                Vector2 msgpos = ImGui.GetCursorScreenPos() + new Vector2(graphSize.X, -1 * graphSize.Y);
                MainGraphWidget.DisplayEventMessages(msgpos);
                ImGui.EndChild();
            }
            //ImGui.PopStyleVar();

            ImGui.SameLine(0, 0);

            Vector2 previewPaneSize = new Vector2(UI.PREVIEW_PANE_WIDTH, height);
            ImGui.PushStyleColor(ImGuiCol.Border, Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewPaneBorder));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.ePreviewPaneBackground));

            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(0, 0));
            if (ImGui.BeginChild(ImGui.GetID("GLVisThreads"), previewPaneSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                PreviewGraphWidget!.DrawWidget();
                if (PreviewGraphWidget.clickedGraph != null)
                {
                    SetActiveGraph(PreviewGraphWidget.clickedGraph);
                    PreviewGraphWidget.ResetClickedGraph();
                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar(4);
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();


        }

        public Vector2 GraphSize => MainGraphWidget.WidgetSize;
        public Vector2 GraphPosition => MainGraphWidget.WidgetPos;

        public bool ThreadsRunning => (mainRenderThreadObj != null && mainRenderThreadObj.Running);
        public bool MouseInMainWidget => MainGraphWidget != null && MainGraphWidget.MouseInWidget();


        public void NotifyMouseWheel(float _delta)
        {
            if (MouseInMainWidget)
            {
                MainGraphWidget?.ApplyZoom(_delta);
            }
        }

        public void NotifyMouseDrag(Vector2 _delta)
        {
            if (MouseInMainWidget)
            {
                MainGraphWidget?.ApplyMouseDrag(_delta);
            }
        }

        public void NotifyMouseRotate(Vector2 _delta)
        {
            if (MouseInMainWidget)
            {
                MainGraphWidget?.ApplyMouseRotate(_delta);
            }
        }

        public bool AlertRawKeyPress(Tuple<Key, ModifierKeys> KeyModifierTuple) => MainGraphWidget.AlertRawKeyPress(KeyModifierTuple);

        public bool AlertKeybindPressed(eKeybind action, Tuple<Key, ModifierKeys> KeyModifierTuple)
        {
            /*
            if (action == eKeybind.Cancel && _show_stats_dialog)
            {
                _show_stats_dialog = false;
                return true;
            }*/

            MainGraphWidget.AlertKeybindPressed(KeyModifierTuple, action);
            return false;
        }


        public void ClearPreviewTrace() => PreviewGraphWidget?.SetActiveTrace(null);

        private void DrawCameraPopup()
        {
            PlottedGraph? ActiveGraph = _rgatState.ActiveGraph;
            if (ActiveGraph == null)
            {
                return;
            }

            if (ImGui.BeginChild(ImGui.GetID("CameraControlsb"), new Vector2(235, 200)))
            {
                ImGui.DragFloat("Field Of View", ref ActiveGraph.CameraFieldOfView, 0.005f, 0.05f, (float)Math.PI, "%f");
                ImGui.DragFloat("Near Clipping", ref ActiveGraph.CameraClippingNear, 50.0f, 0.1f, 200000f, "%f");
                ImGui.DragFloat("Far Clipping", ref ActiveGraph.CameraClippingFar, 50.0f, 0.1f, 200000f, "%f");
                ImGui.DragFloat("X Shift", ref ActiveGraph.CameraXOffset, 1f, -400, 40000, "%f");
                ImGui.DragFloat("Y Position", ref ActiveGraph.CameraYOffset, 1, -400, 200000, "%f");

                ImGui.DragFloat("Zoom", ref ActiveGraph.CameraZoom, 5, 100, 100000, "%f");
                //ImGui.DragFloat("Rotation", ref ActiveGraph.PlotZRotation, 0.01f, -10, 10, "%f");
                ImGui.EndChild();
            }
        }


        private unsafe void DrawPlaybackControls(float otherControlsHeight, float width)
        {
            PlottedGraph? activeGraph = _rgatState.ActiveGraph;
            if (activeGraph == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(width, otherControlsHeight)))
                {
                    ImGui.Text("No active graph");

                    ImGui.EndChild();
                }
                return;
            }

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF000000);

            if (ImGui.BeginChild(ImGui.GetID("ReplayControlPanel"), new Vector2(width, otherControlsHeight)))
            {
                _visualiserBar!.DrawReplaySlider(width: width - 10, height: 50, graph: activeGraph);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);

                ImGui.BeginGroup();
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBg));
                    if (ImGui.BeginChild("ReplayControls", new Vector2(725, ImGui.GetContentRegionAvail().Y - 2)))
                    {

                        DrawReplayControlsPanel(activeGraph);
                        ImGui.SameLine();
                        DrawRenderControlPanel(activeGraph);
                        ImGui.SameLine();
                        DrawVideoControlPanel(activeGraph);
                        ImGui.SameLine();
                        DrawCameraPanel(activeGraph);

                        ImGui.EndChild();
                    }
                    ImGui.PopStyleColor();
                    ImGui.EndGroup();
                }
                ImGui.SameLine();
                //ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 8);
                DrawDiasmPreviewBox(activeGraph.InternalProtoGraph, (int)Math.Floor(activeGraph.AnimationIndex));

                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
        }

        private static void DrawReplayControlsPanel(PlottedGraph graph)
        {
            string indexPos = "";
            if (graph.AnimationIndex > 0)
            {
                indexPos = $" ({graph.AnimationIndex:F2}/{graph.InternalProtoGraph.SavedAnimationData.Count})";
            }

            switch (graph.ReplayState)
            {
                case PlottedGraph.REPLAY_STATE.Paused:
                    ImGui.Text("Trace Replay: Paused" + indexPos);
                    break;
                case PlottedGraph.REPLAY_STATE.Ended:
                    ImGui.Text("Trace Replay: Resetting" + indexPos);
                    break;
                case PlottedGraph.REPLAY_STATE.Playing:
                    ImGui.Text("Trace Replay: Replaying" + indexPos);
                    break;
                case PlottedGraph.REPLAY_STATE.Stopped:
                    ImGui.Text("Trace Replay: Stopped" + indexPos);
                    break;
            }


            if (ImGui.BeginChild("ReplayControlsFrame1", new Vector2(250, ImGui.GetContentRegionAvail().Y - 2), true))
            {

                ImGui.BeginGroup();
                {
                    PlottedGraph.REPLAY_STATE replaystate = graph.ReplayState;
                    string BtnText = replaystate == PlottedGraph.REPLAY_STATE.Playing ? "Pause" : "Play";


                    if (SmallWidgets.DisableableButton(BtnText, graph.InternalProtoGraph.TraceData.DiscardTraceData is false, new Vector2(38, 26)))
                    {
                        graph.PlayPauseClicked();
                    }
                    ImGui.SameLine();
                    if (SmallWidgets.DisableableButton("Reset", graph.InternalProtoGraph.TraceData.DiscardTraceData is false, new Vector2(38, 26)))
                    {
                        graph.ResetClicked();
                    }
                    ImGui.SameLine();
                    if (replaystate == PlottedGraph.REPLAY_STATE.Paused && ImGui.Button("Step", new Vector2(38, 26)))
                    {
                        ImGui.SameLine();
                        graph.StepPausedAnimation(1);
                    }
                    ImGui.EndGroup();
                }
                ImGui.SetNextItemWidth(120f);

                float speedVal = graph.AnimationRate;
                if (ImGui.DragFloat("##SpeedSlider", ref speedVal, 0.25f, 0, 100, format: "Replay Speed: %.2f", flags: ImGuiSliderFlags.Logarithmic))
                {
                    graph.AnimationRate = speedVal;
                }
                SmallWidgets.MouseoverText("The number of trace updates to replay per frame. Double click to set a custom rate.");
                ImGui.SameLine();

                ImGui.SetNextItemWidth(65f);
                if (ImGui.BeginCombo("##Replay Speed", $" {graph.AnimationRate:F2}", ImGuiComboFlags.HeightLargest))
                {
                    if (ImGui.Selectable("x1/10"))
                    {
                        graph.AnimationRate = 0.1f;
                    }

                    if (ImGui.Selectable("x1/4"))
                    {
                        graph.AnimationRate = 0.25f;
                    }

                    if (ImGui.Selectable("x1/2"))
                    {
                        graph.AnimationRate = 0.5f;
                    }

                    if (ImGui.Selectable("x1"))
                    {
                        graph.AnimationRate = 1;
                    }

                    if (ImGui.Selectable("x2"))
                    {
                        graph.AnimationRate = 2;
                    }

                    if (ImGui.Selectable("x5"))
                    {
                        graph.AnimationRate = 5;
                    }

                    if (ImGui.Selectable("x10"))
                    {
                        graph.AnimationRate = 10;
                    }

                    if (ImGui.Selectable("x25"))
                    {
                        graph.AnimationRate = 25;
                    }

                    if (ImGui.Selectable("x50"))
                    {
                        graph.AnimationRate = 50;
                    }

                    if (ImGui.Selectable("x100"))
                    {
                        graph.AnimationRate = 100;
                    }

                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("The number of trace updates to replay per frame");

                ImGui.EndChild();
            }
        }

        private static void DrawActiveTraceControlPanel(PlottedGraph graph)
        {
            if (ImGui.BeginChild("LiveTraceCtrls", new Vector2(160, 110), true))
            {

                ImGui.Columns(2);
                ImGui.SetColumnWidth(0, 65);
                ImGui.SetColumnWidth(1, 90);


                ImGui.BeginGroup();
                {
                    if (ImGui.Button("Kill"))
                    {
                        graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "EXIT");
                    }
                    SmallWidgets.MouseoverText("Terminate the process running the current thread");

                    if (ImGui.Button("Kill All"))
                    {
                        Logging.WriteConsole("Kill All clicked");
                    }

                    ImGui.EndGroup();
                }

                ImGui.NextColumn();

                ImGui.BeginGroup();
                {
                    if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.ProcessState.eRunning)
                    {
                        if (ImGui.Button("Pause/Break"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "BRK");
                        }
                        SmallWidgets.MouseoverText("Pause all process threads");
                    }

                    if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.ProcessState.eSuspended)
                    {
                        if (ImGui.Button("Continue"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "CTU");
                        }
                        SmallWidgets.MouseoverText("Resume all process threads");

                        if (ImGui.Button("Step In"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugStep(graph.InternalProtoGraph);
                        }
                        SmallWidgets.MouseoverText("Step to next instruction");

                        if (ImGui.Button("Step Over"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugStepOver(graph.InternalProtoGraph);
                        }
                        SmallWidgets.MouseoverText("Step past call instruction");

                    }
                    ImGui.EndGroup();
                }
                ImGui.Columns(1);
                ImGui.EndChild();
            }
        }

        private static void DrawRenderControlPanel(PlottedGraph graph)
        {
            if (ImGui.BeginChild("GraphRenderControlsFrame1", new Vector2(180, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                if (SmallWidgets.ToggleButton("AnimatedToggle", graph.IsAnimated, "In animated mode the graph is dark with active regions lit up"))
                {
                    graph.SetAnimated(!graph.IsAnimated);
                }
                ImGui.SameLine();
                ImGui.Text(graph.IsAnimated ? "Animated" : "Static Brightness");

                if (SmallWidgets.ToggleButton("LayoutComputeEnabled", GlobalConfig.LayoutPositionsActive, "Toggle GPU graph layout compuation"))
                {
                    GlobalConfig.LayoutPositionsActive = !GlobalConfig.LayoutPositionsActive;
                }
                ImGui.SameLine();
                ImGui.Text(GlobalConfig.LayoutPositionsActive ? "Layout Enabled" : "Layout Disabled");
                ImGui.EndChild();
            }
        }


        private static void DrawVideoControlPanel(PlottedGraph graph)
        {
            if (ImGui.BeginChild("VideoControlsFrame1", new Vector2(130, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                if (rgatState.VideoRecorder.Recording)
                {
                    if (rgatState.VideoRecorder.CapturePaused)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                        if (ImGui.Button("Resume Capture")) //this is more intended as an indicator than a control
                        {
                            rgatState.VideoRecorder.CapturePaused = false;
                        }
                        ImGui.PopStyleColor();
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBg));
                        if (ImGui.Button("Stop Capture"))
                        {
                            rgatState.VideoRecorder.StopRecording();
                        }
                        ImGui.PopStyleColor();
                    }
                }
                else
                {
                    if (ImGui.Button("Start Capture"))
                    {
                        rgatState.VideoRecorder.StartRecording();
                    }
                }

                ImGui.Button("Add Caption");
                ImGui.Button("Capture Settings");
                ImGui.EndChild();
            }
        }


        private static void DrawCameraPanel(PlottedGraph graph)
        {
            if (ImGui.BeginChild("CameraStatFrame1", new Vector2(130, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                ImGui.Text($"CameraX: {graph.CameraXOffset}");
                ImGui.Text($"CameraY: {graph.CameraYOffset}");
                ImGui.Text($"CameraZ: {graph.CameraZoom}");
                if (graph.CenteringInFrame is not PlottedGraph.CenteringMode.Inactive)
                {
                    if (graph.CenteringInFrame is PlottedGraph.CenteringMode.Centering)
                        ImGui.Text("Centering...");
                    else if (graph.CenteringInFrame is PlottedGraph.CenteringMode.ContinuousCentering)
                        ImGui.Text("Centering [locked]");
                }
                ImGui.EndChild();
            }
        }


        private static void DrawDiasmPreviewBox(ProtoGraph graph, int lastAnimIdx)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
            if (ImGui.BeginChildFrame(ImGui.GetID("##DisasmPreview"), ImGui.GetContentRegionAvail()))
            {

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2);
                ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(10, 0));

                try
                {
                    if (lastAnimIdx >= 0 && lastAnimIdx < graph.SavedAnimationData.Count)
                    {
                        ANIMATIONENTRY lastEntry = graph.SavedAnimationData[lastAnimIdx];
                        ImGui.Text(lastEntry.entryType.ToString());
                        switch (lastEntry.entryType)
                        {
                            case eTraceUpdateType.eAnimExecTag:
                                {
                                    uint blkID = lastEntry.blockID;
                                    ImGui.Text($"Block {blkID} (0x{lastEntry.blockAddr})");
                                    if (blkID < uint.MaxValue)
                                    {
                                        List<InstructionData>? inslist = graph.ProcessData.getDisassemblyBlock(blockID: blkID);
                                        if (inslist is not null)
                                        {
                                            for (var i = Math.Max(0, inslist.Count - 5); i < inslist.Count; i++)
                                            {
                                                ImGui.Text(inslist[i].InsText);
                                            }
                                        }
                                    }
                                }
                                break;
                            case eTraceUpdateType.eAnimUnchained:
                                {
                                    int ucBlkCount = 0;
                                    for (var i = lastAnimIdx; i > 0; i--)
                                    {
                                        if (graph.SavedAnimationData[i].entryType != eTraceUpdateType.eAnimUnchained)
                                        {
                                            break;
                                        }

                                        ucBlkCount++;
                                    }
                                    ImGui.Text($"Busy area of {ucBlkCount} blocks");
                                }
                                break;
                            case eTraceUpdateType.eAnimUnchainedResults:
                                break;

                        }
                    }
                }
                catch { }
                ImGui.PopStyleVar(3);
                ImGui.EndChild();
            }
            else
            {
                ImGui.InvisibleButton("#badDismbox", new Vector2(1, 1));
            }

            ImGui.PopStyleColor();
        }


        private unsafe void DrawLiveTraceControls(float otherControlsHeight, float width, PlottedGraph graph)
        {
            float replayControlsSize = ImGui.GetContentRegionAvail().X;
            if (ImGui.BeginChild(ImGui.GetID("LiveTraceControlPanel"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                _visualiserBar!.Draw(width, 50);
                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("LiveControlsPane", new Vector2(500, ImGui.GetContentRegionAvail().Y - 2)))
                {
                    ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX(), ImGui.GetCursorPosY() + 6));
                    DrawActiveTraceControlPanel(graph);
                    ImGui.SameLine();
                    DrawRenderControlPanel(graph);
                    ImGui.SameLine();
                    DrawVideoControlPanel(graph);
                    ImGui.SameLine();
                    DrawCameraPanel(graph);
                    ImGui.EndChild();
                }
                ImGui.SameLine();
                DrawDiasmPreviewBox(graph.InternalProtoGraph, graph.InternalProtoGraph.SavedAnimationData.Count - 1);
                ImGui.EndChild();
            }

        }

        private void SetActiveGraph(PlottedGraph graph)
        {
            if (_rgatState.ActiveGraph is not null && graph.PID != _rgatState.ActiveGraph.PID)
            {
                Logging.WriteConsole("Warning: Graph selected in inactive trace");
                return;
            }

            _rgatState.SwitchToGraph(graph);
            PreviewGraphWidget!.SetSelectedGraph(graph);
            //MainGraphWidget.SetActiveGraph(graph);
        }


        private void CreateTracesDropdown(TraceRecord tr, int level)
        {
            foreach (TraceRecord child in tr.Children)
            {
                string tabs = new string("  ");
                if (ImGui.Selectable(tabs + "PID " + child.PID, _rgatState.ActiveGraph?.PID == child.PID))
                {
                    _rgatState.SelectActiveTrace(child);
                }
                if (child.Children.Length > 0)
                {
                    CreateTracesDropdown(tr, level + 1);
                }
            }
        }


        private void DrawThreadSelectorCombo(ProtoGraph graph)
        {
            if (_rgatState.ActiveTrace != null)
            {
                string selString = $"TID {graph.ThreadID}: {graph.FirstInstrumentedModuleName}";
                List<PlottedGraph> graphs = _rgatState.ActiveTrace.GetPlottedGraphs();
                if (ImGui.BeginCombo($"{graphs.Count} Thread{(graphs.Count != 1 ? "s" : "")}", selString))
                {
                    foreach (PlottedGraph selectablegraph in graphs)
                    {
                        string caption = $"{selectablegraph.TID}: {selectablegraph.InternalProtoGraph.FirstInstrumentedModuleName}";
                        int nodeCount = selectablegraph.GraphNodeCount();
                        if (nodeCount == 0)
                        {
                            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                            caption += " [Uninstrumented]";
                        }
                        else
                        {
                            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                            caption += $" [{nodeCount} nodes]";
                        }

                        if (ImGui.Selectable(caption, graph.ThreadID == selectablegraph.TID) && nodeCount > 0)
                        {
                            SetActiveGraph(selectablegraph);
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.BeginTooltip();
                            ImGui.Text($"Thread Start: 0x{graph.StartAddress:X} [{graph.StartModuleName}]");
                            if (graph.NodeList.Count > 0)
                            {
                                NodeData? n = graph.GetNode(0);
                                if (n is not null)
                                {
                                    string insBase = System.IO.Path.GetFileName(graph.ProcessData.GetModulePath(n.GlobalModuleID));
                                    ImGui.Text($"First Instrumented: 0x{n.address:X} [{insBase}]");
                                }
                            }
                            ImGui.EndTooltip();
                        }
                        ImGui.PopStyleColor();
                    }
                    ImGui.EndCombo();
                }
            }
        }


        private void DrawPlotStatColumns(PlottedGraph plot)
        {
            ProtoGraph graph = plot.InternalProtoGraph;

            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);

            ImGui.Text($"Thread ID: {graph.ThreadID}");

            ImGui.SameLine();
            if (graph.Terminated)
            {
                ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Red), "(Terminated)");
            }
            else
            {
                ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.LimeGreen), $"(Active)");
            }

            float metricsHeight = ImGui.GetContentRegionAvail().Y - 4;
            ImGui.Columns(3, "visstatColumns");
            ImGui.SetColumnWidth(0, 12);
            ImGui.SetColumnWidth(1, 150);
            ImGui.SetColumnWidth(2, 170);
            ImGui.NextColumn();

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff110022);
            if (ImGui.BeginChild("ActiveTraceMetrics", new Vector2(130, metricsHeight)))
            {
                ImGui.Text($"Edges: {graph.EdgeCount}");
                ImGui.Text($"Nodes: {graph.NodeList.Count}");
                ImGui.Text($"Updates: {graph.UpdateCount}");
                ImGui.Text($"Instructions: {graph.TotalInstructions}");

                ImGui.EndChild();
            }

            ImGui.NextColumn();

            if (_stats_click_hover)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff313142);
            }

            if (ImGui.BeginChild("OtherMetrics", new Vector2(ImGui.GetContentRegionAvail().X, metricsHeight)))
            {
                if (graph.TraceReader != null)
                {
                    if (graph.TraceReader.QueueSize > 0)
                    {
                        ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.OrangeRed), $"Backlog: {graph.TraceReader.QueueSize}");
                    }
                    else
                    {
                        ImGui.Text($"Backlog: {graph.TraceReader.QueueSize}");
                    }
                }

                if (graph.PerformingUnchainedExecution)
                {
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Yellow), $"Busy: True");
                }
                else
                {
                    ImGui.Text("Busy: False");
                }
                SmallWidgets.MouseoverText("Busy if the thread is in a lightly instrumented high-CPU usage area");

                ThreadTraceProcessingThread? traceProcessor = graph.TraceProcessor;
                if (traceProcessor != null)
                {
                    string BrQlab = $"{traceProcessor.PendingBlockRepeats}";
                    if (traceProcessor.PendingBlockRepeats > 0)
                    {
                        BrQlab += $" {traceProcessor.LastBlockRepeatsTime}";
                    }
                    ImGui.Text($"BRepQu: {BrQlab}");
                }

                double fps = rgatUI.UIDrawFPS;
                if (fps >= 100)
                {
                    ImGui.Text($"UI FPS: 100+");
                }
                else
                {
                    uint fpscol;
                    if (fps >= 40)
                    {
                        fpscol = Themes.GetThemeColourImGui(ImGuiCol.Text);
                    }
                    else if (fps < 40 && fps >= 10)
                    {
                        fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                    }
                    else
                    {
                        fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    }

                    ImGui.PushStyleColor(ImGuiCol.Text, fpscol);
                    ImGui.Text($"UI FPS: {fps:0.#}");
                    ImGui.PopStyleColor();
                }
                SmallWidgets.MouseoverText($"How many frames the UI can render in one second (Last 10 Avg MS: {UIFrameAverage})");

                if (plot.ComputeLayoutSteps > 0)
                {
                    ImGui.Text($"Layout MS: {(plot.ComputeLayoutTime / plot.ComputeLayoutSteps):0.#}");
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text("How long it takes to complete a step of graph layout");
                        ImGui.Text($"Layout Cumulative Time: {plot.ComputeLayoutTime} MS - ({plot.ComputeLayoutSteps} steps");
                        ImGui.EndTooltip();
                    }
                }


                ImGui.EndChild();
                if (ImGui.IsItemClicked())
                {
                    rgatUI.ToggleRenderStatsDialog();
                }
            }
            if (_stats_click_hover)
            {
                ImGui.PopStyleColor();
            }

            _stats_click_hover = ImGui.IsItemHovered();
            ImGui.PopStyleColor();
            ImGui.Columns(1, "smushes");
        }


        private void DrawTraceSelector(float frameHeight, float frameWidth)
        {

            PlottedGraph? plot = _rgatState.ActiveGraph;
            if (plot == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(frameWidth, frameHeight)))
                {
                    ImGui.Text($"No selected graph");
                    ImGui.EndChild();
                }
                return;
            }
            ProtoGraph graph = plot.InternalProtoGraph;

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);
            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(frameWidth - 15, frameHeight)))
            {
                if (_rgatState.ActiveTarget != null)
                {
                    var tracelist = _rgatState.ActiveTarget.GetTracesUIList();
                    string selString = "PID " + graph.TraceData.PID;
                    if (ImGui.BeginCombo($"{tracelist.Count} Process{(tracelist.Count != 1 ? "es" : "")}", selString))
                    {
                        foreach (var timepid in tracelist)
                        {
                            TraceRecord selectableTrace = timepid.Item2;
                            if (ImGui.Selectable("PID " + selectableTrace.PID, graph.TraceData.PID == selectableTrace.PID))
                            {
                                _rgatState.SelectActiveTrace(selectableTrace);
                            }
                            if (selectableTrace.Children.Length > 0)
                            {
                                CreateTracesDropdown(selectableTrace, 1);
                            }
                        }
                        ImGui.EndCombo();
                    }
                    DrawThreadSelectorCombo(graph);
                }

                DrawPlotStatColumns(plot);

                ImGui.EndChild();
            }
            ImGui.PopStyleColor(1);

            if (rgatUI.ShowStatsDialog)
            {
                bool closeClick = true;
                DrawGraphStatsDialog(ref closeClick);
                if (closeClick is false) rgatUI.ToggleRenderStatsDialog();
            }
        }

        private bool _stats_click_hover = false;

        private unsafe void DrawVisualiserControls(float controlsHeight)
        {
            float vpadding = 10;

            if (_rgatState.ActiveGraph == null)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF222222);
                if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(ImGui.GetContentRegionAvail().X, controlsHeight - vpadding)))
                {
                    string caption = "No trace to display";
                    ImguiUtils.DrawRegionCenteredText(caption);
                    ImGui.Text($"temp: {_rgatState.ActiveGraph?.Temperature}");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                return;
            }
            float topControlsBarHeight = 30;
            float otherControlsHeight = controlsHeight - topControlsBarHeight;
            float frameHeight = otherControlsHeight - vpadding;
            float controlsWidth = ImGui.GetContentRegionAvail().X;

            if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(controlsWidth - 10, frameHeight)))
            {
                PlottedGraph activeGraph = _rgatState.ActiveGraph;
                if (activeGraph != null)
                {
                    if (ImGui.BeginChild("ControlsInner", new Vector2((controlsWidth - UI.PREVIEW_PANE_WIDTH), frameHeight)))
                    {
                        if (!activeGraph.InternalProtoGraph.Terminated)
                        {
                            DrawLiveTraceControls(frameHeight, ImGui.GetContentRegionAvail().X, activeGraph);
                        }
                        else
                        {
                            DrawPlaybackControls(frameHeight, ImGui.GetContentRegionAvail().X);
                        }
                        ImGui.EndChild();
                    }
                }
                ImGui.SameLine();
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() - 5); //too much item padding
                DrawTraceSelector(frameHeight, UI.PREVIEW_PANE_WIDTH);
                ImGui.EndChild();
            }
        }

        private void ManageActiveGraph()
        {
            if (_rgatState.ActiveGraph == null)
            {
                if (_rgatState.ActiveTrace == null)
                {
                    _rgatState.SelectActiveTrace();
                }

                if (PreviewGraphWidget is null)
                {
                    return;
                }

                if (_rgatState.ChooseActiveGraph())
                {
                    if (rgatState.RecordVideoOnNextTrace)
                    {
                        rgatState.VideoRecorder.StartRecording();
                        rgatState.RecordVideoOnNextTrace = false;
                    }
                    PreviewGraphWidget.SetActiveTrace(_rgatState.ActiveTrace);
                    PreviewGraphWidget.SetSelectedGraph(_rgatState.ActiveGraph);
                }
                else
                {
                    if (MainGraphWidget.ActiveGraph != null)
                    {
                        PreviewGraphWidget.SetActiveTrace(null);
                    }
                }
            }
            else if (_rgatState.ActiveGraph != MainGraphWidget.ActiveGraph)
            {

                if (rgatState.RecordVideoOnNextTrace)
                {
                    rgatState.VideoRecorder.StartRecording();
                    rgatState.RecordVideoOnNextTrace = false;
                }

                PreviewGraphWidget!.SetActiveTrace(_rgatState.ActiveTrace);
                PreviewGraphWidget!.SetSelectedGraph(_rgatState.ActiveGraph);
            }
        }



        public void DrawGraphStatsDialog(ref bool hideme)
        {
            if (_rgatState.ActiveGraph == null)
            {
                return;
            }

            PlottedGraph graphplot = _rgatState.ActiveGraph;
            ProtoGraph graph = graphplot.InternalProtoGraph;

            ImGui.SetNextWindowSize(new Vector2(800, 500), ImGuiCond.Appearing);

            if (ImGui.Begin("Performance Statistics", ref hideme))
            {

                if (ImGui.BeginTable("#StatsTable", 3, ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg))
                {
                    ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 120);
                    ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthFixed, 220);
                    ImGui.TableSetupColumn("Explain");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Trace Backlog");
                    ImGui.TableNextColumn();

                    if (graph.TraceReader != null)
                    {
                        if (graph.TraceReader.QueueSize > 0)
                        {
                            ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.OrangeRed), $"{graph.TraceReader.QueueSize}");
                        }
                        else
                        {
                            ImGui.Text($"{graph.TraceReader.QueueSize}");
                        }
                    }

                    ImGui.TableNextColumn();
                    ImGui.Text("Number of items in trace data backlog");


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Busy");
                    ImGui.TableNextColumn();

                    if (graph.PerformingUnchainedExecution)
                    {
                        ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Yellow), $"True");
                    }
                    else
                    {
                        ImGui.Text("False");
                    }

                    ImGui.TableNextColumn();
                    ImGui.Text("The thread is in a lightly instrumented high-CPU usage area");


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Repeat Queue");
                    ImGui.TableNextColumn();

                    ThreadTraceProcessingThread? traceProcessor = graph.TraceProcessor;
                    if (traceProcessor != null)
                    {
                        string BrQlab = $"{traceProcessor.PendingBlockRepeats}";
                        if (traceProcessor.PendingBlockRepeats > 0)
                        {
                            BrQlab += $" {traceProcessor.LastBlockRepeatsTime}";
                        }
                        ImGui.Text($"{BrQlab}");
                    }

                    ImGui.TableNextColumn();
                    ImGui.Text("Deinstrumented execution counts awaiting assignment to the graph");

                    ImGui.TableNextRow();

                    ImGui.TableNextColumn();
                    ImGui.Text($"UI FPS");
                    ImGui.TableNextColumn();

                    double fps = rgatUI.UIDrawFPS;
                    if (fps >= 100)
                    {
                        ImGui.Text("100+");
                    }
                    else
                    {
                        uint fpscol;
                        if (fps >= 40)
                        {
                            fpscol = Themes.GetThemeColourImGui(ImGuiCol.Text);
                        }
                        else if (fps < 40 && fps >= 10)
                        {
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                        }
                        else
                        {
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                        }

                        ImGui.PushStyleColor(ImGuiCol.Text, fpscol);
                        ImGui.Text($"{fps:0.#}");
                        ImGui.PopStyleColor();
                    }
                    ImGui.TableNextColumn();
                    ImGui.Text("How many frames the UI can render in one second");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Frame Time (Last 10)");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{UIFrameAverage} MS");
                    ImGui.TableNextColumn();
                    ImGui.Text("Average time to render a UI frame over last 10 frames");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Graph Temperature");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{graphplot.Temperature}");
                    ImGui.TableNextColumn();
                    ImGui.Text("This sets the speed of graph layout and slows over time");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Layout Step Time");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{MainGraphWidget.LayoutEngine.AverageComputeTime:0.#} MS");
                    ImGui.TableNextColumn();
                    ImGui.Text($"Time to complete a step of layout (Avg over {GlobalConfig.StatisticsTimeAvgWindow} steps)");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Total Layout Time");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{graphplot.ComputeLayoutTime:0.#} MS over ({graphplot.ComputeLayoutSteps} steps (Avg: {graphplot.ComputeLayoutTime / graphplot.ComputeLayoutSteps:0.#})");
                    ImGui.TableNextColumn();
                    ImGui.Text("Total compute engine time used to generate this layout");

                    double accountedComputeTime = graphplot.VelocitySetupTime + graphplot.VelocityShaderTime +
                        graphplot.PositionSetupTime + graphplot.PositionShaderTime +
                        graphplot.AttributeSetupTime + graphplot.AttributeShaderTime;


                    if (graphplot.VelocitySteps is not 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Setup MS");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.VelocitySetupTime:0.#} MS over ({graphplot.VelocitySteps} steps (Avg: {graphplot.VelocitySetupTime / graphplot.VelocitySteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to measure forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff884444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.VelocityShaderTime:0.#} MS over ({graphplot.VelocitySteps} steps (Avg: {graphplot.VelocityShaderTime / graphplot.VelocitySteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent measuring forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff884444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity %");
                        ImGui.TableNextColumn();
                        double velpc = ((graphplot.VelocitySetupTime + graphplot.VelocityShaderTime)) / accountedComputeTime;
                        ImGui.Text($"{velpc * 100.0:0.#}%%");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent measuring forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff884444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.VelocityNodes / graphplot.VelocityShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the velocity shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff884444);
                    }

                    if (graphplot.PositionSteps is not 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.PositionSetupTime:0.#} MS over ({graphplot.PositionSteps} steps (Avg: {graphplot.PositionSetupTime / graphplot.PositionSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to move nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff684444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.PositionShaderTime:0.#} MS over ({graphplot.PositionSteps} steps (Avg: {graphplot.PositionShaderTime / graphplot.PositionSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent moving nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff684444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Time %");
                        ImGui.TableNextColumn();
                        double pospc = ((graphplot.PositionSetupTime + graphplot.PositionShaderTime)) / accountedComputeTime;
                        ImGui.Text($"{pospc * 100.0:0.#}%%");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent moving nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff684444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.PositionNodes / graphplot.PositionShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the position shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff684444);

                    }

                    if (graphplot.AttributeSteps is not 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.AttributeSetupTime:0.#} MS over ({graphplot.AttributeSteps} steps (Avg: {graphplot.AttributeSetupTime / graphplot.AttributeSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to animate nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff484444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.AttributeShaderTime:0.#} MS over ({graphplot.AttributeSteps} steps (Avg: {graphplot.AttributeShaderTime / graphplot.AttributeSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent animating nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff484444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Time %");
                        ImGui.TableNextColumn();
                        double attpc = ((graphplot.AttributeSetupTime + graphplot.AttributeShaderTime)) / accountedComputeTime;
                        ImGui.Text($"{attpc * 100.0:0.#}%%");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent animating nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff484444);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.AttributeNodes / graphplot.AttributeShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the attribute shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, 0xff484444);
                    }


                    if (graphplot.ComputeLayoutSteps is not 0)
                    {
                        double setupTime = graphplot.ComputeLayoutTime - accountedComputeTime;

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{setupTime:0.#} MS over ({graphplot.ComputeLayoutSteps} steps (Avg: {setupTime / graphplot.ComputeLayoutSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent setting up resources");

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Misc Time %");
                        ImGui.TableNextColumn();
                        double unaccpc = (setupTime / graphplot.ComputeLayoutTime) * 100.0;
                        ImGui.Text($"{setupTime:0.#} MS ({unaccpc:0.#} %%)");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent managing layout");
                    }


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Allocated VRAM");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{VeldridGraphBuffers.AllocatedBytes.Bytes()} ({VeldridGraphBuffers.AllocatedBuffers} buffers)");
                    ImGui.TableNextColumn();
                    ImGui.Text("GPU compute buffers, excluding resource sets");

                    if (rgatState.VideoRecorder.Recording)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Video Frame Backlog");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{rgatState.VideoRecorder.FrameQueueSize}");
                        ImGui.TableNextColumn();
                        ImGui.Text("Number of recorded frames awaiting commit to video");
                    }
                    ImGui.EndTable();
                }
                ImGui.End();
            }
        }
    }
}
