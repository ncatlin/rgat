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
    class VisualiserTab
    {
        GraphPlotWidget MainGraphWidget;
        public PreviewGraphsWidget PreviewGraphWidget { get; private set; }
        VisualiserBar _visualiserBar;
        readonly rgatState _rgatState;

        //threads
        Threads.VisualiserBarRendererThread? visbarRenderThreadObj = null;
        Threads.MainGraphRenderThread? mainRenderThreadObj = null;

        public double UIFrameAverage = 0;

        public VisualiserTab(rgatState _state)
        {
            _rgatState = _state;
        }

        public void Init(GraphicsDevice gd, ImGuiController controller, IProgress<float> progress)
        {
            _visualiserBar = new VisualiserBar(gd, controller); //200~ ms
            progress.Report(0.3f);
            MainGraphWidget = new GraphPlotWidget(controller, gd, _rgatState, new Vector2(1000, 500)); //1000~ ms

            progress.Report(0.8f);
            PreviewGraphWidget = new PreviewGraphsWidget(controller, gd, _rgatState); //350~ ms
            PreviewRendererThread.SetPreviewWidget(PreviewGraphWidget);

            progress.Report(0.99f);

            mainRenderThreadObj = new MainGraphRenderThread(MainGraphWidget);
            mainRenderThreadObj.Begin();

            visbarRenderThreadObj = new VisualiserBarRendererThread(_visualiserBar);
            visbarRenderThreadObj.Begin();
            progress.Report(1f);
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
        Action<bool>? _dialogStateChangeCallback = null;


        public void Draw()
        {
            if (MainGraphWidget != null && PreviewGraphWidget != null)
            {
                ManageActiveGraph();

                float controlsHeight = 230;

                DrawVisualiserGraphs((ImGui.GetWindowContentRegionMax().Y - 13) - controlsHeight);
                DrawVisualiserControls(controlsHeight);
            }
            ImGui.EndTabItem();
        }


        private void DrawVisualiserGraphs(float height)
        {
            Vector2 graphSize = new Vector2(ImGui.GetContentRegionAvail().X - UI.PREVIEW_PANE_WIDTH, height);
            if (ImGui.BeginChild(ImGui.GetID("MainGraphWidget"), graphSize))
            {
                MainGraphWidget.Draw(graphSize, _rgatState.ActiveGraph);

                Vector2 msgpos = ImGui.GetCursorScreenPos() + new Vector2(graphSize.X, -1 * graphSize.Y);
                MainGraphWidget.DisplayEventMessages(msgpos);
                ImGui.EndChild();
            }

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
                PreviewGraphWidget.DrawWidget();
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
            if (action == eKeybind.Cancel && _show_stats_dialog)
            {
                _show_stats_dialog = false;
                return true;
            }

            MainGraphWidget.AlertKeybindPressed(KeyModifierTuple, action);
            return false;
        }


        public void ClearPreviewTrace() => PreviewGraphWidget?.SetActiveTrace(null);

        private void DrawCameraPopup()
        {
            PlottedGraph? ActiveGraph = _rgatState.ActiveGraph;
            if (ActiveGraph == null) return;

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
                _visualiserBar.DrawReplaySlider(width: width, height: 50, graph: activeGraph);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);

                ImGui.BeginGroup();
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBg));
                    if (ImGui.BeginChild("ReplayControls", new Vector2(600, ImGui.GetContentRegionAvail().Y - 2)))
                    {

                        DrawReplayControlsPanel(activeGraph);
                        ImGui.SameLine();
                        DrawRenderControlPanel(activeGraph);
                        ImGui.SameLine();
                        DrawVideoControlPanel(activeGraph);

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

        void DrawReplayControlsPanel(PlottedGraph graph)
        {
            string indexPos = "";
            if (graph.AnimationIndex > 0)
                indexPos = $" ({graph.AnimationIndex:F2}/{graph.InternalProtoGraph.SavedAnimationData.Count})";
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

                    if (ImGui.Button(BtnText, new Vector2(38, 26)))
                    {
                        graph.PlayPauseClicked();
                    }
                    ImGui.SameLine();
                    if (ImGui.Button("Reset", new Vector2(38, 26)))
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
                    if (ImGui.Selectable("x1/10")) graph.AnimationRate = 0.1f;
                    if (ImGui.Selectable("x1/4")) graph.AnimationRate = 0.25f;
                    if (ImGui.Selectable("x1/2")) graph.AnimationRate = 0.5f;
                    if (ImGui.Selectable("x1")) graph.AnimationRate = 1;
                    if (ImGui.Selectable("x2")) graph.AnimationRate = 2;
                    if (ImGui.Selectable("x5")) graph.AnimationRate = 5;
                    if (ImGui.Selectable("x10")) graph.AnimationRate = 10;
                    if (ImGui.Selectable("x25")) graph.AnimationRate = 25;
                    if (ImGui.Selectable("x50")) graph.AnimationRate = 50;
                    if (ImGui.Selectable("x100")) graph.AnimationRate = 100;
                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("The number of trace updates to replay per frame");

                ImGui.EndChild();
            }
        }

        void DrawActiveTraceControlPanel(PlottedGraph graph)
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

                    if (ImGui.Button("Kill All")) Console.WriteLine("Kill All clicked");
                    ImGui.EndGroup();
                }

                ImGui.NextColumn();

                ImGui.BeginGroup();
                {
                    if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eRunning)
                    {
                        if (ImGui.Button("Pause/Break"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "BRK");
                        }
                        SmallWidgets.MouseoverText("Pause all process threads");
                    }

                    if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eSuspended)
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


        void DrawRenderControlPanel(PlottedGraph graph)
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



        void DrawVideoControlPanel(PlottedGraph graph)
        {
            if (ImGui.BeginChild("VideoControlsFrame1", new Vector2(180, ImGui.GetContentRegionAvail().Y - 2), true))
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






        void DrawDiasmPreviewBox(ProtoGraph graph, int lastAnimIdx)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
            if (ImGui.BeginChildFrame(ImGui.GetID("##DisasmPreview"), ImGui.GetContentRegionAvail()))
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2);
                ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(10, 0));

                if (lastAnimIdx >= 0 && lastAnimIdx < graph.SavedAnimationData.Count)
                {
                    ANIMATIONENTRY lastEntry = graph.SavedAnimationData[lastAnimIdx];
                    ImGui.Text(lastEntry.entryType.ToString());
                    switch (lastEntry.entryType)
                    {
                        case eTraceUpdateType.eAnimExecTag:
                            {
                                uint blkID = lastEntry.blockID;
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
                                        break;
                                    ucBlkCount++;
                                }
                                ImGui.Text($"Busy area of {ucBlkCount} blocks");
                            }
                            break;
                        case eTraceUpdateType.eAnimUnchainedResults:
                            break;

                    }
                }
                /*
                ImGui.Text("0x400000: xor eax, eax");
                ImGui.Text("0x400001: xor eax, eax");
                ImGui.Text("0x400002: xor eax, eax");
                ImGui.Text("0x400003: xor eax, eax");
                ImGui.Text("0x400004: xor eax, eax");
                ImGui.Text("0x400005: xor eax, eax");
                */
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

                _visualiserBar.Draw(width, 50);
                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("LiveControlsPane", new Vector2(500, ImGui.GetContentRegionAvail().Y - 2)))
                {
                    ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX(), ImGui.GetCursorPosY() + 6));
                    DrawActiveTraceControlPanel(graph);
                    ImGui.SameLine();
                    DrawRenderControlPanel(graph);
                    ImGui.SameLine();
                    DrawVideoControlPanel(graph);
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
                Console.WriteLine("Warning: Graph selected in inactive trace");
                return;
            }

            _rgatState.SwitchToGraph(graph);
            PreviewGraphWidget.SetSelectedGraph(graph);
            //MainGraphWidget.SetActiveGraph(graph);
        }


        private void CreateTracesDropdown(TraceRecord tr, int level)
        {
            foreach (TraceRecord child in tr.children)
            {
                string tabs = new String("  ");
                if (ImGui.Selectable(tabs + "PID " + child.PID, _rgatState.ActiveGraph?.PID == child.PID))
                {
                    _rgatState.SelectActiveTrace(child);
                }
                if (child.children.Count > 0)
                {
                    CreateTracesDropdown(tr, level + 1);
                }
            }
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

            float vpadding = 4;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);

            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(frameWidth, frameHeight)))
            {

                float combosHeight = 60 - vpadding;

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
                            if (selectableTrace.children.Count > 0)
                            {
                                CreateTracesDropdown(selectableTrace, 1);
                            }
                            //ImGui.Selectable("PID 12345 (xyz.exe)");
                        }
                        ImGui.EndCombo();
                    }

                    if (_rgatState.ActiveTrace != null)
                    {
                        selString = "TID " + graph.ThreadID;
                        List<PlottedGraph> graphs = _rgatState.ActiveTrace.GetPlottedGraphs();
                        if (ImGui.BeginCombo($"{graphs.Count} Thread{(graphs.Count != 1 ? "s" : "")}", selString))
                        {
                            foreach (PlottedGraph selectablegraph in graphs)
                            {
                                string caption = $"{selectablegraph.TID}: {selectablegraph.InternalProtoGraph.StartModuleName}";
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



                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);

                ImGui.Text($"Thread ID: {graph.ThreadID}");

                ImGui.SameLine();
                if (graph.Terminated)
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Red), "(Terminated)");
                else
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.LimeGreen), $"(Active)");

                float metricsHeight = ImGui.GetContentRegionAvail().Y - 4;
                ImGui.Columns(3, "smushes");
                ImGui.SetColumnWidth(0, 20);
                ImGui.SetColumnWidth(1, 130);
                ImGui.SetColumnWidth(2, 250);
                ImGui.NextColumn();

                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff110022);
                if (ImGui.BeginChild("ActiveTraceMetrics", new Vector2(130, metricsHeight)))
                {
                    ImGui.Text($"Edges: {graph.EdgeCount}");
                    ImGui.Text($"Nodes: {graph.NodeList.Count}");
                    ImGui.Text($"Updates: {graph.SavedAnimationData.Count}");
                    ImGui.Text($"Instructions: {graph.TotalInstructions}");

                    ImGui.EndChild();
                }

                ImGui.NextColumn();

                if (_stats_click_hover) ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff313142);
                if (ImGui.BeginChild("OtherMetrics", new Vector2(200, metricsHeight)))
                {
                    if (graph.TraceReader != null)
                    {
                        if (graph.TraceReader.QueueSize > 0)
                            ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.OrangeRed), $"Backlog: {graph.TraceReader.QueueSize}");
                        else
                            ImGui.Text($"Backlog: {graph.TraceReader.QueueSize}");
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
                            fpscol = Themes.GetThemeColourImGui(ImGuiCol.Text);
                        else if (fps < 40 && fps >= 10)
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                        else
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);

                        ImGui.PushStyleColor(ImGuiCol.Text, fpscol);
                        ImGui.Text($"UI FPS: {fps:0.#}");
                        ImGui.PopStyleColor();
                    }
                    SmallWidgets.MouseoverText($"How many frames the UI can render in one second (Last 10 Avg MS: {UIFrameAverage})");

                    ImGui.Text($"Layout MS: {MainGraphWidget.LayoutEngine.AverageComputeTime:0.#}");
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text("How long it takes to complete a step of graph layout");
                        ImGui.Text($"Layout Cumulative Time: {MainGraphWidget.ActiveGraph?.ComputeLayoutTime} MS - ({MainGraphWidget.ActiveGraph?.ComputeLayoutSteps} steps");
                        ImGui.EndTooltip();
                    }
                    //ImGui.Text($"AllocMem: {_controller.graphicsDevice.MemoryManager._totalAllocatedBytes}");

                    ImGui.EndChild();
                    if (ImGui.IsItemClicked())
                    {
                        _show_stats_dialog = !_show_stats_dialog;
                    }
                }
                if (_stats_click_hover) ImGui.PopStyleColor();

                _stats_click_hover = ImGui.IsItemHovered();
                ImGui.PopStyleColor();
                ImGui.Columns(1, "smushes");


                ImGui.EndChild();
            }
            ImGui.PopStyleColor();

            if (_show_stats_dialog) DrawGraphStatsDialog(ref _show_stats_dialog);
        }
        bool _stats_click_hover = false;
        bool _show_stats_dialog = false;

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
            if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(controlsWidth, frameHeight)))
            {
                PlottedGraph activeGraph = _rgatState.ActiveGraph;
                if (activeGraph != null)
                {
                    if (ImGui.BeginChild("ControlsInner", new Vector2(controlsWidth - UI.PREVIEW_PANE_WIDTH, frameHeight)))
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
                DrawTraceSelector(frameHeight, UI.PREVIEW_PANE_WIDTH);
                ImGui.EndChild();
            }

        }



        void ManageActiveGraph()
        {
            if (_rgatState.ActiveGraph == null)
            {
                if (_rgatState.ActiveTrace == null)
                {
                    _rgatState.SelectActiveTrace();
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

                PreviewGraphWidget.SetActiveTrace(_rgatState.ActiveTrace);
                PreviewGraphWidget.SetSelectedGraph(_rgatState.ActiveGraph);
            }
        }



        public void DrawGraphStatsDialog(ref bool hideme)
        {
            if (_rgatState.ActiveGraph == null) return;
            PlottedGraph graphplot = _rgatState.ActiveGraph;
            ProtoGraph graph = graphplot.InternalProtoGraph;

            ImGui.SetNextWindowSize(new Vector2(800, 250), ImGuiCond.Appearing);

            if (ImGui.Begin("Graph Performance Stats", ref hideme))
            {

                if (ImGui.BeginTable("#StatsTable", 3))
                {
                    ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 120);
                    ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthFixed, 80);
                    ImGui.TableSetupColumn("Explain");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Trace Backlog");
                    ImGui.TableNextColumn();

                    if (graph.TraceReader != null)
                    {
                        if (graph.TraceReader.QueueSize > 0)
                            ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.OrangeRed), $"{graph.TraceReader.QueueSize}");
                        else
                            ImGui.Text($"{graph.TraceReader.QueueSize}");
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
                            fpscol = Themes.GetThemeColourImGui(ImGuiCol.Text);
                        else if (fps < 40 && fps >= 10)
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                        else
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);

                        ImGui.PushStyleColor(ImGuiCol.Text, fpscol);
                        ImGui.Text($"{fps:0.#}");
                        ImGui.PopStyleColor();
                    }
                    ImGui.TableNextColumn();
                    ImGui.Text("How many frames the UI can render in one second");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("FPS (Last 10)");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{UIFrameAverage} MS");
                    ImGui.TableNextColumn();
                    ImGui.Text("Average time to render a UI frame over last 10 frames");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Layout Step Time");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{MainGraphWidget.LayoutEngine.AverageComputeTime:0.#} MS");
                    ImGui.TableNextColumn();
                    ImGui.Text($"Time to complete a step of layout (Avg over {GlobalConfig.StatisticsTimeAvgWindow} steps)");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Total Layout Steps");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{MainGraphWidget.ActiveGraph?.ComputeLayoutSteps}");
                    ImGui.TableNextColumn();
                    ImGui.Text("How many steps it took to create this layout");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Total Layout Time");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{MainGraphWidget.ActiveGraph?.ComputeLayoutTime:0.#} MS");
                    ImGui.TableNextColumn();
                    ImGui.Text("Total GPU time used to generate this layout");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text($"Graph Temperature");
                    ImGui.TableNextColumn();
                    ImGui.Text($"{graphplot.Temperature}");
                    ImGui.TableNextColumn();
                    ImGui.Text("This sets the speed of graph layout and slows over time");

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
