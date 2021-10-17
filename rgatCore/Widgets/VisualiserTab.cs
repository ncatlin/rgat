using Humanizer;
using ImGuiNET;
using rgat.Threads;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
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

        readonly List<PreviewRendererThread> previewRenderers = new();


        public VisualiserTab(rgatState state, ImGuiController controller)
        {
            _rgatState = state;
            _controller = controller;
            MainGraphWidget = new GraphPlotWidget(state, controller, new Vector2(1000, 500));
            PreviewGraphWidget = new PreviewGraphsWidget(controller, state);
        }



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
                Logging.RecordLogEvent($"Starting {count} preview workers", Logging.LogFilterType.Debug);
            }
            else
            {
                Logging.RecordLogEvent($"Starting {count} preview workers because the requested [{GlobalConfig.Settings.UI.PreviewWorkers}] was outside the limits");
            }


            /*
             * Always create a background worker that prioritises low priority threads so
             * traces that are not selected in the visualiser are not starved of rendering
             */
            PreviewRendererThread prev = new PreviewRendererThread(0, PreviewGraphWidget, _controller, background: true);
            previewRenderers.Add(prev);
            prev.Begin();
            for (var i = 1; i < count; i++)
            {
                prev = new PreviewRendererThread(i, PreviewGraphWidget, _controller, background: false);
                previewRenderers.Add(prev);
                prev.Begin();
                progress.Report(0.2f + (i / (float)count));
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
            Stopwatch sw = new Stopwatch();
            if (MainGraphWidget != null && PreviewGraphWidget != null)
            {
                ManageActiveGraph();


                sw.Start();
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);
                if (ImGui.BeginTable("MainVisPanelsTable", 2))
                {
                    ImGui.TableSetupColumn("MainVisTCol");
                    ImGui.TableSetupColumn("PrevVisTCol", ImGuiTableColumnFlags.WidthFixed, CONSTANTS.UI.PREVIEW_PANE_WIDTH);
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    ImGui.PopStyleVar();
                    DrawMainVisualiser(200);
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);

                    sw.Stop();
                    if (sw.ElapsedMilliseconds > 40)
                        Console.WriteLine($"DrawVisualiserGraphs took {sw.ElapsedMilliseconds}ms");
                    sw.Restart();
                    ImGui.TableNextColumn();
                    DrawPreviewVisualiser(controlsHeight: 200);
                    ImGui.EndTable();
                }
                ImGui.PopStyleVar();

                sw.Stop();
                if (sw.ElapsedMilliseconds > 40)
                    Console.WriteLine($"DrawVisualiserControls took {sw.ElapsedMilliseconds}ms");
            }
        }

        readonly Stopwatch swdbg2 = new();
        private void DrawMainVisualiser(float controlsHeight = 200)
        {
            if (rgatState.ActiveGraph == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), ImGui.GetContentRegionAvail()))// controlsHeight - vpadding)))
                {
                    if (rgatState.ActiveTrace is null)
                    {
                        ImGuiUtils.DrawRegionCenteredText("No traces recorded for this target yet");
                    }
                    else
                    {
                        ImGuiUtils.DrawRegionCenteredText("Waiting for instrumented trace data");
                    }
                    ImGui.EndChild();
                }
                return;
            }

            float mainHeight = ImGui.GetContentRegionAvail().Y;
            TraceRecord? trace = rgatState.ActiveTrace;
            bool drawVisualiserBar = trace is not null && trace.TraceState is TraceRecord.ProcessState.eTerminated && trace.DiscardTraceData;
            if (drawVisualiserBar)
                controlsHeight -= 50;
            Vector2 graphSize = new Vector2(ImGui.GetContentRegionAvail().X, mainHeight - (controlsHeight ));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            if (ImGui.BeginChild(ImGui.GetID("MainGraphWidget"), graphSize))
            {
                ImGui.PopStyleVar();
                swdbg2.Restart();
                MainGraphWidget.Draw(graphSize, rgatState.ActiveGraph);
                swdbg2.Stop();
                ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
                if (swdbg2.ElapsedMilliseconds > 52)
                    Console.WriteLine($"MainGraphWidget.Draw took {swdbg2.ElapsedMilliseconds}ms");

                Vector2 msgpos = ImGui.GetCursorScreenPos() + new Vector2(graphSize.X, -1 * graphSize.Y);
                swdbg2.Restart();
                MainGraphWidget.DisplayEventMessages(msgpos);
                swdbg2.Stop();
                if (swdbg2.ElapsedMilliseconds > 42)
                    Console.WriteLine($"MainGraphWidget.DisplayEventMessages took {swdbg2.ElapsedMilliseconds}ms");
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();

            PlottedGraph activeGraph = rgatState.ActiveGraph;
            if (activeGraph != null)
            {
                if (ImGui.BeginChild("ControlsInner", new Vector2(graphSize.X, controlsHeight)))
                {
                    if (activeGraph.InternalProtoGraph.TraceData.TraceState is not TraceRecord.ProcessState.eTerminated)
                    {
                        DrawLiveTraceControls(controlsHeight - 5, ImGui.GetContentRegionAvail().X, activeGraph);
                    }
                    else
                    {
                        /*
                        if (rgatState.ActiveTrace?.TraceState == TraceRecord.ProcessState.eTerminated && rgatState.ActiveTrace.DiscardTraceData)
                        {
                            frameHeight -= 50;
                            //ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 50);
                        }
                        */
                        DrawPlaybackControls(controlsHeight - 5, ImGui.GetContentRegionAvail().X);
                    }
                    ImGui.EndChild();
                }
                else
                {
                    Console.WriteLine("Fail3");
                }
            }
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

        public bool AlertKeybindPressed(KeybindAction action, Tuple<Key, ModifierKeys>? KeyModifierTuple)
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

        private static void DrawCameraPopup()
        {
            PlottedGraph? ActiveGraph = rgatState.ActiveGraph;
            if (ActiveGraph == null)
            {
                return;
            }

            if (ImGui.BeginChild(ImGui.GetID("CameraControlsb"), new Vector2(235, 200)))
            {
                ImGui.DragFloat("Field Of View", ref ActiveGraph.CameraFieldOfView, 0.005f, 0.05f, (float)Math.PI, "%f");
                ImGui.DragFloat("Near Clipping", ref ActiveGraph.CameraClippingNear, 50.0f, 0.1f, 200000f, "%f");
                ImGui.DragFloat("Far Clipping", ref ActiveGraph.CameraClippingFar, 50.0f, 0.1f, 200000f, "%f");
                ImGui.DragFloat("X Shift", ref ActiveGraph.CameraState.MainCameraXOffset, 1f, -400, 40000, "%f");
                ImGui.DragFloat("Y Position", ref ActiveGraph.CameraState.MainCameraYOffset, 1, -400, 200000, "%f");

                ImGui.DragFloat("Zoom", ref ActiveGraph.CameraState.MainCameraZoom, 5, 100, 100000, "%f");
                //ImGui.DragFloat("Rotation", ref ActiveGraph.PlotZRotation, 0.01f, -10, 10, "%f");
                ImGui.EndChild();
            }
        }


        private unsafe void DrawPlaybackControls(float otherControlsHeight, float width)
        {
            PlottedGraph? activeGraph = rgatState.ActiveGraph;
            if (activeGraph == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(width, otherControlsHeight)))
                {
                    ImGui.Text("No active graph");

                    ImGui.EndChild();
                }
                return;
            }


            if (ImGui.BeginChild(ImGui.GetID("ReplayControlPanel"), new Vector2(width, otherControlsHeight)))
            {
                if (activeGraph.InternalProtoGraph.TraceData.DiscardTraceData is false)
                {
                    _visualiserBar!.DrawReplaySlider(width: width - 10, height: 50, graph: activeGraph);
                }
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);

                ImGui.BeginGroup();
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                    //ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBg));
                    if (ImGui.BeginChild("ReplayControls", new Vector2(660, ImGui.GetContentRegionAvail().Y - 2)))
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
                    //ImGui.PopStyleColor();
                    ImGui.EndGroup();
                }
                ImGui.SameLine();
                //ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 8);
                DrawDiasmPreviewBox(activeGraph.InternalProtoGraph, (int)Math.Floor(activeGraph.AnimationIndex));

                ImGui.EndChild();
            }

        }

        private static void DrawReplayControlsPanel(PlottedGraph plot)
        {
            string indexPos = "";
            if (plot.AnimationIndex > 0)
            {
                indexPos = $" ({plot.AnimationIndex}/{plot.InternalProtoGraph.StoredUpdateCount})";
            }

            if (ImGui.BeginChild("ReplayControlsFrame1", new Vector2(220, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(5, 15));
                switch (plot.ReplayState)
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
                        ImGui.Text("Trace Replay: Stopped");
                        break;
                }
                ImGui.PopStyleVar();

                ImGui.BeginGroup();
                {
                    PlottedGraph.REPLAY_STATE replaystate = plot.ReplayState;
                    string BtnText = replaystate == PlottedGraph.REPLAY_STATE.Playing ? $"{ImGuiController.FA_ICON_MEDIAPAUSE} Pause" : $"{ImGuiController.FA_ICON_MEDIAPLAY} Play";


                    if (SmallWidgets.DisableableButton(BtnText, plot.InternalProtoGraph.TraceData.DiscardTraceData is false, new Vector2(58, 26)))
                    {
                        plot.PlayPauseClicked();
                    }
                    ImGui.SameLine();
                    if (SmallWidgets.DisableableButton($"{ImGuiController.FA_ICON_MEDIASTOP} Reset", plot.InternalProtoGraph.TraceData.DiscardTraceData is false, new Vector2(58, 26)))
                    {
                        plot.ResetClicked();
                    }
                    ImGui.SameLine();
                    if (replaystate == PlottedGraph.REPLAY_STATE.Paused && ImGui.Button($"{ImGuiController.FA_ICON_STEP} Step", new Vector2(58, 26)))
                    {
                        ImGui.SameLine();
                        plot.StepPausedAnimation(1);
                    }
                    ImGui.EndGroup();
                }
                ImGui.SetNextItemWidth(120f);

                float speedVal = plot.AnimationRate;
                if (ImGui.DragFloat("##SpeedSlider", ref speedVal, 0.25f, 0, 100, format: "Replay Speed: %.2f", flags: ImGuiSliderFlags.Logarithmic))
                {
                    plot.AnimationRate = speedVal;
                }
                SmallWidgets.MouseoverText("The number of trace updates to replay per frame.\nDrag or Double click to set a custom rate.");
                ImGui.SameLine();

                ImGui.SetNextItemWidth(65f);
                if (ImGui.BeginCombo("##Replay Speed", $" {plot.AnimationRate:F2}", ImGuiComboFlags.HeightLargest))
                {
                    if (ImGui.Selectable("x1/10"))
                    {
                        plot.AnimationRate = 0.1f;
                    }

                    if (ImGui.Selectable("x1/4"))
                    {
                        plot.AnimationRate = 0.25f;
                    }

                    if (ImGui.Selectable("x1/2"))
                    {
                        plot.AnimationRate = 0.5f;
                    }

                    if (ImGui.Selectable("x1"))
                    {
                        plot.AnimationRate = 1;
                    }

                    if (ImGui.Selectable("x2"))
                    {
                        plot.AnimationRate = 2;
                    }

                    if (ImGui.Selectable("x5"))
                    {
                        plot.AnimationRate = 5;
                    }

                    if (ImGui.Selectable("x10"))
                    {
                        plot.AnimationRate = 10;
                    }

                    if (ImGui.Selectable("x25"))
                    {
                        plot.AnimationRate = 25;
                    }

                    if (ImGui.Selectable("x50"))
                    {
                        plot.AnimationRate = 50;
                    }

                    if (ImGui.Selectable("x100"))
                    {
                        plot.AnimationRate = 100;
                    }

                    ImGui.EndCombo();
                }
                SmallWidgets.MouseoverText("The number of trace updates to replay per frame");

                ImGui.EndChild();
            }
        }


        private static void DrawActiveTraceControlPanel(PlottedGraph plot)
        {
            if (ImGui.BeginChild("LiveTraceCtrls", new Vector2(160, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                ImGui.Columns(2);
                ImGui.SetColumnWidth(0, 65);
                ImGui.SetColumnWidth(1, 90);

                ImGui.BeginGroup();
                {
                    if (ImGui.Button("Kill", new Vector2(50, 24)))
                    {
                        plot.InternalProtoGraph.TraceData.SendDebugCommand(0, "EXIT");
                        // Sometimes the pintool doesn't respond
                        // This terminates our end of the connection after a reasonable wait
                        System.Threading.Tasks.Task.Run(async () =>
                        {
                            await System.Threading.Tasks.Task.Delay(800);
                            if (plot.InternalProtoGraph.TraceData.TraceState is not TraceRecord.ProcessState.eTerminated)
                                plot.InternalProtoGraph.TraceReader?.Terminate();
                        }
                        );
                    }
                    SmallWidgets.MouseoverText("Terminate the process running the current thread");

                    if (ImGui.Button("Kill All", new Vector2(50, 24)))
                    {
                        foreach (var child in plot.InternalProtoGraph.TraceData.Children)
                            child.SendDebugCommand(0, "EXIT");
                        plot.InternalProtoGraph.TraceData.SendDebugCommand(0, "EXIT");
                    }

                    ImGui.EndGroup();
                }

                ImGui.NextColumn();

                ImGui.BeginGroup();
                {
                    if (plot.InternalProtoGraph.TraceData.TraceState == TraceRecord.ProcessState.eRunning)
                    {
                        if (ImGui.Button("Pause/Break", new Vector2(80, 24)))
                        {
                            plot.InternalProtoGraph.TraceData.SendDebugCommand(0, "BRK");
                        }
                        SmallWidgets.MouseoverText("Pause all process threads");
                    }

                    if (plot.InternalProtoGraph.TraceData.TraceState == TraceRecord.ProcessState.eSuspended)
                    {
                        if (ImGui.Button("Continue", new Vector2(65, 24)))
                        {
                            plot.InternalProtoGraph.TraceData.SendDebugCommand(0, "CTU");
                        }
                        SmallWidgets.MouseoverText("Resume all process threads");

                        if (ImGui.Button("Step In", new Vector2(65, 24)))
                        {
                            plot.InternalProtoGraph.TraceData.SendDebugStep(plot.InternalProtoGraph);
                        }
                        SmallWidgets.MouseoverText("Step to next instruction");

                        if (ImGui.Button("Step Over", new Vector2(65, 24)))
                        {
                            plot.InternalProtoGraph.TraceData.SendDebugStepOver(plot.InternalProtoGraph);
                        }
                        SmallWidgets.MouseoverText("Step past call instruction");

                    }
                    ImGui.EndGroup();
                }
                ImGui.Columns(1);
                ImGui.EndChild();
            }
        }


        private static void DrawRenderControlPanel(PlottedGraph plot)
        {
            if (ImGui.BeginChild("GraphRenderControlsFrame1", new Vector2(150, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                if (SmallWidgets.ToggleButton("AnimatedToggle", plot.IsAnimated, "In animated mode the graph is dark with active regions lit up"))
                {
                    plot.SetAnimated(!plot.IsAnimated);
                }
                ImGui.SameLine();
                ImGui.Text(plot.IsAnimated ? "Animated" : "Full Brightness");

                if (SmallWidgets.ToggleButton("LayoutComputeEnabled", GlobalConfig.LayoutPositionsActive, "Toggle GPU graph layout compuation"))
                {
                    GlobalConfig.LayoutPositionsActive = !GlobalConfig.LayoutPositionsActive;
                }
                ImGui.SameLine();
                ImGui.Text(GlobalConfig.LayoutPositionsActive ? "Layout Enabled" : "Layout Disabled");
                ImGui.EndChild();
            }
        }


        private static void DrawVideoControlPanel(PlottedGraph plot)
        {
            if (ImGui.BeginChild("VideoControlsFrame1", new Vector2(115, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                if (rgatState.VideoRecorder.Recording)
                {
                    if (rgatState.VideoRecorder.CapturePaused)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                        if (ImGui.Button("Resume Capture", new Vector2(100, 28))) //this is more intended as an indicator than a control
                        {
                            rgatState.VideoRecorder.CapturePaused = false;
                        }
                        ImGui.PopStyleColor();
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.AlertWindowBg));
                        if (ImGui.Button("Stop Capture", new Vector2(100, 28)))
                        {
                            rgatState.VideoRecorder.StopRecording();
                        }
                        ImGui.PopStyleColor();
                    }
                }
                else
                {
                    if (ImGui.Button($"{ImGuiController.FA_BLANK_CIRCLE} Record", new Vector2(100, 28)))
                    {
                        rgatState.VideoRecorder.StartRecording();
                    }
                    SmallWidgets.MouseoverText("Record to video, if FFMpeg is configured");
                }

                SmallWidgets.DisableableButton("Add Caption", false, new Vector2(100, 25));
                SmallWidgets.MouseoverText("Not available in this version of rgat");

                ImGui.Text($"Ctrl: {ImGui.GetIO().KeyCtrl}");
                ImGui.Text($"Shft: {ImGui.GetIO().KeyShift}");

                //ImGui.Button("Capture Settings");
                ImGui.EndChild();
            }
        }




        private void DrawCameraPanel(PlottedGraph plot)
        {
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(18, 4));
            if (ImGui.BeginChild("CameraStatFrame1", new Vector2(150, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                float itemWidth = 60;
                ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourUINT(Themes.eThemeColour.Frame, 45));
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(4,3));
                if (ImGui.BeginTable("#CameraStateTable", 3))
                {
                    ImGui.TableSetupColumn("MovIcon", ImGuiTableColumnFlags.WidthFixed, 20);
                    ImGui.TableSetupColumn("MovFieldLabel", ImGuiTableColumnFlags.WidthFixed, 15);
                    ImGui.TableSetupColumn("MovValue", ImGuiTableColumnFlags.WidthFixed, 100);

                    float furthestNode = Math.Abs(plot.FurthestNodeDimension);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"X");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(itemWidth);
                    float xoff = plot.CameraState.MainCameraXOffset;
                    if (ImGui.DragFloat("##Xm", ref xoff, 150, -3 * furthestNode, 3 * furthestNode, "%.f"))
                        plot.CameraState.MainCameraXOffset = xoff;

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{ImGuiController.FA_ICON_MOVEMENT}");
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"Y");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(itemWidth);
                    float yoff = plot.CameraState.MainCameraYOffset;
                    if (ImGui.DragFloat("##Ym", ref yoff, 150, -3 * furthestNode, 3 * furthestNode, "%.f"))
                        plot.CameraState.MainCameraYOffset = yoff;

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"Z");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(itemWidth);
                    float mainzoom = plot.CameraState.MainCameraZoom;
                    if (ImGui.DragFloat("##Zm", ref mainzoom, 500, -9999999999, furthestNode, "%.f"))
                        plot.CameraState.MainCameraZoom = mainzoom;
                    SmallWidgets.MouseoverText("Camera Zoom. Can be controlled by the mouse wheel (with ctrl, shift and ctrl+shift modifiers");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{ImGuiController.FA_ICON_ROTATION}");
                    ImGui.TableNextColumn();
                    ImGui.TableNextColumn();
                    if (ImGui.Button("Reset", new Vector2(itemWidth, 25)))
                    {
                        plot.CameraState.RotationMatrix = Matrix4x4.Identity;
                    }
                    SmallWidgets.MouseoverText("Reset the rotation of the graph");

                    ImGui.EndTable();
                }
                ImGui.PopStyleColor();
                ImGui.PopStyleVar();

                /*
                if (ImGui.BeginTable("#CameraRotationStateTable", 3))
                {
                    ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 20);
                    ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 6);
                    ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 110);
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{ImGuiController.FA_ICON_ROTATION}");
                    ImGui.TableNextColumn();
                    ImGui.TableNextColumn();
                    if (ImGui.Button("Reset", new Vector2(60, 25)))
                    {
                        graph.CameraState.RotationMatrix = Matrix4x4.Identity;
                    }
                    SmallWidgets.MouseoverText("Reset the rotation of the graph");
                    ImGui.EndTable();
                }
                */
                if (plot.CenteringInFrame is not PlottedGraph.CenteringMode.Inactive)
                {
                    if (plot.CenteringInFrame is PlottedGraph.CenteringMode.Centering)
                        ImGui.Text("Centering...");
                    else if (plot.CenteringInFrame is PlottedGraph.CenteringMode.ContinuousCentering)
                    {
                        ImGui.Text("Centering [locked]");
                        SmallWidgets.MouseoverText("The graph is in lock-centering mode. Use the keybind to deactivate it.");
                    }
                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
        }



        private static void DrawDiasmPreviewBox(ProtoGraph graph, int lastAnimIdx)
        {

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x30000000);
            if (ImGui.BeginChild("##DisasmPreview", ImGui.GetContentRegionAvail()))
            {

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2);
                ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(10, 0));

                List<ANIMATIONENTRY> animData = graph.GetSavedAnimationDataReference();
                try
                {
                    if (lastAnimIdx >= 0 && lastAnimIdx < animData.Count)
                    {

                        ANIMATIONENTRY lastEntry = animData[lastAnimIdx];

                        ImGui.Text($"Trace Tag: {lastEntry.entryType} Location: 0x{lastEntry.Address} (Block {lastEntry.BlockID})");
                        switch (lastEntry.entryType)
                        {
                            case eTraceUpdateType.eAnimExecTag:
                                {
                                    uint blkID = lastEntry.BlockID;
                                    if (blkID < uint.MaxValue)
                                    {

                                        bool resolved = graph.ProcessData.ResolveSymbolAtAddress(lastEntry.Address, out int moduleID2, out string modulenm, out string symbol);
                                        string moduleLabel = ((modulenm.Length > 0) ? modulenm : "Unknown module");
                                        ImGui.TextWrapped($"{moduleLabel}");

                                        ImGui.Indent(8);
                                        ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                                        List<InstructionData>? inslist = graph.ProcessData.getDisassemblyBlock(blockID: blkID);
                                        if (inslist is not null)
                                        {
                                            const int max = 50;
                                            for (var i = Math.Max(0, inslist.Count - max); i < inslist.Count; i++)
                                            {
                                                ImGui.Text(inslist[i].InsText);
                                            }
                                            if (inslist.Count > max)
                                                ImGui.Text($"+{inslist.Count - max} more");
                                        }
                                        ImGui.PopStyleColor();
                                        ImGui.Indent(-8);
                                    }
                                    else
                                    {
                                        if (graph.ProcessData.ResolveSymbolAtAddress(lastEntry.Address, out int moduleID2, out string modulenm, out string symbol))
                                        {
                                            ImGui.Text($"Location: {modulenm}::{symbol}");
                                        }
                                        else
                                        {
                                            ImGui.Text($"Location: {modulenm}::0x{lastEntry.Address:X}");
                                        }
                                    }
                                }
                                break;
                            case eTraceUpdateType.eAnimUnchained:
                                {
                                    int ucBlkCount = 0;
                                    for (var i = lastAnimIdx; i > 0; i--)
                                    {
                                        if (animData[i].entryType != eTraceUpdateType.eAnimUnchained)
                                        {
                                            break;
                                        }

                                        ucBlkCount++;
                                    }
                                    ImGui.Text($"Busy area of {ucBlkCount} blocks");
                                }
                                break;
                            case eTraceUpdateType.eAnimUnchainedResults:
                                if (lastEntry.edgeCounts is not null)
                                {
                                    if (lastEntry.edgeCounts.Count == 1)
                                    {
                                        ImGui.Text($"Block executed in a region of {lastEntry.Count} times");
                                    }
                                    else
                                    {
                                        ImGui.Text($"{lastEntry.Count} block executions in a region of {lastEntry.edgeCounts.Count} blocks");
                                    }
                                }
                                break;

                        }
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Disassembly box exception: {e.Message}");
                }
                finally
                {
                    graph.ReleaseSavedAnimationDataReference();
                }
                ImGui.PopStyleVar(3);
                ImGui.EndChild();
            }
            else
            {
                ImGui.InvisibleButton("#badDismbox", new Vector2(1, 1));
            }

            ImGui.PopStyleColor();
        }


        private unsafe void DrawLiveTraceControls(float otherControlsHeight, float width, PlottedGraph plot)
        {
            float replayControlsSize = ImGui.GetContentRegionAvail().X;
            if (ImGui.BeginChild(ImGui.GetID("LiveTraceControlPanel"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                _visualiserBar!.Draw(width, 50);
                //ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));
                ImGui.Indent(6);
                if (ImGui.BeginChild("LiveControlsPane", new Vector2(ImGui.GetContentRegionAvail().X, ImGui.GetContentRegionAvail().Y - 2)))
                {
                    ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX(), ImGui.GetCursorPosY() + 6));
                    DrawActiveTraceControlPanel(plot);
                    ImGui.SameLine();
                    DrawRenderControlPanel(plot);
                    ImGui.SameLine();
                    DrawVideoControlPanel(plot);
                    ImGui.SameLine();
                    DrawCameraPanel(plot);
                    ImGui.SameLine();
                    DrawDiasmPreviewBox(plot.InternalProtoGraph, plot.InternalProtoGraph.StoredUpdateCount - 1);
                    ImGui.EndChild();
                }
                else
                {
                    Console.WriteLine("Fail4");
                }
                ImGui.EndChild();
            }

        }

        private void SetActiveGraph(PlottedGraph plot)
        {
            if (rgatState.ActiveGraph is not null && plot.PID != rgatState.ActiveGraph.PID)
            {
                Logging.WriteConsole("Warning: Graph selected in inactive trace");
                return;
            }

            rgatState.SwitchToGraph(plot);
            PreviewGraphWidget!.SetSelectedGraph(plot);
            //MainGraphWidget.SetActiveGraph(graph);
        }


        private void DrawPlotStatColumns(PlottedGraph plot)
        {
            ProtoGraph graph = plot.InternalProtoGraph;

            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 12);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 3);

            ImGui.Text($"Thread ID: {graph.ThreadID}");

            ImGui.SameLine();
            if (graph.TraceData.TraceState == TraceRecord.ProcessState.eTerminated)
            {
                if (graph.TraceData.TraceState is TraceRecord.ProcessState.eTerminated && graph.TraceReader?.QueueSize > 0)
                {
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Yellow), $"(Processing Backlog)");
                    ImGui.SameLine();
                    ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 3);
                    if (ImGui.Button($"{ImGuiController.FA_ICON_TRASHCAN}", new Vector2(22, 22)))
                    {
                        graph.TraceProcessor?.Terminate();
                        graph.TraceReader?.Terminate();
                    }
                    SmallWidgets.MouseoverText("Discard the trace backlog");
                    ImGui.PopStyleVar();
                }
                else
                {
                    ImGui.TextColored(Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour).ToVec4(), "(Terminated)");
                }
            }
            else
            {
                ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.LimeGreen), $"(Active)");
            }

            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 3);
            ImGui.Indent(30);
            if (ImGui.BeginTable("VisStatsColumns", 2))
            {
                ImGui.TableSetupColumn("#GraphInfoCol", ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("#StatsInfoCol");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();

                //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff110022);

                int mouseNode = MainGraphWidget.MouseoverNodeID;


                float metricsHeight = ImGui.GetContentRegionAvail().Y - 8;
                if (ImGui.BeginChild("ActiveTraceMetrics", new Vector2(130, metricsHeight)))
                {
                    ImGui.Text($"Edges: {graph.EdgeCount}");
                    SmallWidgets.MouseoverText($"Instruction to Instruction transitions");
                    ImGui.Text($"Nodes: {graph.NodeList.Count}");
                    SmallWidgets.MouseoverText($"Unique instructions");
                    ImGui.Text($"Updates: {graph.UpdateCount}");
                    SmallWidgets.MouseoverText($"How many items of trace data have been generated by this thread");
                    ImGui.Text($"Instructions: {graph.TotalInstructions}");
                    SmallWidgets.MouseoverText($"How many times instrumented instructions have been executed in this thread");
                    ImGui.Text($"Exceptions: {graph.ExceptionCount}");
                    SmallWidgets.MouseoverText($"Number of exceptions recorded in this thread");
                    ImGui.EndChild();
                }

                ImGui.TableNextColumn();

                if (_stats_click_hover)
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff313142);
                }

                if (ImGui.BeginChild("OtherMetrics", new Vector2(ImGui.GetContentRegionAvail().X, metricsHeight)))
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(2, 5));
                    if (graph.TraceReader != null)
                    {
                        ImGui.Text($"Queue: {graph.TraceReader.QueueSize}");
                        SmallWidgets.MouseoverText("How many items of trace data are awaiting processing");

                        graph.TraceReader.RecentMessageRates(out float[] incoming);
                        if (incoming.Length > 0)
                        {
                            float incomingAvg = incoming.TakeLast(5).Average();
                            ImGui.Text("Queue + ");
                            SmallWidgets.MouseoverText("Average number of trace data items ingested recently for this thread");
                            ImGui.SameLine();
                            ImGui.TextColored(Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour).ToVec4(), $"{incomingAvg:f1}");
                        }

                        graph.TraceReader.RecentProcessingRates(out float[] outgoing);
                        if (outgoing.Length > 0)
                        {
                            float outgoingAvg = outgoing.TakeLast(5).Average();
                            ImGui.Text("Queue - ");
                            SmallWidgets.MouseoverText("Average number of trace data items processed recently for this thread");
                            ImGui.SameLine();
                            ImGui.TextColored(Themes.GetThemeColourWRF(Themes.eThemeColour.GoodStateColour).ToVec4(), $"{outgoingAvg:f1}");
                        }
                    }

                    ThreadTraceProcessingThread? traceProcessor = graph.TraceProcessor;
                    if (traceProcessor != null)
                    {
                        string BrQlab = $"{traceProcessor.PendingBlockRepeats}";
                        if (traceProcessor.PendingBlockRepeats > 0)
                        {
                            BrQlab += $" ({traceProcessor.LastBlockRepeatsTime:f1}ms)";
                        }
                        ImGui.Text($"RepQu: {BrQlab}");
                        SmallWidgets.MouseoverText("Size of the block repeat processing queue");
                    }

                    if (plot.ComputeLayoutSteps > 0)
                    {
                        ImGui.Text($"Layout: {(plot.ComputeLayoutTime / plot.ComputeLayoutSteps):0.#}ms");
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.BeginTooltip();
                            ImGui.Text("How long it takes to complete a step of graph layout");
                            ImGui.Text($"Cumulative Time: {plot.ComputeLayoutTime:f1}ms - ({plot.ComputeLayoutSteps} steps)");
                            ImGui.EndTooltip();
                        }
                    }


                    ImGui.EndChild();
                    if (ImGui.IsItemClicked())
                    {
                        rgatUI.ToggleRenderStatsDialog();
                    }
                    /*
                    //Doesn't work - software cursor rendering not set?
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);
                    }
                    */
                    ImGui.PopStyleVar(); //item spacing
                }
                if (_stats_click_hover)
                {
                    ImGui.PopStyleColor();
                }

                _stats_click_hover = ImGui.IsItemHovered();
                //ImGui.PopStyleColor();
                ImGui.EndTable();
            }
        }


        private void DrawMousePanel(PlottedGraph plot, int mouseNode)
        {
            if (mouseNode is -1) return;


            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
            ImGui.Text($"Mouseover Node: {mouseNode}");
            ImGui.Indent(12);

            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(8, 4));
            if (ImGui.BeginChild("MouseInfoFrame", new Vector2(ImGui.GetContentRegionAvail().X - 5, ImGui.GetContentRegionAvail().Y - 2), true))
            {
                if (ImGui.BeginTable("#MouseInfoFrameTable", 2))
                {
                    ImGui.TableSetupColumn("MouseItem", ImGuiTableColumnFlags.WidthFixed, 45);
                    ImGui.TableSetupColumn("MouseValue");

                    NodeData? n = plot.InternalProtoGraph.GetNode((uint)mouseNode);
                    if (n is not null)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("Address");
                        ImGui.TableNextColumn();
                        ImGui.Text($"0x{n.Address:X}");

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("Sources");
                        ImGui.TableNextColumn();
                        ImGui.TextWrapped(GetNeighbourString(plot.InternalProtoGraph, n, incoming: true));

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("Targets");
                        ImGui.TableNextColumn();
                        ImGui.TextWrapped(GetNeighbourString(plot.InternalProtoGraph, n, incoming: false));
                    }
                    ImGui.EndTable();
                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
        }

        private string GetNeighbourString(ProtoGraph graph, NodeData n, bool incoming = true)
        {
            List<uint> neighbourSet = incoming ? n.IncomingNeighboursSet : n.OutgoingNeighboursSet;
            const int maxNeighbours = 2;
            List<NodeData> srcNodes = new();
            for (var i = 0; i < Math.Min(maxNeighbours, neighbourSet.Count); i++)
            {
                NodeData? neighbour = graph.GetNode(neighbourSet[i]);
                if (neighbour is not null)
                {
                    srcNodes.Add(neighbour);
                }
            }
            string srcString = $"x{neighbourSet.Count}: ";
            for (var i = 0; i < srcNodes.Count; i++) // srcNodes.Count; i++)
            {
                NodeData neighbour = srcNodes[i];
                srcString += $"{neighbour.Index} [0x{neighbour.Address:X}]";
                if (i < srcNodes.Count - 1) srcString += ", ";
            }
            if (srcNodes.Count < neighbourSet.Count)
                srcString += $" +{neighbourSet.Count - srcNodes.Count} more";
            return srcString;
        }


        private bool _stats_click_hover = false;

        private unsafe void DrawPreviewVisualiser(float controlsHeight = 200)
        {
            Vector2 previewPaneSize = new Vector2(UI.PREVIEW_PANE_WIDTH, ImGui.GetContentRegionAvail().Y - controlsHeight);
            ImGui.PushStyleColor(ImGuiCol.Border, Themes.GetThemeColourUINT(Themes.eThemeColour.PreviewPaneBorder));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.PreviewPaneBackground));

            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(0, 0));
            if (ImGui.BeginChild(ImGui.GetID("GLVisThreads"), previewPaneSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                swdbg2.Restart();
                PreviewGraphWidget!.DrawWidget();
                if (PreviewGraphWidget.clickedGraph != null)
                {
                    SetActiveGraph(PreviewGraphWidget.clickedGraph);
                    PreviewGraphWidget.ResetClickedGraph();
                }
                swdbg2.Stop();
                if (swdbg2.ElapsedMilliseconds > 62)
                    Console.WriteLine($"PreviewGraphWidget.DrawWidget took {swdbg2.ElapsedMilliseconds}ms");
                ImGui.EndChild();
            }
            ImGui.PopStyleVar(4);
            ImGui.PopStyleColor(2);

            float controlsWidth = ImGui.GetContentRegionAvail().X;

            if (ImGui.BeginChild(ImGui.GetID("ControlsPrev"), new Vector2(controlsWidth, controlsHeight)))
            {
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 1);

                PlottedGraph? activeGraph = rgatState.ActiveGraph;
                TraceSelector.Draw(activeGraph?.InternalProtoGraph.TraceData);

                if (activeGraph is not null)
                {
                    int mouseNode = MainGraphWidget.MouseoverNodeID;
                    if (mouseNode is -1 || ImGui.GetIO().KeyShift || ImGui.GetIO().KeyCtrl)
                    {
                        DrawPlotStatColumns(activeGraph);
                    }
                    else
                    {
                        DrawMousePanel(activeGraph, mouseNode);
                    }
                }

            }
            ImGui.EndChild();
            if (rgatUI.ShowStatsDialog)
            {
                bool closeClick = true;
                DrawGraphStatsDialog(ref closeClick);
                if (closeClick is false) rgatUI.ToggleRenderStatsDialog();
            }

        }



        private void ManageActiveGraph()
        {
            if (rgatState.ActiveGraph == null)
            {
                if (rgatState.ActiveTrace == null)
                {
                    rgatState.SelectActiveTrace();
                }

                if (PreviewGraphWidget is null)
                {
                    return;
                }

                if (rgatState.ChooseActiveGraph())
                {
                    if (rgatState.RecordVideoOnNextTrace)
                    {
                        rgatState.VideoRecorder.StartRecording();
                        rgatState.RecordVideoOnNextTrace = false;
                    }
                    PreviewGraphWidget.SetActiveTrace(rgatState.ActiveTrace);
                    PreviewGraphWidget.SetSelectedGraph(rgatState.ActiveGraph);
                }
                else
                {
                    if (MainGraphWidget.ActiveGraph != null)
                    {
                        PreviewGraphWidget.SetActiveTrace(null);
                    }
                }
            }
            else if (rgatState.ActiveGraph != MainGraphWidget.ActiveGraph)
            {

                if (rgatState.RecordVideoOnNextTrace)
                {
                    rgatState.VideoRecorder.StartRecording();
                    rgatState.RecordVideoOnNextTrace = false;
                }

                PreviewGraphWidget!.SetActiveTrace(rgatState.ActiveTrace);
                PreviewGraphWidget!.SetSelectedGraph(rgatState.ActiveGraph);
            }
        }



        public void DrawGraphStatsDialog(ref bool hideme)
        {
            if (rgatState.ActiveGraph == null)
            {
                return;
            }

            PlottedGraph graphplot = rgatState.ActiveGraph;
            ProtoGraph graph = graphplot.InternalProtoGraph;

            ImGui.SetNextWindowSize(new Vector2(800, 500), ImGuiCond.Appearing);

            if (ImGui.Begin("Performance Statistics", ref hideme))
            {

                if (ImGui.BeginTable("#StatsTable", 3, ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg))
                {
                    ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 120);
                    ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthFixed, 235);
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
                    ImGui.Text($"Disassembly Backlog");
                    ImGui.TableNextColumn();

                    if (graph.TraceData.ProcessThreads.BBthread is not null && graph.TraceData.ProcessThreads.BBthread.QueueSize > 0)
                    {
                        ImGui.Text($"{graph.TraceData.ProcessThreads.BBthread.QueueSize}");
                    }
                    else
                    {
                        ImGui.Text("0");
                    }
                    ImGui.TableNextColumn();
                    ImGui.Text("Blocks waiting for disassembly");

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
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText);
                        }
                        else if (fps < 40 && fps >= 10)
                        {
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.WarnStateColour);
                        }
                        else
                        {
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour);
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
                    ImGui.Text($"{graphplot.ComputeLayoutTime:0.#} MS over {graphplot.ComputeLayoutSteps} steps (Avg: {graphplot.ComputeLayoutTime / graphplot.ComputeLayoutSteps:0.#})");
                    ImGui.TableNextColumn();
                    ImGui.Text("Total compute engine time used to generate this layout");

                    double accountedComputeTime = 0.1 + graphplot.VelocitySetupTime + graphplot.VelocityShaderTime +
                        graphplot.PositionSetupTime + graphplot.PositionShaderTime +
                        graphplot.AttributeSetupTime + graphplot.AttributeShaderTime;

                    WritableRgbaFloat baseColour = new WritableRgbaFloat(0x8d, 0x00, 0x00, 0xff);

                    if (graphplot.VelocitySteps is not 0)
                    {

                        double velpc = (graphplot.VelocitySetupTime + graphplot.VelocityShaderTime) / accountedComputeTime;
                        double velpc_all = (graphplot.VelocitySetupTime + graphplot.VelocityShaderTime) / graphplot.ComputeLayoutTime;
                        uint bgColour = baseColour.ToUint((uint)(velpc_all * 255.0));


                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Time %%");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{velpc * 100.0:0.#}%% ({velpc_all * 100.0:0.#}%% of total)");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent measuring forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.VelocitySetupTime:0.#} MS over {graphplot.VelocitySteps} steps (Avg: {graphplot.VelocitySetupTime / graphplot.VelocitySteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to measure forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Work Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.VelocityShaderTime:0.#} MS over {graphplot.VelocitySteps} steps (Avg: {graphplot.VelocityShaderTime / graphplot.VelocitySteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent measuring forces");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Velocity Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.VelocityNodes / graphplot.VelocityShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the velocity shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);
                    }

                    if (graphplot.PositionSteps is not 0)
                    {
                        double pospc = ((graphplot.PositionSetupTime + graphplot.PositionShaderTime)) / accountedComputeTime;
                        double pospc_all = ((graphplot.PositionSetupTime + graphplot.PositionShaderTime)) / graphplot.ComputeLayoutTime;
                        uint bgColour = baseColour.ToUint((uint)(pospc_all * 255.0));

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Time %%");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{pospc * 100.0:0.#}%% ({pospc_all * 100.0:0.#}%% of total)");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent moving nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.PositionSetupTime:0.#} MS over {graphplot.PositionSteps} steps (Avg: {graphplot.PositionSetupTime / graphplot.PositionSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to move nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Work Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.PositionShaderTime:0.#} MS over {graphplot.PositionSteps} steps (Avg: {graphplot.PositionShaderTime / graphplot.PositionSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent moving nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Position Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.PositionNodes / graphplot.PositionShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the position shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                    }

                    if (graphplot.AttributeSteps is not 0)
                    {
                        double attpc = ((graphplot.AttributeSetupTime + graphplot.AttributeShaderTime)) / accountedComputeTime;
                        double attpc_all = ((graphplot.AttributeSetupTime + graphplot.AttributeShaderTime)) / graphplot.ComputeLayoutTime;
                        uint bgColour = baseColour.ToUint((uint)(attpc_all * 255.0));

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Time %%");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{attpc * 100.0:0.#}%% ({attpc_all * 100.0:0.#}%% of total)");
                        ImGui.TableNextColumn();
                        ImGui.Text("Proportion of compute time spent animating nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Setup Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.AttributeSetupTime:0.#} MS over {graphplot.AttributeSteps} steps (Avg: {graphplot.AttributeSetupTime / graphplot.AttributeSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent preparing to animate nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Work Time");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{graphplot.AttributeShaderTime:0.#} MS over {graphplot.AttributeSteps} steps (Avg: {graphplot.AttributeShaderTime / graphplot.AttributeSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent animating nodes");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Attribute Throughput");
                        ImGui.TableNextColumn();
                        long nodesPerSec = (long)(graphplot.AttributeNodes / graphplot.AttributeShaderTime) * 1000;
                        ImGui.Text($"{((int)nodesPerSec).ToMetric()} Nodes/Second");
                        ImGui.TableNextColumn();
                        ImGui.Text("How fast the attribute shader is running");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);
                    }


                    if (graphplot.ComputeLayoutSteps is not 0)
                    {
                        double setupTime = graphplot.ComputeLayoutTime - accountedComputeTime;
                        double unaccpc = (setupTime / graphplot.ComputeLayoutTime);
                        uint bgColour = baseColour.ToUint((uint)(unaccpc * 255.0));

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Misc Time %%");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{(unaccpc * 100.0):0.#} %% of total");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent managing layout");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"Misc Time Total");
                        ImGui.TableNextColumn();
                        ImGui.Text($"{setupTime:0.#} MS over {graphplot.ComputeLayoutSteps} steps (Avg: {setupTime / graphplot.ComputeLayoutSteps:0.#})");
                        ImGui.TableNextColumn();
                        ImGui.Text("Time spent setting up resources");
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, bgColour);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, bgColour);

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
