using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;


using Veldrid;
using Veldrid.Sdl2;
using rgatCore.Threads;
using System.Drawing;
using rgatCore.Widgets;
using System.Linq;
using static rgatCore.Logging;

namespace rgatCore
{
    class rgatUI
    {
        //rgat ui state
        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private ImGuiController _ImGuiController = null;

        //rgat program state
        private rgatState _rgatstate = null;
        private int _selectedInstrumentationEngine = 0;

        Threads.MainGraphRenderThread mainRenderThreadObj = null;
        Threads.HeatRankingThread heatRankThreadObj = null;
        ProcessCoordinatorThread processCoordinatorThreadObj = null;

        GraphPlotWidget MainGraphWidget;
        PreviewGraphsWidget PreviewGraphWidget;
        VisualiserBar _visualiserBar;
        SettingsMenu _SettingsMenu = new SettingsMenu();

        Vector2 WindowStartPos = new Vector2(100f, 100f);
        Vector2 WindowOffset = new Vector2(0, 0);

        private readonly object _inputLock = new object();
        List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        float _mouseWheelDelta = 0;
        Vector2 _mouseDragDelta = new Vector2(0, 0);

        public rgatUI(ImGuiController imguicontroller, GraphicsDevice _gd, CommandList _cl)
        {
            Logging.RecordLogEvent("Constructing rgatUI", Logging.eLogLevel.Debug);
            _rgatstate = new rgatState(_gd, _cl);
            Logging.RecordLogEvent("State created", Logging.eLogLevel.Debug);
            GlobalConfig.InitDefaultConfig();
            Logging.RecordLogEvent("Config Inited", Logging.eLogLevel.Debug);


            _ImGuiController = imguicontroller;

            mainRenderThreadObj = new MainGraphRenderThread(_rgatstate);
            heatRankThreadObj = new HeatRankingThread(_rgatstate);
            _visualiserBar = new VisualiserBar(_gd, imguicontroller);

            processCoordinatorThreadObj = new ProcessCoordinatorThread(_rgatstate);

            MainGraphWidget = new GraphPlotWidget(imguicontroller, _gd, new Vector2(1000, 500));
            PreviewGraphWidget = new PreviewGraphsWidget(imguicontroller, _gd, _rgatstate);

            MainGraphWidget.LayoutEngine.AddParallelLayoutEngine(PreviewGraphWidget.LayoutEngine);
            PreviewGraphWidget.LayoutEngine.AddParallelLayoutEngine(MainGraphWidget.LayoutEngine);
            Logging.RecordLogEvent("rgatUI created", Logging.eLogLevel.Debug);
        }

        public void Exit()
        {
            _rgatstate.ShutdownRGAT();
        }


        public void AlertResized(Vector2 size)
        {

        }


        public void AlertKeyEvent(Tuple<Key, ModifierKeys> keyCombo)
        {
            lock (_inputLock)
            {
                _keyPresses.Add(keyCombo);
            }
        }
        public void AlertResponsiveKeyEvent(Key key)
        {
            lock (_inputLock)
            {
                //modifiers are checked later on, if needed
                _keyPresses.Add(new Tuple<Key, ModifierKeys>(key, ModifierKeys.None));
            }
        }



        public void AlertMouseWheel(MouseWheelEventArgs mw)
        {
            lock (_inputLock)
            {
                float thisDelta = mw.WheelDelta;
                if (ImGui.GetIO().KeyShift) { thisDelta *= 10; }
                _mouseWheelDelta += thisDelta;
            }
        }

        public void AlertMouseMove(MouseState ms, Vector2 delta)
        {
            if (ms.IsButtonDown(MouseButton.Left) || ms.IsButtonDown(MouseButton.Right))
            {
                lock (_inputLock)
                {
                    if (ImGui.GetIO().KeyShift) { delta = new Vector2(delta.X * 10, delta.Y * 10); }
                    _mouseDragDelta += delta;
                }

            }
        }



        public void DrawUI()
        {

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;
            //window_flags |= ImGuiWindowFlags.NoTitleBar;
            window_flags |= ImGuiWindowFlags.MenuBar;
            window_flags |= ImGuiWindowFlags.DockNodeHost;
            window_flags |= ImGuiWindowFlags.NoBringToFrontOnFocus;

            ImGui.GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
            //ImGui.GetIO().ConfigWindowsResizeFromEdges = true;

            ImGui.SetNextWindowPos(new Vector2(50, 50), ImGuiCond.Appearing);

            //ImGui.SetNextWindowSize(new Vector2(_ImGuiController._windowWidth, _ImGuiController._windowHeight), ImGuiCond.Appearing);
            ImGui.SetNextWindowSize(new Vector2(1200, 800), ImGuiCond.Appearing);

            ImGui.Begin("rgat Primary Window", window_flags);

            ApplyThemeColours();

            WindowOffset = ImGui.GetWindowPos() - WindowStartPos;
            HandleUserInput();
            DrawMainMenu();
            if (ImGui.BeginChild("MainWindow", ImGui.GetContentRegionAvail(), false, ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoScrollbar))
            {
                DrawTargetBar();
                DrawTabs();
                if (_settings_window_shown) _SettingsMenu.Draw(ref _settings_window_shown);
                if (_show_select_exe_window) DrawFileSelectBox();
                if (_show_load_trace_window) DrawTraceLoadBox();
                ImGui.EndChild();
            }

            ResetThemeColours();

            ImGui.End();

        }


        static void ApplyThemeColours()
        {
            foreach (KeyValuePair<ImGuiCol, uint> kvp in GlobalConfig.ThemeColoursStandard)
            {

                ImGui.PushStyleColor(kvp.Key, kvp.Value);
            }
        }


        static void ResetThemeColours()
        {
            GlobalConfig.ThemeColoursStandard.ToList().ForEach((f) => ImGui.PopStyleColor());
        }



        void HandleUserInput()
        {
            if (_hexTooltipShown && _mouseWheelDelta != 0)
            {
                _hexTooltipScroll -= _mouseWheelDelta * 60;
                if (_hexTooltipScroll < 0) _hexTooltipScroll = 0;
                _mouseWheelDelta = 0;
                return;
            }

            bool MouseInMainWidget = MainGraphWidget.MouseInWidget();
            lock (_inputLock)
            {

                if (MouseInMainWidget)
                {
                    if (_mouseWheelDelta != 0)
                    {
                        MainGraphWidget.ApplyZoom(_mouseWheelDelta);
                        _mouseWheelDelta = 0;
                    }

                    if (_mouseDragDelta.X != 0 || _mouseDragDelta.Y != 0)
                    {


                        if (ImGui.GetIO().KeyAlt)
                        {
                            MainGraphWidget.ApplyMouseRotate(_mouseDragDelta);
                        }
                        else
                        {
                            MainGraphWidget.ApplyMouseDrag(_mouseDragDelta);
                        }

                        _mouseDragDelta = new Vector2(0, 0);
                    }
                }


                foreach (Tuple<Key, ModifierKeys> KeyModifierTuple in _keyPresses)
                {
                    if (_SettingsMenu.HasPendingKeybind)
                    {
                        Key k = KeyModifierTuple.Item1;
                        switch (k)
                        {
                            case Key.ShiftLeft:
                            case Key.ShiftRight:
                            case Key.AltLeft:
                            case Key.AltRight:
                            case Key.ControlLeft:
                            case Key.ControlRight:
                                continue;
                            case Key.Unknown:
                                Console.WriteLine($"Unknown keybind setting: {KeyModifierTuple.Item2}_{KeyModifierTuple.Item1}");
                                break;
                            default:
                                _SettingsMenu.AssignPendingKeybind(KeyModifierTuple);
                                Console.WriteLine($"Known keybind setting: {KeyModifierTuple.Item2}_{KeyModifierTuple.Item1}");
                                continue;
                        }
                    }


                    MainGraphWidget.AlertRawKeyPress(KeyModifierTuple);
                    if (!GlobalConfig.Keybinds.TryGetValue(KeyModifierTuple, out eKeybind boundAction)) continue;

                    if (boundAction == eKeybind.Cancel)
                    {
                        CloseDialogs();
                    }

                    MainGraphWidget.AlertKeybindPressed(KeyModifierTuple, boundAction);


                }
                _keyPresses.Clear();
            }
        }

        private void CloseDialogs()
        {
            if (_SettingsMenu.HasPendingKeybind)
            {
                _SettingsMenu.HasPendingKeybind = false;
                return;
            }

            _show_load_trace_window = false;
            _settings_window_shown = false;
            _show_select_exe_window = false;
        }



        private void DrawDetectItEasyProgress(BinaryTarget activeTarget, Vector2 barSize)
        {
            DiELibDotNet.DieScript.SCANPROGRESS progress = _rgatstate.DIELib.GetDIEScanProgress(activeTarget);
            ImGui.BeginGroup();
            {

                if (progress.loading)
                {
                    SmallWidgets.ProgressBar("DieProgBar", $"Loading Scripts", 0, barSize, 0xff117711, 0xff111111);
                }
                else if (progress.running)
                {
                    float dieProgress = (float)progress.scriptsFinished / (float)progress.scriptCount;
                    string caption = $"{progress.scriptsFinished}/{progress.scriptCount} scripts complete";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }
                else if (progress.errored)
                {
                    float dieProgress = progress.scriptCount == 0 ? 0f : (float)progress.scriptsFinished / (float)progress.scriptCount;
                    string caption = $"Scan Failed after {progress.scriptsFinished} scripts";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }
                else if (progress.StopRequestFlag)
                {
                    float dieProgress = (float)progress.scriptsFinished / (float)progress.scriptCount;
                    string caption = $"Cancelled after {progress.scriptsFinished}/{progress.scriptCount} scripts";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }
                else
                {
                    float dieProgress = (float)progress.scriptsFinished / (float)progress.scriptCount;
                    string caption = $"Scan complete ({progress.scriptsFinished} scripts)";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }

                ImGui.SameLine();

                if ((progress.running || progress.loading))
                {
                    if (ImGui.Button("X")) _rgatstate.DIELib.CancelDIEScan(activeTarget);
                }
                else if (!progress.running && !progress.loading)
                {
                    //if (ImGui.Button("RL")) _rgatstate.DIELib.ReloadDIEScripts();  //add a button to reload scripts somewhere
                    // ImGui.SameLine(); 
                    if (ImGui.Button("RS")) _rgatstate.DIELib.StartDetectItEasyScan(activeTarget);
                }
            }
            ImGui.EndGroup();
        }



        private void DrawSignaturesBox(BinaryTarget activeTarget)
        {
            ImGui.Text("Signature Hits");
            ImGui.NextColumn();
            ImGui.BeginGroup();
            {
                string formatNotes = activeTarget.FormatSignatureHits(out bool gotYARA, out bool gotDIE);
                ImGui.InputTextMultiline("##fmtnote", ref formatNotes, 400, new Vector2(0, 160), ImGuiInputTextFlags.ReadOnly);
                ImGui.SameLine();

                ImGui.BeginGroup();

                DrawDetectItEasyProgress(activeTarget, new Vector2(250, 25));



                //ImGui.ProgressBar(0.4f, new Vector2(250, 20), "YARA Scan Progress");
                ImGui.EndGroup();
            }
            ImGui.EndGroup();

        }

        private void DrawTraceTab_FileInfo(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginChildFrame(22, new Vector2(width, 300), ImGuiWindowFlags.AlwaysAutoResize);
            ImGui.BeginGroup();
            {
                ImGui.Columns(2);
                ImGui.SetColumnWidth(0, 120);
                ImGui.SetColumnWidth(1, width - 120);
                ImGui.Separator();

                byte[] _dataInput = null;

                ImGui.AlignTextToFramePadding();
                ImGui.Text("File"); ImGui.NextColumn();
                string fileStr = String.Format("{0} ({1})", activeTarget.FileName, activeTarget.GetFileSizeString());
                _dataInput = Encoding.UTF8.GetBytes(fileStr);
                ImGui.InputText("##filenameinp", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA1 Hash"); ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA1Hash());
                ImGui.InputText("##s1hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA256 Hash"); ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA256Hash());
                ImGui.InputText("##s256hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();

                ImGui.Text("Hex Preview"); ImGui.NextColumn();
                _hexTooltipShown = false;
                _ImGuiController.PushOriginalFont(); //it's monospace and UTF8
                {
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.HexPreview);
                    ImGui.InputText("##hexprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    _hexTooltipShown = _hexTooltipShown || ImGui.IsItemHovered();
                    if (ImGui.IsItemHovered())
                    {
                        ShowHexPreviewTooltip(activeTarget);
                    }
                    ImGui.PopFont();
                }

                ImGui.Text("ASCII Preview"); ImGui.NextColumn();
                _ImGuiController.PushOriginalFont();
                {
                    _dataInput = Encoding.ASCII.GetBytes(activeTarget.ASCIIPreview);
                    ImGui.InputText("##ascprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    _hexTooltipShown = _hexTooltipShown || ImGui.IsItemHovered();
                    if (ImGui.IsItemHovered())
                    {
                        ShowHexPreviewTooltip(activeTarget);
                    }
                    ImGui.PopFont();

                }

                if (!_hexTooltipShown) _hexTooltipScroll = 0;

                DrawSignaturesBox(activeTarget);


                ImGui.NextColumn();
            }

            ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();
        }

        float _hexTooltipScroll = 0;
        bool _hexTooltipShown;
        private void ShowHexPreviewTooltip(BinaryTarget target)
        {
            ImGui.SetNextWindowSize(new Vector2(530, 300));
            ImGui.BeginTooltip();

            string hexline = target.HexTooltip();


            ImGuiInputTextFlags flags = ImGuiInputTextFlags.ReadOnly;
            flags |= ImGuiInputTextFlags.Multiline;
            flags |= ImGuiInputTextFlags.NoHorizontalScroll;
            ImGui.SetScrollY(_hexTooltipScroll);
            ImGui.InputTextMultiline("##inplin1", ref hexline, (uint)hexline.Length, new Vector2(530, 845), flags);
            if (_hexTooltipScroll > ImGui.GetScrollMaxY())
                _hexTooltipScroll = ImGui.GetScrollMaxY();

            ImGui.EndTooltip();
        }


        private static void DrawTraceTab_DiagnosticSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998800);
                ImGui.BeginChildFrame(9, new Vector2(width, 300));
                {
                    ImGui.Button("DynamoRIO Test");
                    ImGui.Button("PIN Test");

                    if (ImGui.BeginCombo("##loglevel", "Essential"))
                    {

                        if (ImGui.Selectable("Essential", true))
                        {
                            Console.Write("Esel");
                        }
                        if (ImGui.Selectable("Verbose", false))
                        {
                            Console.Write("vbsel");
                        }
                        ImGui.EndCombo();
                    }


                }
                ImGui.EndChildFrame();

                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }

        private void DrawTraceTab_InstrumentationSettings(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginGroup();
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF992200);



            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.AlignTextToFramePadding();
            ImGui.Text("Module Tracing");
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Customise which libraries rgat will instrument. Tracing more code affects performance and makes resulting graphs more complex.");
            ImGui.SameLine();
            string TraceLabel = $"Tracelist [{activeTarget.traceChoices.traceDirCount + activeTarget.traceChoices.traceFilesCount}]";
            if (ImGui.RadioButton(TraceLabel, ref activeTarget.traceChoices._tracingModeRef, 0))
            {
                activeTarget.traceChoices.TracingMode = (eModuleTracingMode)activeTarget.traceChoices._tracingModeRef;
            };
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Only specified libraries will be traced");
            ImGui.SameLine();
            string IgnoreLabel = $"IgnoreList [{activeTarget.traceChoices.ignoreDirsCount + activeTarget.traceChoices.ignoreFilesCount}]";
            if (ImGui.RadioButton(IgnoreLabel, ref activeTarget.traceChoices._tracingModeRef, 1))
            {
                activeTarget.traceChoices.TracingMode = (eModuleTracingMode)activeTarget.traceChoices._tracingModeRef;
            };
            ImGui.SameLine();
            ImguiUtils.HelpMarker("All libraries will be traced except for those specified");
            ImGui.EndChildFrame();


            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFFdddddd);

            if (ImGui.BeginChildFrame(ImGui.GetID("exclusionlist_contents"), ImGui.GetContentRegionAvail()))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);
                if ((eModuleTracingMode)activeTarget.traceChoices.TracingMode == eModuleTracingMode.eDefaultTrace)
                {
                    if (ImGui.TreeNode($"Ignored Directories ({activeTarget.traceChoices.ignoreDirsCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetIgnoredDirs();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode($"Ignored Files ({activeTarget.traceChoices.ignoreFilesCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetIgnoredFiles();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }

                else if ((eModuleTracingMode)activeTarget.traceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
                {
                    if (ImGui.TreeNode($"Included Directories ({activeTarget.traceChoices.traceDirCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetTracedDirs();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode($"Included Files ({activeTarget.traceChoices.traceFilesCount})"))
                    {
                        List<string> names = activeTarget.traceChoices.GetTracedFiles();
                        foreach (string fstr in names) ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }
                ImGui.PopStyleColor();
                ImGui.EndChildFrame();
            }
            ImGui.PopStyleColor();

            if (ImGui.BeginPopupContextItem("exclusionlist_contents", ImGuiPopupFlags.MouseButtonRight))
            {
                ImGui.Selectable("Add files/directories");
                ImGui.EndPopup();
            }

            ImGui.EndChildFrame();

            ImGui.PopStyleColor();
            ImGui.EndGroup();

        }

        bool _checkStartPausedState;
        private void DrawTraceTab_ExecutionSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF222200);
                ImGui.BeginChildFrame(10, new Vector2(width, 200));
                ImGui.Text("Execution Settings");

                ImGui.BeginChildFrame(18, new Vector2(width, 100));
                ImGui.AlignTextToFramePadding();
                ImGui.Text("Instrumentation Engine");
                ImGui.RadioButton("Intel Pin", ref _selectedInstrumentationEngine, 0);
                ImGui.RadioButton("Qiling", ref _selectedInstrumentationEngine, 1);
                ImGui.RadioButton("IPT", ref _selectedInstrumentationEngine, 2);
                ImGui.EndChildFrame();

                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998880);
                ImGui.AlignTextToFramePadding();

                ImGui.Text("Command Line");
                ImGui.SameLine();
                ImguiUtils.HelpMarker("Command line arguments passed to the program being executed");
                ImGui.SameLine();

                byte[] _dataInput = new byte[1024];
                ImGui.InputText("##cmdline", _dataInput, 1024);
                ImGui.PopStyleColor();
                if (ImGui.Button("Start Trace"))
                {
                    string runargs = $"-t \"{GlobalConfig.PinToolPath32}\" -P \"f\" -- \"{ _rgatstate.ActiveTarget.FilePath}\"";
                    System.Diagnostics.Process p = System.Diagnostics.Process.Start(GlobalConfig.PinPath, runargs);
                    Console.WriteLine($"Started process id {p.Id}");
                }
                ImGui.SameLine();
                if (ImGui.Checkbox("Start Paused", ref _checkStartPausedState))
                {
                    if (_checkStartPausedState)
                    {
                        _rgatstate.ActiveTarget.SetTraceConfig("PAUSE_ON_START", "TRUE");
                    }
                }
                ImGui.EndChildFrame();
                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }
















        private void DrawTraceTab()
        {

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            if (activeTarget == null)
            {
                String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁ф";
                ImguiUtils.DrawCenteredText(msg);
                return;
            }

            ImGui.BeginGroup();
            {
                DrawTraceTab_FileInfo(activeTarget, ImGui.GetContentRegionAvail().X - 200);
                ImGui.SameLine();
                DrawTraceTab_DiagnosticSettings(200);
                ImGui.EndGroup();
            }

            ImGui.BeginGroup();
            {
                DrawTraceTab_InstrumentationSettings(activeTarget, 400);
                ImGui.SameLine();
                DrawTraceTab_ExecutionSettings(ImGui.GetContentRegionAvail().X - 400);
                ImGui.EndGroup();
            }
        }

        private void DrawVisualiserGraphs(float height)
        {
            Vector2 graphSize = new Vector2(ImGui.GetContentRegionAvail().X - UI_Constants.PREVIEW_PANE_WIDTH, height);
            if (ImGui.BeginChild(ImGui.GetID("MainGraphWidget"), graphSize))
            {
                MainGraphWidget.Draw(graphSize);
                Vector2 msgpos = ImGui.GetCursorScreenPos() + new Vector2(graphSize.X, -1 * graphSize.Y);
                MainGraphWidget.DisplayEventMessages(msgpos);
                ImGui.EndChild();
            }

            ImGui.SameLine(0, 0);

            Vector2 previewPaneSize = new Vector2(UI_Constants.PREVIEW_PANE_WIDTH, height);
            ImGui.PushStyleColor(ImGuiCol.Border, GlobalConfig.GetThemeColour(GlobalConfig.eThemeColour.ePreviewPaneBorder));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, GlobalConfig.GetThemeColour(GlobalConfig.eThemeColour.ePreviewPaneBackground));


            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(0, 0));

            if (ImGui.BeginChild(ImGui.GetID("GLVisThreads"), previewPaneSize, true))
            {
                PreviewGraphWidget.DrawWidget();
                if (PreviewGraphWidget.clickedGraph != null)
                {
                    SetActiveGraph(PreviewGraphWidget.clickedGraph);
                    PreviewGraphWidget.ResetClickedGraph();
                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();

        }

        float sliderPosX = -1;

        private unsafe void DrawReplaySlider(float replayControlsSize)
        {
            int progressBarPadding = 6;
            Vector2 progressBarSize = new Vector2(replayControlsSize - (progressBarPadding * 2), 50);

            ImGui.InvisibleButton("Replay Progress", progressBarSize);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - progressBarSize.Y);

            Vector2 AnimationProgressBarPos = ImGui.GetItemRectMin();

            Vector2 SliderRectStart = new Vector2(AnimationProgressBarPos.X, AnimationProgressBarPos.Y);
            Vector2 SliderRectEnd = new Vector2(AnimationProgressBarPos.X + progressBarSize.X, AnimationProgressBarPos.Y + progressBarSize.Y);

            PlottedGraph activeGraph = _rgatstate.ActiveGraph;
            if (ImGui.IsItemActive())
            {
                sliderPosX = ImGui.GetIO().MousePos.X - ImGui.GetWindowPos().X;
            }
            else
            {

                if (activeGraph != null)
                {
                    float animPercentage = activeGraph.GetAnimationPercent();
                    sliderPosX = animPercentage * (SliderRectEnd.X - SliderRectStart.X);
                }
            }

            Vector2 SliderArrowDrawPos = new Vector2(AnimationProgressBarPos.X + sliderPosX, AnimationProgressBarPos.Y);
            if (SliderArrowDrawPos.X < SliderRectStart.X) SliderArrowDrawPos.X = AnimationProgressBarPos.X;
            if (SliderArrowDrawPos.X > SliderRectEnd.X) SliderArrowDrawPos.X = SliderRectEnd.X;

            float sliderBarPosition = (SliderArrowDrawPos.X - SliderRectStart.X) / progressBarSize.X;
            if (sliderBarPosition <= 0.05) SliderArrowDrawPos.X += 1;
            if (sliderBarPosition >= 99.95) SliderArrowDrawPos.X -= 1;

            if (ImGui.IsItemActive())
            {
                if (activeGraph != null)
                {
                    activeGraph.SeekToAnimationPosition(sliderBarPosition);
                }
                Console.WriteLine($"User changed animation position to: {sliderBarPosition * 100}%");
            }


            //ImGui.GetWindowDrawList().AddRectFilled(SliderRectStart, SliderRectEnd, 0xff000000);
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
            _visualiserBar.GenerateReplay(progressBarSize.X, 50, _rgatstate.ActiveGraph.internalProtoGraph);
            _visualiserBar.Draw();


            ImguiUtils.RenderArrowsForHorizontalBar(ImGui.GetForegroundDrawList(),
                SliderArrowDrawPos,
                new Vector2(3, 7), progressBarSize.Y, 240f);

        }




        private void DrawCameraPopup()
        {
            PlottedGraph ActiveGraph = _rgatstate.ActiveGraph;
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
            PlottedGraph activeGraph = _rgatstate.ActiveGraph;
            if (activeGraph == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(width, otherControlsHeight)))
                {
                    ImGui.Text("No active graph");

                    ImGui.EndChild();
                }
                return;
            }

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF555555);

            if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(width, otherControlsHeight)))
            {

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);

                DrawReplaySlider(width);

                switch (activeGraph.ReplayState)
                {
                    case PlottedGraph.REPLAY_STATE.ePaused:
                        ImGui.Text("Trace Replay: Paused");
                        break;
                    case PlottedGraph.REPLAY_STATE.eEnded:
                        ImGui.Text("Trace Replay: Resetting");
                        break;
                    case PlottedGraph.REPLAY_STATE.ePlaying:
                        ImGui.Text("Trace Replay: Replaying");
                        break;
                    case PlottedGraph.REPLAY_STATE.eStopped:
                        ImGui.Text("Trace Replay: Stopped");
                        break;
                }

                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("ctrls2354"))
                {




                    if (activeGraph != null)
                    {
                        PlottedGraph.REPLAY_STATE replaystate = activeGraph.ReplayState;
                        string BtnText = replaystate == PlottedGraph.REPLAY_STATE.ePlaying ? "Pause" : "Play";
                        ImGui.BeginGroup();
                        if (ImGui.Button(BtnText, new Vector2(36, 36)))
                        {
                            activeGraph.PlayPauseClicked();
                        }

                        if (replaystate == PlottedGraph.REPLAY_STATE.ePaused)
                        {
                            ImGui.SameLine();
                            if (ImGui.Button("Step", new Vector2(36, 36)))
                            {
                                activeGraph.StepPausedAnimation(1);
                            }
                        }

                        if (ImGui.Button("Reset", new Vector2(36, 36)))
                        {
                            activeGraph.ResetClicked();
                        }

                        bool isanimed = false;
                        string bt = "Set Animated";
                        if (activeGraph.IsAnimated)
                        {
                            bt = "Set NonAnimated";
                            isanimed = true;
                        }
                        ImGui.SameLine();
                        if (ImGui.Button(bt, new Vector2(36, 36)))
                        {
                            activeGraph.SetAnimated(!isanimed);
                        }
                        ImGui.EndGroup();
                    }

                    ImGui.SameLine(); //pointless?
                    ImGui.SetNextItemWidth(60f);
                    if (ImGui.BeginCombo("Replay Speed", " x1", ImGuiComboFlags.HeightLargest))
                    {
                        if (ImGui.Selectable("x1/4")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x1/2")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x1")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x2")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x4")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x8")) Console.WriteLine("Speed changed");
                        if (ImGui.Selectable("x16")) Console.WriteLine("Speed changed");
                        ImGui.EndCombo();
                    }

                    ImGui.EndChild();
                }



                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
        }


        private unsafe void DrawLiveTraceControls(float otherControlsHeight, float width, PlottedGraph graph)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF555555);

            float replayControlsSize = ImGui.GetContentRegionAvail().X - 300f;
            if (ImGui.BeginChild(ImGui.GetID("LiveControls"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("RenderingBox"))
                {

                    _visualiserBar.GenerateLive(width, 50, _rgatstate.ActiveGraph.internalProtoGraph);
                    _visualiserBar.Draw();

                    ImGui.Columns(2);
                    ImGui.SetColumnWidth(0, 200);
                    ImGui.SetColumnWidth(1, 200);

                    ImGui.BeginGroup();
                    if (ImGui.RadioButton("Static", !graph.IsAnimated))
                    {
                        graph.SetAnimated(false);
                    }
                    if (ImGui.RadioButton("Animated", graph.IsAnimated))
                    {
                        graph.SetAnimated(true);
                    }
                    ImGui.EndGroup();

                    ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff3300c0);
                    ImGui.BeginGroup();
                    if (ImGui.Button("Kill"))
                    {

                        graph.internalProtoGraph.TraceData.SendDebugCommand(0, "EXIT");

                    }
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Terminate the process");

                    ImGui.SameLine();

                    if (ImGui.Button("Kill All")) Console.WriteLine("Kill All clicked");

                    ImGui.EndGroup();

                    ImGui.NextColumn();

                    ImGui.BeginGroup();

                    if (graph.internalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eRunning)
                    {
                        if (ImGui.Button("Pause/Break"))
                        {
                            graph.internalProtoGraph.TraceData.SendDebugCommand(0, "BRK");
                        }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("Pause all process threads");
                    }

                    if (graph.internalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eSuspended)
                    {
                        if (ImGui.Button("Continue"))
                        {
                            graph.internalProtoGraph.TraceData.SendDebugCommand(0, "CTU");
                        }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("Resume all process threads");

                        if (ImGui.Button("Step In"))
                        {
                            graph.internalProtoGraph.TraceData.SendDebugStep(graph.tid);
                        }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("Step to next instruction");

                        if (ImGui.Button("Step Over"))
                        {
                            graph.internalProtoGraph.TraceData.SendDebugStepOver(graph.internalProtoGraph);
                        }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("Step past call instruction");
                    }

                    ImGui.EndGroup();
                    ImGui.PopStyleColor();

                    ImGui.Columns(1);

                    ImGui.EndChild();
                }



                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
        }

        private void SetActiveGraph(PlottedGraph graph)
        {
            if (graph.pid != _rgatstate.ActiveGraph.pid)
            {
                Console.WriteLine("Warning: Graph selected in non-viewed trace");
                return;
            }

            _rgatstate.SwitchToGraph(graph);
            PreviewGraphWidget.SetSelectedGraph(graph);
            MainGraphWidget.SetActiveGraph(graph);
        }


        private void CreateTracesDropdown(TraceRecord tr, int level)
        {
            foreach (TraceRecord child in tr.children)
            {
                string tabs = new String("  ");
                if (ImGui.Selectable(tabs + "PID " + child.PID, _rgatstate.ActiveGraph.pid == child.PID))
                {
                    _rgatstate.SelectActiveTrace(child);
                }
                if (child.children.Count > 0)
                {
                    CreateTracesDropdown(tr, level + 1);
                }
            }
        }

        private void DrawTraceSelector(float frameHeight, float frameWidth)
        {

            PlottedGraph graph = _rgatstate.ActiveGraph;
            if (graph == null)
            {
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(frameWidth, frameHeight)))
                {
                    ImGui.Text($"No selected graph");
                    ImGui.EndChild();
                }
                return;
            }


            float vpadding = 4;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);

            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(frameWidth, frameHeight)))
            {

                float combosHeight = 60 - vpadding;

                if (_rgatstate.ActiveTarget != null)
                {
                    var tracelist = _rgatstate.ActiveTarget.GetTracesUIList();
                    string selString = (_rgatstate.ActiveGraph != null) ? "PID " + _rgatstate.ActiveGraph.pid : "";
                    if (ImGui.BeginCombo($"{tracelist.Count} Process{(tracelist.Count != 1 ? "es" : "")}", selString))
                    {
                        foreach (var timepid in tracelist)
                        {
                            TraceRecord selectableTrace = timepid.Item2;
                            if (ImGui.Selectable("PID " + selectableTrace.PID, _rgatstate.ActiveGraph?.pid == selectableTrace.PID))
                            {
                                _rgatstate.SelectActiveTrace(selectableTrace);
                            }
                            if (selectableTrace.children.Count > 0)
                            {
                                CreateTracesDropdown(selectableTrace, 1);
                            }
                            //ImGui.Selectable("PID 12345 (xyz.exe)");
                        }
                        ImGui.EndCombo();
                    }

                    if (_rgatstate.ActiveTrace != null)
                    {
                        selString = (_rgatstate.ActiveGraph != null) ? "TID " + _rgatstate.ActiveGraph.tid : "";
                        uint activeTID = (_rgatstate.ActiveGraph != null) ? +_rgatstate.ActiveGraph.tid : 0;
                        List<PlottedGraph> graphs = _rgatstate.ActiveTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
                        if (ImGui.BeginCombo($"{graphs.Count} Thread{(graphs.Count != 1 ? "s" : "")}", selString))
                        {
                            foreach (PlottedGraph selectablegraph in graphs)
                            {
                                string caption = "TID " + selectablegraph.tid;
                                int nodeCount = selectablegraph.GraphNodeCount();
                                if (nodeCount == 0) caption += " [No Data]";
                                else caption += $" [{nodeCount} nodes]";
                                if (ImGui.Selectable(caption, activeTID == selectablegraph.tid))
                                {
                                    SetActiveGraph(selectablegraph);
                                }
                            }
                            ImGui.EndCombo();
                        }
                    }
                }



                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);

                ImGui.Text($"Thread ID: {graph.tid}");

                ImGui.SameLine();
                if (graph.internalProtoGraph.Terminated)
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Red), "(Terminated)");
                else
                    ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.LimeGreen), $"(Active)");

                float metricsHeight = 80;
                ImGui.Columns(3, "smushes");
                ImGui.SetColumnWidth(0, 20);
                ImGui.SetColumnWidth(1, 130);
                ImGui.SetColumnWidth(2, 250);
                ImGui.NextColumn();

                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff110022);
                if (ImGui.BeginChild("ActiveTraceMetrics", new Vector2(130, metricsHeight)))
                {
                    ImGui.Text($"Edges: {graph.internalProtoGraph.edgeList.Count}");
                    ImGui.Text($"Nodes: {graph.internalProtoGraph.NodeList.Count}");
                    ImGui.Text($"Updates: {graph.internalProtoGraph.SavedAnimationData.Count}");
                    if (graph.internalProtoGraph.TraceReader != null)
                    {
                        if (graph.internalProtoGraph.TraceReader.QueueSize > 0)
                            ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.OrangeRed), $"Backlog: {graph.internalProtoGraph.TraceReader.QueueSize}");
                        else
                            ImGui.Text($"Backlog: {graph.internalProtoGraph.TraceReader.QueueSize}");
                    }

                    ImGui.EndChild();
                }

                ImGui.NextColumn();

                if (ImGui.BeginChild("OtherMetrics", new Vector2(200, metricsHeight)))
                {
                    ImGui.Text($"Instructions: {graph.internalProtoGraph.TotalInstructions}");
                    if (graph.internalProtoGraph.PerformingUnchainedExecution)
                    {
                        ImGui.TextColored(WritableRgbaFloat.ToVec4(Color.Yellow), $"Busy: True");
                    }
                    else
                        ImGui.Text("Busy: False");

                    ImGui.Text("Z: 496");
                    ImGui.Text("Q: 41");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                ImGui.Columns(1, "smushes");


                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        private unsafe void DrawVisualiserControls(float controlsHeight)
        {
            float vpadding = 10;

            if (_rgatstate.ActiveGraph == null)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF222222);
                if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(ImGui.GetContentRegionAvail().X, controlsHeight - vpadding)))
                {
                    string caption = "No trace to display";
                    Vector2 captionsize = ImGui.CalcTextSize(caption);
                    ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X / 2 - captionsize.X / 2);
                    ImGui.SetCursorPosY(ImGui.GetContentRegionAvail().Y / 2 - captionsize.Y / 2);
                    ImGui.Text(caption);
                    ImGui.Text($"temp: {_rgatstate.ActiveGraph?.temperature}");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                return;
            }
            float topControlsBarHeight = 30;
            float otherControlsHeight = controlsHeight - topControlsBarHeight;
            float frameHeight = otherControlsHeight - vpadding;

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF553180);
            if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(ImGui.GetContentRegionAvail().X, frameHeight)))
            {
                PlottedGraph activeGraph = _rgatstate.ActiveGraph;
                if (activeGraph != null)
                {
                    float width = ImGui.GetContentRegionAvail().X - UI_Constants.PREVIEW_PANE_WIDTH;
                    if (!activeGraph.internalProtoGraph.Terminated)
                        DrawLiveTraceControls(frameHeight, width, activeGraph);
                    else
                        DrawPlaybackControls(frameHeight, width);

                }
                ImGui.SameLine(0, 0);
                DrawTraceSelector(frameHeight, UI_Constants.PREVIEW_PANE_WIDTH);
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();

        }


        void ManageActiveGraph()
        {
            if (_rgatstate.ActiveGraph == null)
            {
                if (_rgatstate.ActiveTrace == null)
                {
                    _rgatstate.SelectActiveTrace();
                }
                if (_rgatstate.ChooseActiveGraph())
                {
                    MainGraphWidget.SetActiveGraph(_rgatstate.ActiveGraph);
                    PreviewGraphWidget.SetActiveTrace(_rgatstate.ActiveTrace);
                    PreviewGraphWidget.SetSelectedGraph(_rgatstate.ActiveGraph);
                }
                else
                {
                    if (MainGraphWidget.ActiveGraph != null)
                    {
                        MainGraphWidget.SetActiveGraph(null);
                        PreviewGraphWidget.SetActiveTrace(null);

                    }
                }
            }
            else if (_rgatstate.ActiveGraph != MainGraphWidget.ActiveGraph)
            {
                MainGraphWidget.SetActiveGraph(_rgatstate.ActiveGraph);
                PreviewGraphWidget.SetActiveTrace(_rgatstate.ActiveTrace);
                PreviewGraphWidget.SetSelectedGraph(_rgatstate.ActiveGraph);
            }
        }



        private void DrawVisTab()
        {
            ManageActiveGraph();

            float controlsHeight = 230;

            DrawVisualiserGraphs(ImGui.GetContentRegionAvail().Y - controlsHeight);
            DrawVisualiserControls(controlsHeight);
        }

        private void DrawAnalysisTab()
        {
            ImGui.Text("Trace start stuff here");
        }
        private void DrawCompareTab()
        {
            ImGui.Text("Trace start stuff here");
        }


        static bool[] selected = new bool[(int)LogFilterType.COUNT];
        static bool[] rowLastSelected = new bool[3];
        static byte[] textFilterValue = new byte[500];
        private void DrawLogsTab()
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("logtableframe"), ImGui.GetContentRegionAvail()))
            {
                Logging.LOG_EVENT[] msgs = Logging.GetLogMessages(selected);
                int activeCount = selected.Where(x => x == true).Count();

                string label = $"{msgs.Length} log entries displayed from ({selected.Length-activeCount}/{selected.Length}) sources";
                bool isOpen = ImGui.TreeNode("##FiltersTree", label);
                if (isOpen)
                {
                    Vector2 boxSize = new Vector2(64, 40);
                    Vector2 marginSize = new Vector2(70, 40);

                    ImGuiSelectableFlags flags = ImGuiSelectableFlags.DontClosePopups;
                    uint tableHdrBG = 0xff333333;

                    if (ImGui.BeginTable("LogFilterTable", 6, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX, new Vector2(440, 100)))
                    {
                        ImGui.TableNextRow();

                        ImGui.TableSetColumnIndex(0);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                        if (ImGui.Selectable("Message", false, flags, marginSize))
                        {
                            rowLastSelected[0] = !rowLastSelected[0];
                            selected[(int)LogFilterType.TextDebug] = rowLastSelected[0];
                            selected[(int)LogFilterType.TextInfo] = rowLastSelected[0];
                            selected[(int)LogFilterType.TextAlert] = rowLastSelected[0];
                            selected[(int)LogFilterType.TextError] = rowLastSelected[0];
                        }


                        ImGui.TableNextColumn();
                        ImGui.Selectable("Debug", ref selected[(int)LogFilterType.TextDebug], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable("Info", ref selected[(int)LogFilterType.TextInfo], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable("Alert", ref selected[(int)LogFilterType.TextAlert], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable("Error", ref selected[(int)LogFilterType.TextError], flags, boxSize);

                        ImGui.TableNextRow();
                        ImGui.TableSetColumnIndex(0);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                        if (ImGui.Selectable("Timeline", false, flags, marginSize))
                        {
                            rowLastSelected[1] = !rowLastSelected[1];
                            selected[(int)LogFilterType.TimelineProcess] = rowLastSelected[1];
                            selected[(int)LogFilterType.TimelineThread] = rowLastSelected[1];
                        }
                        ImGui.TableNextColumn();
                        ImGui.Selectable("Process", ref selected[(int)LogFilterType.TimelineProcess], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable("Thread", ref selected[(int)LogFilterType.TimelineThread], flags, boxSize);

                        ImGui.TableNextRow();
                        ImGui.TableSetColumnIndex(0);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                        if (ImGui.Selectable("API", false, flags, marginSize))
                        {
                            rowLastSelected[2] = !rowLastSelected[2];
                            selected[(int)LogFilterType.APIFile] = rowLastSelected[2];
                            selected[(int)LogFilterType.APINetwork] = rowLastSelected[2];
                            selected[(int)LogFilterType.APIReg] = rowLastSelected[2];
                            selected[(int)LogFilterType.APIProcess] = rowLastSelected[2];
                            selected[(int)LogFilterType.APIOther] = rowLastSelected[2];
                        }

                        ImGui.TableNextColumn();
                        ImGui.Selectable("File", ref selected[(int)LogFilterType.APIFile], flags, boxSize);
                        ImGui.TableNextColumn();
                        ImGui.Selectable("Network", ref selected[(int)LogFilterType.APINetwork], flags, boxSize);
                        ImGui.TableNextColumn();
                        ImGui.Selectable("Registry", ref selected[(int)LogFilterType.APIReg], flags, boxSize);
                        ImGui.TableNextColumn();
                        ImGui.Selectable("Process", ref selected[(int)LogFilterType.APIProcess], flags, boxSize);
                        ImGui.TableNextColumn();
                        ImGui.Selectable("Other", ref selected[(int)LogFilterType.APIOther], flags, boxSize);
                        ImGui.EndTable();
                    }
                    
                    if (ImGui.BeginPopupContextItem("FlterTableRightCtx",ImGuiPopupFlags.MouseButtonRight))
                    {
                        if (ImGui.MenuItem("Clear All Source Filters"))
                        {
                            Array.Clear(selected, 0, selected.Length);
                        }
                        if (ImGui.MenuItem("Apply All Source Filters"))
                        {
                            selected = Enumerable.Repeat(true, selected.Length).ToArray();
                        }
                        ImGui.EndPopup();
                    }
                    
                    
                    ImGui.BeginGroup();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);
                    ImGui.Indent(8);
                    ImGui.Text("Log Text Filter");
                    ImGui.SameLine();
                    ImGui.SetNextItemWidth(280);
                    ImGui.InputText("##IT1", textFilterValue, (uint)textFilterValue.Length);

                    ImGui.SameLine();
                    if (ImGui.Button("Clear")) textFilterValue = new byte[textFilterValue.Length];

                    ImGui.EndGroup();


                    ImGui.TreePop();
                }











                if (ImGui.BeginTable("LogsTable", 3, ImGuiTableFlags.Borders))
                {
                    ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 90);
                    ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 100);
                    ImGui.TableSetupColumn("Details");
                    ImGui.TableHeadersRow();

                    foreach (LOG_EVENT msg in msgs)
                    {
                        string msgString;
                        string sourceString;
                        switch (msg.LogType)
                        {
                            case Logging.eLogType.Text:
                                {
                                    Logging.TEXT_LOG_EVENT text_evt = (Logging.TEXT_LOG_EVENT)msg;
                                    sourceString = $"{msg.LogType} - {text_evt._logLevel}";
                                    msgString = text_evt._text;
                                    break;
                                }

                            case Logging.eLogType.TimeLine:
                                {
                                    Logging.TIMELINE_EVENT tl_evt = (Logging.TIMELINE_EVENT)msg;
                                    sourceString = $"{msg.LogType} - {tl_evt.LogType}";
                                    msgString = tl_evt.ID.ToString();
                                    break;
                                }
                            default:
                                sourceString = "";
                                msgString = "Other event type " + msg.LogType.ToString();
                                break;

                        }

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeMilliseconds(msg.EventTimeMS);
                        string timeString = dateTimeOffset.ToString("HH:mm:ss:ff");
                        ImGui.Text(timeString);
                        ImGui.TableNextColumn();
                        ImGui.Text(sourceString);
                        ImGui.TableNextColumn();
                        ImGui.TextWrapped(msgString);
                    }
                    ImGui.EndTable();
                }
                ImGui.EndChildFrame();
            }
        }


        private unsafe void DrawMainMenu()
        {
            if (ImGui.BeginMenuBar())
            {
                if (ImGui.BeginMenu("Target"))
                {
                    if (ImGui.MenuItem("Select Target Executable")) { _show_select_exe_window = true; }
                    if (ImGui.MenuItem("Recent Targets")) { }
                    if (ImGui.MenuItem("Open Saved Trace")) { _show_load_trace_window = true; }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Save Thread Trace")) { }
                    if (ImGui.MenuItem("Save Process Traces")) { }
                    if (ImGui.MenuItem("Save All Traces")) { _rgatstate.SaveAllTargets(); }
                    if (ImGui.MenuItem("Export Pajek")) { _rgatstate.ExportTraceAsPajek(_rgatstate.ActiveTrace, _rgatstate.ActiveGraph.tid); }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Exit")) { }
                    ImGui.EndMenu();
                }


                ImGui.MenuItem("Settings", null, ref _settings_window_shown);
                ImGui.EndMenuBar();
            }
        }

        private unsafe void DrawTargetBar()
        {
            if (_rgatstate.targets.count() == 0)
            {
                ImGui.Text("No target selected or trace loaded");
                return;
            }

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            string activeString = (activeTarget == null) ? "No target selected" : activeTarget.FilePath;
            List<string> paths = _rgatstate.targets.GetTargetPaths();
            ImGuiComboFlags flags = 0;
            if (ImGui.BeginCombo("Selected Binary", activeString, flags))
            {
                foreach (string path in paths)
                {
                    bool is_selected = activeTarget != null && activeTarget.FilePath == path;
                    if (ImGui.Selectable(path, is_selected))
                    {
                        _rgatstate.SetActiveTarget(path);
                    }

                    // Set the initial focus when opening the combo (scrolling + keyboard navigation focus)
                    if (is_selected)
                        ImGui.SetItemDefaultFocus();
                }
                ImGui.EndCombo();
            }
        }

        private unsafe void DrawTabs()
        {
            bool dummy = true;
            ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;


            if (ImGui.BeginTabBar("Primary Tab Bar", tab_bar_flags))
            {
                if (ImGui.BeginTabItem("Start Trace"))
                {
                    DrawTraceTab();
                    ImGui.EndTabItem();
                }

                if (ImGui.BeginTabItem("Visualiser"))
                {
                    DrawVisTab();
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Trace Analysis"))
                {
                    DrawAnalysisTab();
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Graph Comparison"))
                {
                    DrawCompareTab();
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Logs"))
                {
                    DrawLogsTab();
                    ImGui.EndTabItem();
                }

                ImGui.EndTabBar();
            }

        }


        private unsafe void DrawFileSelectBox()
        {
            ImGui.OpenPopup("Select Executable");

            if (ImGui.BeginPopupModal("Select Executable", ref _show_select_exe_window, ImGuiWindowFlags.None))
            {

                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue && File.Exists(picker.SelectedFile))
                    {
                        FileStream fs = File.OpenRead(picker.SelectedFile);
                        bool isJSON = (fs.ReadByte() == '{' && fs.ReadByte() == '"');
                        fs.Close();
                        if (isJSON)
                        {
                            Console.WriteLine("JSON detected, attempting to load file as saved trace instead");
                            LoadTraceByPath(picker.SelectedFile);
                        }
                        else
                        {
                            _rgatstate.AddTargetByPath(picker.SelectedFile);
                        }
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    _show_select_exe_window = false;
                }

                ImGui.EndPopup();
            }
        }

        private void LoadTraceByPath(string filepath)
        {
            if (!_rgatstate.LoadTraceByPath(filepath, out TraceRecord trace)) return;

            launch_all_trace_threads(trace, _rgatstate);

            _rgatstate.ActiveTarget = trace.binaryTarg;
            _rgatstate.SelectActiveTrace(trace.binaryTarg.GetFirstTrace());
            //_rgatstate.SwitchTrace = trace;

            //ui.dynamicAnalysisContentsTab.setCurrentIndex(eVisualiseTab);

        }

        void launch_all_trace_threads(TraceRecord trace, rgatState clientState)
        {
            ProcessLaunching.launch_saved_process_threads(trace, clientState);

            foreach (TraceRecord childTrace in trace.children)
            {
                launch_all_trace_threads(childTrace, clientState);
            }
        }

        private void DrawTraceLoadBox()
        {
            ImGui.OpenPopup("Select Trace File");

            if (ImGui.BeginPopupModal("Select Trace File", ref _show_load_trace_window, ImGuiWindowFlags.None))
            {
                string savedir = GlobalConfig.SaveDirectory;
                if (!Directory.Exists(savedir)) savedir = Environment.CurrentDirectory;
                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, savedir);
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        LoadTraceByPath(picker.SelectedFile);

                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    _show_load_trace_window = false;
                }

                ImGui.EndPopup();
            }
        }
    }

    class PendingKeybind
    {
        public PendingKeybind() { }
        public bool active;
        public string actionText = "";
        public eKeybind action;
        public int bindIndex;
        public string currentKey = "";
    }
}
