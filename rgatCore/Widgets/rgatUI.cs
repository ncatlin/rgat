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
using Humanizer;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace rgatCore
{
    class rgatUI
    {
        //rgat ui state
        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private bool _show_test_harness = false;
        private ImGuiController _ImGuiController = null;

        //rgat program state
        private rgatState _rgatstate = null;
        private int _selectedInstrumentationEngine = 0;
        private int _selectedInstrumentationLevel = 0;

        Threads.MainGraphRenderThread mainRenderThreadObj = null;
        Threads.HeatRankingThread heatRankThreadObj = null;
        ProcessCoordinatorThread processCoordinatorThreadObj = null;

        GraphPlotWidget MainGraphWidget;
        PreviewGraphsWidget PreviewGraphWidget;
        VisualiserBar _visualiserBar;
        SettingsMenu _SettingsMenu;
        TestsWindow _testHarness;

        Vector2 WindowStartPos = new Vector2(100f, 100f);
        Vector2 WindowOffset = new Vector2(0, 0);

        private readonly object _inputLock = new object();
        List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        float _mouseWheelDelta = 0;
        Vector2 _mouseDragDelta = new Vector2(0, 0);

        double _UIstartupProgress = 0;
        List<double> _lastFrameTimeMS = new List<double>();
        double _UIDrawFPS = 0;
        bool _frameTimerFired = false;

        public rgatUI(ImGuiController imguicontroller, GraphicsDevice _gd, CommandList _cl)
        {
            Logging.RecordLogEvent("rgatUI is starting in imgui mode", Logging.LogFilterType.TextDebug);
            _ImGuiController = imguicontroller;
            Task.Run(() => LoadingThread(imguicontroller, _gd, _cl));
            _UIstartupProgress = 0.1;

            System.Timers.Timer FrameStatTimer = new System.Timers.Timer(500);
            FrameStatTimer.Elapsed += FireTimer;
            FrameStatTimer.AutoReset = true;
            FrameStatTimer.Start();

            /*
            VeldridGraphBuffers.SetupZeroFillshader(imguicontroller);

            Stopwatch sw = new Stopwatch();
            sw.Start();
            //10000 in 30s, gross
            for (var i = 0; i < 1000; i++)
            {
                Console.Write($"[i:{i}],");
                trashmem(i, 10000);
                dotest(i, 10000);
            }
            sw.Stop();
            Console.WriteLine($"1 Done in {sw.ElapsedMilliseconds} ms");
            sw.Restart();
            //10000 in 30s, gross
            for (var i = 0; i < 1000; i++)
            {
                Console.Write($"{i},");

                trashmem(i, 10000);
                dotest2(i, 10000);
            }
            sw.Stop();
            Console.WriteLine($"2 Done in {sw.ElapsedMilliseconds} ms");
            */

        }


        unsafe void trashmem(int ri, int size)
        {
            BufferDescription bd = new BufferDescription((uint)size * 4, BufferUsage.StructuredBufferReadWrite, structureByteStride: 4);
            DeviceBuffer buffer = _ImGuiController.graphicsDevice.ResourceFactory.CreateBuffer(bd);
            CommandList cl = _ImGuiController.graphicsDevice.ResourceFactory.CreateCommandList();

            int[] bbb = new int[size];

            for (int i = 0; i < size; i += 1) { bbb[i] = -1; }


            cl.Begin();
            fixed (int* dataPtr = bbb)
            {
                cl.UpdateBuffer(buffer, 0, (IntPtr)dataPtr, (uint)size * 4);
                cl.End();
                _ImGuiController.graphicsDevice.SubmitCommands(cl);
                _ImGuiController.graphicsDevice.WaitForIdle();
                cl.Dispose();
            }
            buffer.Dispose();
        }

        unsafe void dotest(int ri, int size)
        {
            BufferDescription bd = new BufferDescription((uint)size * 4, BufferUsage.StructuredBufferReadWrite, structureByteStride: 4);
            DeviceBuffer buffer = _ImGuiController.graphicsDevice.ResourceFactory.CreateBuffer(bd);

            VeldridGraphBuffers.ZeroFillBuffers(new List<DeviceBuffer>() { buffer }, _ImGuiController.graphicsDevice);
            System.Diagnostics.Debug.Assert(!VeldridGraphBuffers.DetectNaN(_ImGuiController.graphicsDevice, buffer));
            buffer.Dispose();

        }



        unsafe void dotest2(int ri, int size)
        {
            BufferDescription bd = new BufferDescription((uint)size * 4, BufferUsage.StructuredBufferReadWrite, structureByteStride: 4);
            DeviceBuffer buffer = _ImGuiController.graphicsDevice.ResourceFactory.CreateBuffer(bd);

            CommandList cl = _ImGuiController.graphicsDevice.ResourceFactory.CreateCommandList();

            int[] ccc = new int[size];

            for (int i = 0; i < size; i += 1) { ccc[i] = 0; }


            fixed (int* fillPtr = ccc)
            {
                cl.Begin();
                cl.UpdateBuffer(buffer, 0, (IntPtr)fillPtr, (uint)size * 4);
                cl.End();
                _ImGuiController.graphicsDevice.SubmitCommands(cl);
                _ImGuiController.graphicsDevice.WaitForIdle();
                cl.Dispose();
            }

            System.Diagnostics.Debug.Assert(!VeldridGraphBuffers.DetectNaN(_ImGuiController.graphicsDevice, buffer));
            buffer.Dispose();


            /*
    cl.UpdateBuffer(buffer, 0, (IntPtr)dataPtr, (uint)size * 4);
    //cl.UpdateBuffer(buffer, 0, (IntPtr)fillPtr, (uint)size * 4);
    cl.End();
    _ImGuiController.graphicsDevice.SubmitCommands(cl);
    _ImGuiController.graphicsDevice.WaitForIdle();
    cl.Dispose();*/
        }


        private void FireTimer(object sender, System.Timers.ElapsedEventArgs e) { _frameTimerFired = true; }


        void LoadingThread(ImGuiController imguicontroller, GraphicsDevice _gd, CommandList _cl)
        {
            _rgatstate = new rgatState(_gd, _cl);
            TraceProcessorWorker.SetRgatState(_rgatstate);

            RecordLogEvent("Constructing rgatUI: Initing/Loading Config", Logging.LogFilterType.TextDebug); //about 800 ish ms
            double currentUIProgress = _UIstartupProgress;
            Task confloader = Task.Run(() => GlobalConfig.LoadConfig());
            while (!confloader.IsCompleted)
            {
                _UIstartupProgress = currentUIProgress + 0.3 * GlobalConfig.LoadProgress;
                Thread.Sleep(10);
            }

            RecordLogEvent("Startup: Config Inited", LogFilterType.TextDebug);
            _UIstartupProgress = 0.4;

            RecordLogEvent("Startup: Initing State Object", Logging.LogFilterType.TextDebug);


            RecordLogEvent("Startup: State created", LogFilterType.TextDebug);
            _UIstartupProgress = 0.5;

            RecordLogEvent("Startup: Initing Settings Window", LogFilterType.TextDebug);
            _SettingsMenu = new SettingsMenu(imguicontroller, _rgatstate); //call after config init, so theme gets generated
            _UIstartupProgress = 0.55;


            RecordLogEvent("Startup: Initing graph display widgets", LogFilterType.TextDebug);

            _visualiserBar = new VisualiserBar(_gd, imguicontroller); //200~ ms

            _UIstartupProgress = 0.60;
            MainGraphWidget = new GraphPlotWidget(imguicontroller, _gd, new Vector2(1000, 500)); //1000~ ms

            _UIstartupProgress = 0.9;
            PreviewGraphWidget = new PreviewGraphsWidget(imguicontroller, _gd, _rgatstate); //350~ ms
            _rgatstate.PreviewWidget = PreviewGraphWidget;


            RecordLogEvent("Startup: Initing graph rendering threads", LogFilterType.TextDebug);
            mainRenderThreadObj = new MainGraphRenderThread(MainGraphWidget);
            mainRenderThreadObj.Begin();

            heatRankThreadObj = null;// new HeatRankingThread(_rgatstate);           

            //todo - conditional thread here instead of new trace
            processCoordinatorThreadObj = new ProcessCoordinatorThread();
            processCoordinatorThreadObj.Begin();
            _UIstartupProgress = 0.95;



            RecordLogEvent("Startup: Initing layout engines", LogFilterType.TextDebug);
            _UIstartupProgress = 0.99;

            MainGraphWidget.LayoutEngine.AddParallelLayoutEngine(PreviewGraphWidget.LayoutEngine);
            PreviewGraphWidget.LayoutEngine.AddParallelLayoutEngine(MainGraphWidget.LayoutEngine);

            RecordLogEvent("Startup: rgatUI created", LogFilterType.TextDebug);

            _rgatstate.LoadSignatures();

            RecordLogEvent("Startup: Signatures Loaded", LogFilterType.TextDebug);

            _LogFilters[(int)LogFilterType.TextDebug] = true;
            _LogFilters[(int)LogFilterType.TextInfo] = true;
            _LogFilters[(int)LogFilterType.TextError] = true;
            _LogFilters[(int)LogFilterType.TextAlert] = true;
            _UIstartupProgress = 1;

        }


        public void Exit()
        {
            if (GlobalConfig.BulkLogging)
                Logging.RecordLogEvent("rgat Exit() triggered", LogFilterType.BulkDebugLogFile);

            _rgatstate?.ShutdownRGAT();

            MainGraphWidget?.Dispose();
            PreviewGraphWidget?.Dispose();

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
            var timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            bool hasActiveTrace = _rgatstate?.ActiveTarget != null;

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;
            //window_flags |= ImGuiWindowFlags.NoTitleBar;
            if (hasActiveTrace)
            {
                window_flags |= ImGuiWindowFlags.MenuBar;
            }
            window_flags |= ImGuiWindowFlags.DockNodeHost;
            window_flags |= ImGuiWindowFlags.NoBringToFrontOnFocus;

            ImGui.GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
            //ImGui.GetIO().ConfigWindowsResizeFromEdges = true;

            ImGui.SetNextWindowPos(new Vector2(50, 50), ImGuiCond.Appearing);

            //ImGui.SetNextWindowSize(new Vector2(_ImGuiController._windowWidth, _ImGuiController._windowHeight), ImGuiCond.Appearing);
            ImGui.SetNextWindowSize(new Vector2(1200, 800), ImGuiCond.Appearing);

            Themes.ApplyThemeColours();
            ImGui.Begin("rgat Primary Window", window_flags);


            WindowOffset = ImGui.GetWindowPos() - WindowStartPos;
            HandleUserInput();

            BinaryTarget activeTarget = _rgatstate?.ActiveTarget;
            if (activeTarget == null)
            {
                DrawStartSplash();
            }
            else
            {
                DrawMainMenu();
                DrawWindowContent();
            }

            if (_settings_window_shown) _SettingsMenu.Draw(ref _settings_window_shown);
            if (_show_select_exe_window) DrawFileSelectBox();
            if (_show_load_trace_window) DrawTraceLoadBox();
            if (_show_test_harness) _testHarness.Draw(ref _show_test_harness);

            Themes.ResetThemeColours();

            ImGui.End();

            timer.Stop();
            _lastFrameTimeMS.Add(timer.ElapsedMilliseconds);
            if (_lastFrameTimeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
                _lastFrameTimeMS = _lastFrameTimeMS.Skip(1).Take(GlobalConfig.StatisticsTimeAvgWindow).ToList();
            if (_frameTimerFired)
            {
                _frameTimerFired = false;
                _UIDrawFPS = Math.Min(101, 1000.0 / (_lastFrameTimeMS.Average()));
            }
        }


        void DrawWindowContent()
        {
            if (ImGui.BeginChild("MainWindow", ImGui.GetContentRegionAvail(), false, ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoScrollbar))
            {
                DrawTargetBar();
                if (DrawAlertBox())
                {
                    //raise the tabs up so the alert box nestles into the space
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 12);
                }

                BinaryTarget activeTarget = _rgatstate.ActiveTarget;
                if (activeTarget == null)
                {
                    DrawStartSplash();
                }
                else
                {
                    DrawTabs();
                }
                ImGui.EndChild();
            }
        }


        bool DrawAlertBox()
        {
            int alertCount = Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alerts.Length == 0) return false;

            const float width = 250;
            Vector2 size = new Vector2(width, 38);
            ImGui.SameLine(ImGui.GetWindowContentRegionMax().X - (width + 6));


            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBg));
            ImGui.PushStyleColor(ImGuiCol.Border, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBorder));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 1));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(1, 0));
            Vector2 popupBR = ImGui.GetCursorPos() + new Vector2(0, 150);
            if (ImGui.BeginChild(78789, size, true))
            {
                if (alerts.Length <= 2)
                {
                    for (var i = Math.Max(alerts.Length - 2, 0); i < alerts.Length; i++)
                    {
                        ImGui.Text(((TEXT_LOG_EVENT)alerts[i])._text);
                    }
                }
                else
                {
                    ImGui.Text($"{alerts.Length} Alerts");
                    ImGui.Text(((TEXT_LOG_EVENT)alerts[^1])._text);
                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByPopup))
            {
                if (ImGui.IsMouseClicked(ImGuiMouseButton.Left))
                {
                    //switch to the logs tab
                    _SwitchToLogsTab = true;
                    //select only the alerts filter
                    Array.Clear(_LogFilters, 0, _LogFilters.Length);
                    _LogFilters[(int)LogFilterType.TextAlert] = true;

                    Logging.ClearAlertsBox();
                }
                if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                {
                    Logging.ClearAlertsBox();
                }

                ImGui.SetNextWindowPos(new Vector2(popupBR.X, popupBR.Y));
                ImGui.OpenPopup("##AlertsCtx");

                if (ImGui.BeginPopup("##AlertsCtx"))
                {
                    if (ImGui.BeginTable("##AlertsCtxTbl", 2))
                    {
                        ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 60);
                        ImGui.TableSetupColumn("Event");
                        ImGui.TableHeadersRow();
                        foreach (LOG_EVENT log in alerts)
                        {
                            TEXT_LOG_EVENT msg = (TEXT_LOG_EVENT)log;
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeMilliseconds(msg.EventTimeMS);
                            string timeString = dateTimeOffset.ToString("HH:mm:ss:ff");
                            ImGui.Text(timeString);
                            ImGui.TableNextColumn();
                            ImGui.Text(msg._text);
                        }
                        ImGui.EndTable();
                    }
                    if (alertCount > alerts.Length)
                    {
                        ImGui.Text($"...and {alertCount - alerts.Length} more");
                    }
                    ImGui.Separator();
                    ImGui.Indent(5);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                    ImGui.Text($"Left click to view in logs tab. Right click to dismiss.");
                    ImGui.PopStyleColor();
                    ImGui.EndPopup();
                }
            }


            return true;
        }




        void HandleUserInput()
        {
            if (_UIstartupProgress < 1) return;
            if (_hexTooltipShown && _mouseWheelDelta != 0)
            {
                _hexTooltipScroll -= _mouseWheelDelta * 60;
                if (_hexTooltipScroll < 0) _hexTooltipScroll = 0;
                _mouseWheelDelta = 0;
                return;
            }

            bool currentTabVisualiser = _currentTab == "Visualiser";
            bool currentTabTimeline = _currentTab == "Timeline";
            bool MouseInMainWidget = MainGraphWidget != null && currentTabVisualiser && MainGraphWidget.MouseInWidget();
            lock (_inputLock)
            {

                if (_mouseWheelDelta != 0)
                {
                    if (MouseInMainWidget)
                    {
                        MainGraphWidget?.ApplyZoom(_mouseWheelDelta);
                    }
                    chart?.ApplyZoom(_mouseWheelDelta);
                    _mouseWheelDelta = 0;
                }



                if (_mouseDragDelta.X != 0 || _mouseDragDelta.Y != 0)
                {
                    if (ImGui.GetIO().KeyAlt)
                    {
                        if (MouseInMainWidget) MainGraphWidget.ApplyMouseRotate(_mouseDragDelta);
                    }
                    else
                    {
                        if (MouseInMainWidget)
                        {
                            MainGraphWidget.ApplyMouseDrag(_mouseDragDelta);
                        }
                        else if (currentTabTimeline)
                        {
                            chart.ApplyMouseDrag(_mouseDragDelta);
                        }
                    }

                    _mouseDragDelta = new Vector2(0, 0);
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


                    bool isKeybind = GlobalConfig.Keybinds.TryGetValue(KeyModifierTuple, out eKeybind boundAction);


                    if (isKeybind)
                    {
                        if (MainGraphWidget.QuickMenuActive &&
                            (boundAction == eKeybind.QuickMenu || boundAction == eKeybind.Cancel))
                        {
                            MainGraphWidget.AlertKeybindPressed(KeyModifierTuple, eKeybind.Cancel);
                            continue;
                        }
                        if (boundAction == eKeybind.Cancel)
                            CloseDialogs();
                    }

                    //could be a menu shortcut
                    if (MainGraphWidget.AlertRawKeyPress(KeyModifierTuple)) continue;

                    if (isKeybind)
                    {
                        if (currentTabVisualiser)
                        { MainGraphWidget.AlertKeybindPressed(KeyModifierTuple, boundAction); }
                        else if (currentTabTimeline)
                        { chart.AlertKeybindPressed(KeyModifierTuple, boundAction); }
                    }


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
            if (_rgatstate.DIELib == null)
            {
                ImGui.Text("Not Loaded");
                return;
            }
            DiELibDotNet.DieScript.SCANPROGRESS DEProgress = _rgatstate.DIELib.GetDIEScanProgress(activeTarget);
            ImGui.BeginGroup();
            {
                uint textColour = Themes.GetThemeColourImGui(ImGuiCol.Text);
                if (DEProgress.loading)
                {
                    SmallWidgets.ProgressBar("DieProgBar", $"Loading Scripts", 0, barSize, 0xff117711, 0xff111111);
                }
                else if (DEProgress.running)
                {
                    float dieProgress = (float)DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"DiE:{DEProgress.scriptsFinished}/{DEProgress.scriptCount}";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }
                else if (DEProgress.errored)
                {
                    float dieProgress = DEProgress.scriptCount == 0 ? 0f : (float)DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"Failed ({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    uint errorColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, errorColour, 0xff111111, textColour);
                }
                else if (DEProgress.StopRequestFlag)
                {
                    float dieProgress = (float)DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"Cancelled ({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    uint cancelColor = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, cancelColor, 0xff111111, 0xff000000);
                }
                else
                {
                    float dieProgress = (float)DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"DiE:({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111, textColour);
                }

                if (DEProgress.running)
                {
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text($"{DEProgress.scriptsFinished}/{DEProgress.scriptCount} DetectItEasy scripts have been run so far");
                        ImGui.Text($"Note that rgat does not use the original DiE codebase - the original may provide better results.");
                        ImGui.Separator();
                        ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                        ImGui.Text("Click To Cancel");
                        ImGui.PopStyleColor();
                        ImGui.EndTooltip();
                    }
                    if (ImGui.IsItemClicked())
                    {
                        _rgatstate.DIELib.CancelDIEScan(activeTarget);
                    }
                }
                else if (!DEProgress.running && !DEProgress.loading)
                {
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text($"{DEProgress.scriptsFinished} DetectItEasy scripts were executed out of {DEProgress.scriptCount} applicable");
                        ImGui.Text($"Note that rgat does not use the original DiE codebase - the original may provide better results.");
                        ImGui.Separator();
                        if (DEProgress.errored && DEProgress.error.Length > 0)
                        {
                            ImGui.Text(DEProgress.error);
                            ImGui.Separator();
                        }
                        ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                        ImGui.Text("Left Click  - Rescan");
                        ImGui.Text("Right Click - Reload & Rescan");
                        ImGui.PopStyleColor();
                        ImGui.EndTooltip();
                    }
                    if (_rgatstate.DIELib.ScriptsLoaded && ImGui.IsItemClicked(ImGuiMouseButton.Left))
                    {
                        _rgatstate.DIELib.StartDetectItEasyScan(activeTarget);
                    }
                    if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                    {
                        _rgatstate.DIELib.ReloadDIEScripts(GlobalConfig.DiESigsPath);
                        if (_rgatstate.DIELib.ScriptsLoaded)
                            _rgatstate.DIELib.StartDetectItEasyScan(activeTarget);
                    }
                }
                else if (DEProgress.loading)
                {
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text($"Detect It Easy scripts are being loaded. This should not take long.");
                        ImGui.EndTooltip();
                    }
                }
            }
            ImGui.EndGroup();
        }



        //YARA
        private void DrawYARAProgress(BinaryTarget activeTarget, Vector2 barSize)
        {
            if (_rgatstate.YARALib == null)
            {
                ImGui.Text("Not Loaded");
                return;
            }
            YARAScan.eYaraScanProgress progress = _rgatstate.YARALib.Progress(activeTarget);
            string caption;
            float progressAmount = 0;
            uint barColour = 0;
            switch (progress)
            {
                case YARAScan.eYaraScanProgress.eNotStarted:
                    caption = "YARA: No Scan";
                    break;
                case YARAScan.eYaraScanProgress.eComplete:
                    {
                        uint rulecount = _rgatstate.YARALib.LoadedRuleCount();
                        caption = $"YARA:{rulecount}/{rulecount}"; //wrong if reloaded?
                        barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eGoodStateColour);
                        progressAmount = 1;
                        break;
                    }
                case YARAScan.eYaraScanProgress.eFailed:
                    caption = "YARA: Error";
                    barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    progressAmount = 0;
                    break;
                case YARAScan.eYaraScanProgress.eRunning:
                    caption = "YARA: Scanning...";
                    barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eGoodStateColour);
                    progressAmount = 0.5f;
                    break;
                default:
                    barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    caption = "Bad State";
                    progressAmount = 0;
                    break;
            }

            SmallWidgets.ProgressBar("YaraProgBar", caption, progressAmount, barSize, barColour, 0xff111111);
            if (ImGui.IsItemHovered())
            {
                ImGui.BeginTooltip();
                ImGui.Text($"{caption} with {_rgatstate.YARALib.LoadedRuleCount()} loaded rules");
                ImGui.Separator();
                ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                ImGui.Text("Left Click  - Rescan");
                ImGui.Text("Right Click - Reload & Rescan");
                ImGui.PopStyleColor();
                ImGui.EndTooltip();
            }
            if (_rgatstate.YARALib.LoadedRuleCount() > 0 && ImGui.IsItemClicked(ImGuiMouseButton.Left))
            {
                _rgatstate.YARALib.StartYARATargetScan(activeTarget);
            }
            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
            {
                _rgatstate.YARALib.RefreshRules(forceRecompile: true);
                if (_rgatstate.YARALib.LoadedRuleCount() > 0)
                    _rgatstate.YARALib.StartYARATargetScan(activeTarget);
            }

        }


        private void DrawSignaturesBox(BinaryTarget activeTarget, float width)
        {
            if (ImGui.BeginTable("#SigHitsTable", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX, new Vector2(width, ImGui.GetContentRegionAvail().Y - 6)))
            {
                ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Rule", ImGuiTableColumnFlags.WidthFixed, width - 92);
                ImGui.TableHeadersRow();

                if (activeTarget.GetDieHits(out string[] diehits))
                {
                    foreach (string hit in diehits)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("DetectItEasy");
                        ImGui.TableNextColumn();
                        _ImGuiController.PushOriginalFont();
                        ImGui.AlignTextToFramePadding();
                        ImGui.Text(hit);
                        ImGui.PopFont();
                    }
                }

                if (activeTarget.GetYaraHits(out dnYara.ScanResult[] yarahits))
                {
                    foreach (dnYara.ScanResult hit in yarahits)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("YARA");
                        ImGui.TableNextColumn();
                        _ImGuiController.PushOriginalFont();
                        ImGui.AlignTextToFramePadding();
                        int strCount = hit.Matches.Values.Count;
                        string label = hit.MatchingRule.Identifier;
                        if (strCount > 0)
                        {
                            label += $" ({strCount} string{((strCount != 1) ? "s" : "")})";
                        }
                        ImGui.Text(label);
                        ImGui.PopFont();
                        if (ImGui.IsItemHovered())
                        {
                            DrawYaraTooltip(hit);
                        }
                    }
                }

                ImGui.EndTable();
            }
        }


        private void DrawYaraTooltip(dnYara.ScanResult hit)
        {
            ImGui.BeginTooltip();

            string idTags = "Rule: " + hit.MatchingRule.Identifier;

            foreach (string tag in hit.MatchingRule.Tags)
                idTags += $" [{tag}]";
            ImGui.Text(idTags);

            foreach (var kvp in hit.MatchingRule.Metas)
                ImGui.Text($"\"{kvp.Key}\": \"{kvp.Value}\"");

            if (hit.Matches.Count > 0)
            {
                if (ImGui.BeginTable("#YaraHitTablToolTip", 4, ImGuiTableFlags.Borders))
                {
                    ImGui.TableSetupColumn("String Name");
                    ImGui.TableSetupColumn("Offset");
                    ImGui.TableSetupColumn("Size");
                    ImGui.TableSetupColumn("Match Data");
                    ImGui.TableHeadersRow();

                    foreach (var matchList in hit.Matches)
                    {
                        foreach (var match in matchList.Value)
                        {
                            ImGui.TableNextRow();

                            ImGui.TableNextColumn();
                            ImGui.Text($"{matchList.Key}");

                            ImGui.TableNextColumn();
                            ImGui.Text($"0x{(match.Base + match.Offset):X}");

                            ImGui.TableNextColumn();
                            ImGui.Text($"{match.Data.Length}");

                            ImGui.TableNextColumn();

                            int maxlen = 16;
                            int previewLen = Math.Min(match.Data.Length, maxlen);
                            string strillus = "";
                            strillus += TextUtils.IllustrateASCIIBytesCompact(match.Data, previewLen);
                            if (previewLen < maxlen)
                                strillus += "...";
                            strillus += "  {";
                            strillus += BitConverter.ToString(match.Data, 0, previewLen).Replace("-", " ");
                            strillus += "}";

                            ImGui.Text($"{strillus}");
                        }
                    }
                    ImGui.EndTable();
                }

            }
            ImGui.EndTooltip();
        }


        private void DrawTraceTab_FileInfo(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginChildFrame(22, new Vector2(width, 300), ImGuiWindowFlags.AlwaysAutoResize);
            ImGui.BeginGroup();
            {
                if (ImGui.BeginTable("#BasicStaticFields", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX, ImGui.GetContentRegionAvail()))
                {
                    ImGui.TableSetupColumn("#FieldName", ImGuiTableColumnFlags.WidthFixed, 135);
                    ImGui.TableSetupColumn("#FieldValue", ImGuiTableColumnFlags.WidthFixed, width - 140);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Filename (Size)");
                    ImGui.TableNextColumn();
                    string fileStr = String.Format("{0} ({1})", activeTarget.FileName, activeTarget.GetFileSizeString());
                    byte[] _dataInput = Encoding.UTF8.GetBytes(fileStr);
                    ImGui.InputText("##filenameinp", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("SHA1 Hash");
                    ImGui.TableNextColumn();
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA1Hash());
                    ImGui.InputText("##s1hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("SHA256 Hash");
                    ImGui.TableNextColumn();
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA256Hash());
                    ImGui.InputText("##s256hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Hex Preview");
                    ImGui.TableNextColumn();
                    _hexTooltipShown = false;
                    _ImGuiController.PushOriginalFont(); //original imgui font is monospace and UTF8, good for this
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

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("ASCII Preview");
                    ImGui.TableNextColumn();
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



                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Signature Scan");
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 12);
                    DrawDetectItEasyProgress(activeTarget, new Vector2(120, 25));
                    DrawYARAProgress(activeTarget, new Vector2(120, 25));


                    ImGui.TableNextColumn();

                    DrawSignaturesBox(activeTarget, 530);

                    ImGui.EndTable();
                }
            }

            // ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();
        }

        float _hexTooltipScroll = 0;
        bool _hexTooltipShown;
        private void ShowHexPreviewTooltip(BinaryTarget target)
        {
            string hexline = target.HexTooltip();
            if (hexline != null)
            {
                ImGui.SetNextWindowSize(new Vector2(530, 300));
                ImGui.BeginTooltip();


                ImGuiInputTextFlags flags = ImGuiInputTextFlags.ReadOnly;
                flags |= ImGuiInputTextFlags.Multiline;
                flags |= ImGuiInputTextFlags.NoHorizontalScroll;
                ImGui.SetScrollY(_hexTooltipScroll);
                float BoxSize = Math.Max(ImGui.GetContentRegionAvail().Y, (hexline.Length / 4608f) * 845f);
                ImGui.InputTextMultiline("##inplin1", ref hexline, (uint)hexline.Length, new Vector2(530, BoxSize), flags);
                if (_hexTooltipScroll > ImGui.GetScrollMaxY())
                    _hexTooltipScroll = ImGui.GetScrollMaxY();

                ImGui.EndTooltip();
            }
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
        bool _diagnosticMode;
        private void DrawTraceTab_ExecutionSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF222200);
                ImGui.BeginChildFrame(10, new Vector2(width, 280));
                ImGui.Text("Execution Settings");

                ImGui.BeginChildFrame(18, new Vector2(width, 50));
                //ImGui.AlignTextToFramePadding();
                /*
                ImGui.Text("Instrumentation Engine: ");
                ImGui.SameLine();
                ImGui.RadioButton("Intel Pin", ref _selectedInstrumentationEngine, 0);
                ImGui.SameLine();
                ImGui.RadioButton("Qiling", ref _selectedInstrumentationEngine, 1);
                ImGui.SameLine();
                ImGui.RadioButton("IPT", ref _selectedInstrumentationEngine, 2);
                */
                ImGui.Text("Diagnostic Mode");
                ImGui.SameLine();
                if (SmallWidgets.ToggleButton("#DiagnosticModeTog", _diagnosticMode, "Will perform some diagnostic tests to see if pin can run on this"))
                {
                    _diagnosticMode = !_diagnosticMode;
                }

                ImGui.Text("Instrumentation Level: ");
                ImGui.SameLine();
                ImGui.RadioButton("Single Shot", ref _selectedInstrumentationLevel, 0);
                ImGui.SameLine();
                ImGui.RadioButton("Continuous", ref _selectedInstrumentationLevel, 1);
                ImGui.SameLine();
                ImGui.RadioButton("Data", ref _selectedInstrumentationLevel, 2);



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

                string pintoolpath = _rgatstate.ActiveTarget.BitWidth == 32 ? GlobalConfig.PinToolPath32 : GlobalConfig.PinToolPath64;

                if (ImGui.Button("Start Trace"))
                {
                    _WaitingNewTraceCount = _rgatstate.InstrumentationCount;
                    System.Diagnostics.Process p = ProcessLaunching.StartTracedProcess(pintoolpath, _rgatstate.ActiveTarget.FilePath);
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

                if (GlobalConfig.BadSigners(out List<Tuple<string, string>> issues))
                {
                    issues = issues.Where(i => (i.Item1 == pintoolpath || i.Item1 == GlobalConfig.PinPath)).ToList();
                    if (issues.Any())
                    {
                        //todo: be more specific on tooltip, but prevent a potential errordictionary reading race condition
                        ImGui.TextWrapped("Warning: One or more tracing binaries does not have a validated signature");
                        foreach (var issue in issues)
                        {
                            ImGui.TextWrapped($"    {Path.GetFileName(issue.Item1)}: {issue.Item2}");
                        }
                    }

                }
                ImGui.EndChildFrame();
                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }



        bool _splashHeaderHover = false;

        void DrawStartSplash()
        {
            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, Vector2.Zero);

            float regionHeight = ImGui.GetContentRegionAvail().Y;
            float regionWidth = ImGui.GetContentRegionAvail().X;
            float buttonBlockWidth = Math.Min(400f, regionWidth / 2.1f);
            float headerSize = regionHeight / 3;
            float blockHeight = (regionHeight * 0.95f) - headerSize;
            float blockStart = headerSize + 40f;


            if (_UIstartupProgress < 1)
            {
                float ypos = ImGui.GetCursorPosY();
                ImGui.ProgressBar((float)_UIstartupProgress, new Vector2(-1, 4f));
                ImGui.SetCursorPosY(ypos);
            }

            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0000ff);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0);

            bool boxBorders = false;

            if (ImGui.BeginChild("header", new Vector2(ImGui.GetContentRegionAvail().X, headerSize), boxBorders))
            {
                Texture settingsIcon = _ImGuiController.GetImage("Menu");
                GraphicsDevice gd = _ImGuiController.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(gd.ResourceFactory, settingsIcon, "SettingsIcon");

                ImGui.SetCursorPosX((regionWidth / 2) - 25);
                ImGui.SetCursorPosY((headerSize / 2) - 75);

                ImGui.BeginGroup();
                {
                    Vector2 cpb4 = ImGui.GetCursorPos();
                    ImGui.SetCursorPosY(cpb4.Y - ImGui.GetItemRectSize().Y);
                    ImGui.Image(CPUframeBufferTextureId, new Vector2(50, 50), Vector2.Zero, Vector2.One, Vector4.One);
                    ImGui.SetCursorPos(cpb4 - new Vector2(35, 15));
                    if (ImGui.Selectable("##SettingsDlg", false, ImGuiSelectableFlags.None, new Vector2(120, 120)))
                    {
                        if (_SettingsMenu != null)
                        {
                            _settings_window_shown = true;
                        }
                    }
                    if (ImGui.IsItemHovered(ImGuiHoveredFlags.None))
                    {
                        ImGui.SetTooltip("Open Settings Menu");
                    }
                    if (_splashHeaderHover)
                    {
                        ImGui.PushFont(_ImGuiController.SplashButtonFont); //todo destroy this font on leaving splash?
                        float textw = ImGui.CalcTextSize("Settings").X;
                        ImGui.SetCursorPosX(ImGui.GetCursorPosX() - (textw - 50) / 2);
                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 50);
                        ImGui.Text("Settings");
                        ImGui.PopFont();
                    }
                }
                ImGui.EndGroup();
                ImGui.EndChild();
            }
            _splashHeaderHover = ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByActiveItem | ImGuiHoveredFlags.AllowWhenBlockedByPopup);
            ImGui.PopStyleColor();

            //Run group
            float voidspace = Math.Max(0, (regionWidth - (2 * buttonBlockWidth)) / 3);
            float runGrpX = voidspace;
            float iconTableYSep = 18;

            ImGuiTableFlags tblflags = ImGuiTableFlags.NoHostExtendX;
            if (boxBorders) tblflags |= ImGuiTableFlags.Borders;

            ImGui.SetCursorPos(new Vector2(runGrpX, blockStart));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0);
            if (ImGui.BeginChild("##RunGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                Texture btnIcon = _ImGuiController.GetImage("Crosshair");
                GraphicsDevice gd = _ImGuiController.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(gd.ResourceFactory, btnIcon, "CrossHairIcon");

                //ImGui.BeginGroup();
                ImGui.PushFont(_ImGuiController.SplashButtonFont);
                float captionHeight = ImGui.CalcTextSize("Load Binary").Y;
                Vector2 iconsize = new Vector2(80, 80);
                ImGui.BeginTable("##LoadBinBtnBox", 3, tblflags);
                float iconColumnWidth = 200;
                float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                ImGui.TableSetupColumn("##BBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableSetupColumn("##LoadBinBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                ImGui.TableSetupColumn("##BBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(1);
                Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + iconsize.Y);
                if (ImGui.Selectable("##Load Binary", false, ImGuiSelectableFlags.None, selectableSize))
                {
                    _show_select_exe_window = true;
                }
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                ImguiUtils.DrawHorizCenteredText("Load Binary");
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (iconsize.X / 2));
                ImGui.Image(CPUframeBufferTextureId, iconsize, Vector2.Zero, Vector2.One, Vector4.One);
                ImGui.EndTable();
                ImGui.PopFont();
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);
                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                List<GlobalConfig.CachedPathData> recentBins = GlobalConfig.RecentBinaries;
                if (recentBins?.Count > 0)
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                    if (ImGui.BeginTable("#RecentBinTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                    {
                        ImGui.Indent(5);
                        ImGui.TableSetupColumn("Recent Binaries");
                        ImGui.TableSetupScrollFreeze(0, 1);
                        ImGui.TableHeadersRow();

                        foreach (var entry in recentBins)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            if (DrawRecentPathEntry(entry, false))
                            {
                                LoadSelectedBinary(entry.path);
                            }
                        }
                        ImGui.EndTable();
                    }
                    ImGui.PopStyleVar();
                }
                else
                {
                    if (GlobalConfig.LoadProgress < 1)
                    {
                        ImGui.ProgressBar((float)GlobalConfig.LoadProgress, new Vector2(300, 3));
                    }
                }
                ImGui.EndChild();
            }

            ImGui.SetCursorPosY(blockStart);
            ImGui.SetCursorPosX(runGrpX + buttonBlockWidth + voidspace);
            if (ImGui.BeginChild("##LoadGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                Texture btnIcon = _ImGuiController.GetImage("Crosshair");
                GraphicsDevice gd = _ImGuiController.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(gd.ResourceFactory, btnIcon, "LoadGrpIcon");

                //ImGui.BeginGroup();
                ImGui.PushFont(_ImGuiController.SplashButtonFont);
                float captionHeight = ImGui.CalcTextSize("Load Trace").Y;
                Vector2 iconsize = new Vector2(80, 80);
                ImGui.BeginTable("##LoadBtnBox", 3, tblflags);
                float iconColumnWidth = 200;
                float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                ImGui.TableSetupColumn("##LBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableSetupColumn("##LoadBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                ImGui.TableSetupColumn("##LBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(1);
                Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + iconsize.Y);
                if (ImGui.Selectable("##Load Trace", false, ImGuiSelectableFlags.None, selectableSize))
                {
                    _show_load_trace_window = true;
                }
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                ImguiUtils.DrawHorizCenteredText("Load Trace");
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (iconsize.X / 2));
                ImGui.Image(CPUframeBufferTextureId, iconsize, Vector2.Zero, Vector2.One, Vector4.One);
                ImGui.EndTable();
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);

                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                List<GlobalConfig.CachedPathData> recentTraces = GlobalConfig.RecentTraces;
                if (recentTraces?.Count > 0)
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                    if (ImGui.BeginTable("#RecentTraceTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                    {
                        ImGui.Indent(5);
                        ImGui.TableSetupColumn("Recent Traces");
                        ImGui.TableSetupScrollFreeze(0, 1);
                        ImGui.TableHeadersRow();

                        foreach (var entry in recentTraces)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            if (DrawRecentPathEntry(entry, false))
                            {
                                LoadTraceByPath(entry.path);
                            }
                        }
                        ImGui.EndTable();
                    }
                    ImGui.PopStyleVar();
                }
                else
                {
                    if (GlobalConfig.LoadProgress < 1)
                    {
                        ImGui.ProgressBar((float)GlobalConfig.LoadProgress, new Vector2(300, 3));
                    }
                }
                ImGui.EndChild();
            }

            ImGui.PopStyleVar(5);


            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(100, 40));
            if (ImGui.BeginChild("##SplashCorner", new Vector2(80, 35)))
            {



                if (ImGui.Selectable("rgat v0.6.0"))
                {
                    ToggleTestHarness();
                }

                ImGui.EndChild();
            }
            //String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁ф";
            //ImguiUtils.DrawRegionCenteredText(msg);
        }




        void ToggleTestHarness()
        {
            if (_show_test_harness == false)
            {
                if (_testHarness == null) _testHarness = new TestsWindow(_rgatstate, _ImGuiController);
            }
            _show_test_harness = !_show_test_harness;
        }

        bool DrawRecentPathEntry(GlobalConfig.CachedPathData pathdata, bool menu)
        {

            string path = pathdata.path;
            if (path.ToLower().EndsWith(".rgat"))
            {
                int dateIdx = path.LastIndexOf("__");
                if (dateIdx > 0)
                    path = path.Substring(0, dateIdx);
            }
            string agoText = $" ({pathdata.lastSeen.Humanize()})";
            if (ImGui.CalcTextSize(path + agoText).X > ImGui.GetContentRegionAvail().X)
            {
                if (path.Length > 50)
                    path = path.Truncate(50, "...", TruncateFrom.Left);
            }

            if (menu)
            {
                if (ImGui.MenuItem(path + agoText))
                {
                    return true;
                }
            }
            else
            {
                ImGui.Selectable(path + agoText);
            }
            if (ImGui.IsItemHovered())
            {
                if (ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
                {
                    return true;
                }
                ImGui.BeginTooltip();
                ImGui.Text($"{pathdata.path}");
                ImGui.Text($"Most recently opened {pathdata.lastSeen.Humanize()}");
                ImGui.Text($"First opened {pathdata.lastSeen.Humanize()}");
                ImGui.Text($"Has been loaded {pathdata.count} times.");
                ImGui.EndTooltip();
            }
            return false;
        }


        private void DrawTraceTab(BinaryTarget activeTarget)
        {
            if (ImGui.BeginTabItem("Start Trace"))
            {
                _currentTab = "Start Trace";
                DrawTraceTab_FileInfo(activeTarget, ImGui.GetContentRegionAvail().X);

                ImGui.BeginGroup();
                {
                    DrawTraceTab_InstrumentationSettings(activeTarget, 400);
                    ImGui.SameLine();
                    DrawTraceTab_ExecutionSettings(ImGui.GetContentRegionAvail().X);
                    ImGui.EndGroup();
                }
                ImGui.EndTabItem();
            }
            else
            {
                _hexTooltipShown = false;
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




        float sliderPosX = -1;

        private unsafe void DrawReplaySlider(float width, float height)
        {
            Vector2 progressBarSize = new Vector2(width, height);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));
            ImGui.PushStyleColor(ImGuiCol.Button, 0xff00ffff);
            ImGui.InvisibleButton("##ReplayProgressBtn", progressBarSize);
            ImGui.PopStyleColor();
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - progressBarSize.Y);
            ImGui.PopStyleVar();

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

            Vector2 SliderArrowDrawPos = new Vector2(AnimationProgressBarPos.X + sliderPosX, AnimationProgressBarPos.Y - 4);
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


            ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 0);
            _visualiserBar.GenerateReplay(progressBarSize.X, height, _rgatstate.ActiveGraph.InternalProtoGraph); //todo remove from ui thread
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

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF000000);

            if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(width, otherControlsHeight)))
            {
                //DrawReplaySlider(width: width, height: 50);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);

                ImGui.BeginGroup();
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x77889900);
                    if (ImGui.BeginChild("ctrls2354", new Vector2(600, 110)))
                    {
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
                            if (ImGui.Button(bt, new Vector2(66, 36)))
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
                    ImGui.PopStyleColor();
                }
                ImGui.EndGroup();
                ImGui.SameLine();
                //ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 8);
                DrawDiasmPreviewBox(activeGraph.InternalProtoGraph, activeGraph.AnimationIndex);

                ImGui.EndChild();
            }

            ImGui.PopStyleColor();
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

                if (lastAnimIdx >= 0 && lastAnimIdx > graph.SavedAnimationData.Count)
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
                                    List<InstructionData> inslist = graph.ProcessData.getDisassemblyBlock(blockID: blkID);

                                    for (var i = Math.Max(0, inslist.Count - 5); i < inslist.Count; i++)
                                    {
                                        ImGui.Text(inslist[i].ins_text);
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
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF808022);

            float replayControlsSize = ImGui.GetContentRegionAvail().X;
            if (ImGui.BeginChild(ImGui.GetID("LiveControls"), new Vector2(replayControlsSize, otherControlsHeight)))
            {

                //_visualiserBar.GenerateLive(width, 50, _rgatstate.ActiveGraph.InternalProtoGraph);
                //_visualiserBar.Draw();

                ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX() + 6, ImGui.GetCursorPosY() + 6));

                if (ImGui.BeginChild("RenderingBox"))
                {
                    ImGui.SetCursorPos(new Vector2(ImGui.GetCursorPosX(), ImGui.GetCursorPosY() + 6));
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x77889900);
                    if (ImGui.BeginChild("LiveTraceCtrls", new Vector2(600, 110)))
                    {

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

                        ImGui.BeginGroup();
                        if (ImGui.Button("Kill"))
                        {
                            graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "EXIT");
                        }
                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("Terminate the process");

                        ImGui.SameLine();

                        if (ImGui.Button("Kill All")) Console.WriteLine("Kill All clicked");

                        ImGui.EndGroup();

                        ImGui.NextColumn();

                        ImGui.BeginGroup();

                        if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eRunning)
                        {
                            if (ImGui.Button("Pause/Break"))
                            {
                                graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "BRK");
                            }
                            if (ImGui.IsItemHovered())
                                ImGui.SetTooltip("Pause all process threads");
                        }

                        if (graph.InternalProtoGraph.TraceData.TraceState == TraceRecord.eTraceState.eSuspended)
                        {
                            if (ImGui.Button("Continue"))
                            {
                                graph.InternalProtoGraph.TraceData.SendDebugCommand(0, "CTU");
                            }
                            if (ImGui.IsItemHovered())
                                ImGui.SetTooltip("Resume all process threads");

                            if (ImGui.Button("Step In"))
                            {
                                graph.InternalProtoGraph.TraceData.SendDebugStep(graph.tid);
                            }
                            if (ImGui.IsItemHovered())
                                ImGui.SetTooltip("Step to next instruction");

                            if (ImGui.Button("Step Over"))
                            {
                                graph.InternalProtoGraph.TraceData.SendDebugStepOver(graph.InternalProtoGraph);
                            }
                            if (ImGui.IsItemHovered())
                                ImGui.SetTooltip("Step past call instruction");
                        }

                        ImGui.EndGroup();
                        ImGui.Columns(1);
                        ImGui.EndChild();
                        ImGui.PopStyleColor();
                    }
                    ImGui.SameLine();
                    DrawDiasmPreviewBox(graph.InternalProtoGraph, graph.InternalProtoGraph.SavedAnimationData.Count - 1);


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

            PlottedGraph plot = _rgatstate.ActiveGraph;
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

                if (_rgatstate.ActiveTarget != null)
                {
                    var tracelist = _rgatstate.ActiveTarget.GetTracesUIList();
                    string selString = "PID " + graph.TraceData.PID;
                    if (ImGui.BeginCombo($"{tracelist.Count} Process{(tracelist.Count != 1 ? "es" : "")}", selString))
                    {
                        foreach (var timepid in tracelist)
                        {
                            TraceRecord selectableTrace = timepid.Item2;
                            if (ImGui.Selectable("PID " + selectableTrace.PID, graph.TraceData.PID == selectableTrace.PID))
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
                        selString = "TID " + graph.ThreadID;
                        List<PlottedGraph> graphs = _rgatstate.ActiveTrace.GetPlottedGraphs(eRenderingMode.eStandardControlFlow);
                        if (ImGui.BeginCombo($"{graphs.Count} Thread{(graphs.Count != 1 ? "s" : "")}", selString))
                        {
                            foreach (PlottedGraph selectablegraph in graphs)
                            {
                                string caption = "TID " + selectablegraph.tid;
                                int nodeCount = selectablegraph.GraphNodeCount();
                                if (nodeCount == 0)
                                {
                                    caption += " [Uninstrumented]";
                                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                                }
                                else
                                {
                                    caption += $" [{nodeCount} nodes]";
                                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                                }
                                if (ImGui.Selectable(caption, graph.ThreadID == selectablegraph.tid))
                                {
                                    SetActiveGraph(selectablegraph);
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
                    ImGui.Text($"Edges: {graph.EdgeList.Count}");
                    ImGui.Text($"Nodes: {graph.NodeList.Count}");
                    ImGui.Text($"Updates: {graph.SavedAnimationData.Count}");
                    ImGui.Text($"Instructions: {graph.TotalInstructions}");

                    ImGui.EndChild();
                }

                ImGui.NextColumn();

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

                    ThreadTraceProcessingThread traceProcessor = graph.TraceProcessor;
                    string BrQlab = $"{traceProcessor.PendingBlockRepeats}";
                    if (traceProcessor.PendingBlockRepeats > 0)
                    {
                        BrQlab += $" {traceProcessor.LastBlockRepeatsTime}";
                    }
                    ImGui.Text($"BRepQu: {BrQlab}");


                    if (_UIDrawFPS >= 100)
                    {
                        ImGui.Text($"UI FPS: 100+");
                    }
                    else
                    {
                        uint fpscol;
                        if (_UIDrawFPS >= 40)
                            fpscol = Themes.GetThemeColourImGui(ImGuiCol.Text);
                        else if (_UIDrawFPS < 40 && _UIDrawFPS >= 10)
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                        else
                            fpscol = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);

                        ImGui.PushStyleColor(ImGuiCol.Text, fpscol);
                        ImGui.Text($"UI FPS: {_UIDrawFPS:0.#}");
                        ImGui.PopStyleColor();
                    }
                    SmallWidgets.MouseoverText($"How many frames the UI can render in one second (Last 10 Avg MS: {_lastFrameTimeMS.Average()})");

                    ImGui.Text($"Layout MS: {MainGraphWidget.LayoutEngine.AverageComputeTime:0.#}");
                    SmallWidgets.MouseoverText("How long it takes to complete a step of graph layout");
                    //ImGui.Text($"AllocMem: {_ImGuiController.graphicsDevice.MemoryManager._totalAllocatedBytes}");

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
                    ImguiUtils.DrawRegionCenteredText(caption);
                    ImGui.Text($"temp: {_rgatstate.ActiveGraph?.temperature}");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                return;
            }
            float topControlsBarHeight = 30;
            float otherControlsHeight = controlsHeight - topControlsBarHeight;
            float frameHeight = otherControlsHeight - vpadding;
            float controlsWidth = ImGui.GetContentRegionAvail().X;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFFf0f000);
            if (ImGui.BeginChild(ImGui.GetID("ControlsOther"), new Vector2(controlsWidth, frameHeight)))
            {
                PlottedGraph activeGraph = _rgatstate.ActiveGraph;
                if (activeGraph != null)
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF00ff00);
                    if (ImGui.BeginChild("ControlsInner", new Vector2(controlsWidth - UI_Constants.PREVIEW_PANE_WIDTH, frameHeight)))
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
                    ImGui.PopStyleColor();
                }
                ImGui.SameLine();
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
            if (MainGraphWidget != null && PreviewGraphWidget != null)
            {
                ManageActiveGraph();

                float controlsHeight = 230;

                DrawVisualiserGraphs((ImGui.GetWindowContentRegionMax().Y - 13) - controlsHeight);
                DrawVisualiserControls(controlsHeight);
            }
            ImGui.EndTabItem();
        }


        SandboxChart chart = new SandboxChart();
        private void DrawAnalysisTab(TraceRecord activeTrace)
        {

            if (activeTrace == null || !ImGui.BeginTabItem("Timeline")) return;
            _currentTab = "Timeline";


            float height = ImGui.GetContentRegionAvail().Y;
            float width = ImGui.GetContentRegionAvail().X;
            float sidePaneWidth = 300;

            if (height < 50 || width < 50)
            {

                ImGui.EndTabItem();
                return;
            }

            chart.InitChartFromTrace(activeTrace);


            SandboxChart.itemNode selectedNode = chart.GetSelectedNode;
            if (ImGui.BeginTable("#TaTTable", 3, ImGuiTableFlags.Resizable))
            {
                ImGui.TableSetupColumn("#TaTTEntryList", ImGuiTableColumnFlags.None, sidePaneWidth);
                ImGui.TableSetupColumn("#TaTTChart", ImGuiTableColumnFlags.NoDirectResize, width - 2 * sidePaneWidth);
                ImGui.TableSetupColumn("#TaTTControlsFocus", ImGuiTableColumnFlags.NoDirectResize, sidePaneWidth);

                ImGui.TableNextRow();

                ImGui.TableNextColumn();
                //ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff99ff77);
                ImGui.Text("Full Listing");


                TIMELINE_EVENT[] events = activeTrace.GetTimeLineEntries();
                if (ImGui.BeginTable("#TaTTFullList", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY))
                {
                    ImGui.TableSetupColumn("#", ImGuiTableColumnFlags.WidthFixed, 50);
                    ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthFixed, 90);
                    ImGui.TableSetupColumn("Details", ImGuiTableColumnFlags.None);
                    ImGui.TableHeadersRow();
                    ImGui.TableSetupScrollFreeze(0, 1);

                    int i = 0;
                    foreach (TIMELINE_EVENT TLevent in events)
                    {
                        i += 1;
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        bool selected = false;
                        if (selectedNode != null)
                        {
                            switch (TLevent.TimelineEventType)
                            {
                                case eTimelineEvent.ProcessStart:
                                case eTimelineEvent.ProcessEnd:
                                    selected = (Equals(selectedNode.reference.GetType(), typeof(TraceRecord)) &&
                                        TLevent.ID == ((TraceRecord)selectedNode.reference).PID);
                                    break;
                                case eTimelineEvent.ThreadStart:
                                case eTimelineEvent.ThreadEnd:
                                    selected = (Equals(selectedNode.reference.GetType(), typeof(ProtoGraph)) &&
                                        TLevent.ID == ((ProtoGraph)selectedNode.reference).ThreadID);
                                    break;
                            }
                        }
                        if (ImGui.Selectable(i.ToString(), selected, ImGuiSelectableFlags.SpanAllColumns) && !selected)
                        {
                            chart.SelectEventNode(TLevent);
                        }
                        ImGui.TableNextColumn();
                        ImGui.Text(TLevent.TimelineEventType.ToString());
                        ImGui.TableNextColumn();
                        ImGui.Text(TLevent.Label());

                    }
                    ImGui.EndTable();

                }


                ImGui.TableNextColumn();
                ImGui.Text("Sandbox View");

                chart.Draw();

                ImGui.TableNextColumn();
                float tr_height = (height / 2) - 4;
                float tb_height = (height / 2) - 4;
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x5f88705f);
                if (ImGui.BeginChild("#SandboxTabtopRightPane", new Vector2(sidePaneWidth, tr_height)))
                {

                    ImGui.Text("Filters");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();

                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x8f48009f);
                if (ImGui.BeginChild("#SandboxTabbaseRightPane", new Vector2(sidePaneWidth, tb_height)))
                {

                    if (selectedNode != null)
                    {
                        switch (selectedNode.TLtype)
                        {
                            case eTimelineEvent.ProcessStart:
                                DrawProcessNodeTable((TraceRecord)selectedNode.reference);
                                break;

                            case eTimelineEvent.ThreadStart:
                                DrawThreadNodeTable((ProtoGraph)selectedNode.reference);
                                break;

                            case eTimelineEvent.APICall:
                                ImGui.Text("Api call (not handled yet)");
                                break;
                            default:
                                ImGui.Text($"We don't do {selectedNode.TLtype} here");
                                break;
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();

                ImGui.EndTable();
            }

            ImGui.EndTabItem();
        }

        void DrawProcessNodeTable(TraceRecord trace)
        {
            if (ImGui.BeginTable("#ProcSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Process ID");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.PID}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Path");
                ImGui.TableNextColumn();
                ImGui.TextWrapped($"{trace.binaryTarg.FilePath}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"State");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.TraceState}");
                ImGui.TableNextColumn();

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Started");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.launchedTime.ToLocalTime()}");
                ImGui.EndTable();
            }
        }


        void DrawThreadNodeTable(ProtoGraph thread)
        {
            if (ImGui.BeginTable("#ThreadSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Thread ID");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.ThreadID}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Started");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.ConstructedTime}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Terminated");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.Terminated}");
                ImGui.TableNextColumn();

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Instructions");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.TotalInstructions}");

                ImGui.EndTable();
            }
        }

        private void DrawMemDataTab()
        {
            if (ImGui.BeginTabItem("Memory Activity"))
            {
                ImGui.Text("Memory data stuff here");
                ImGui.EndTabItem();
            }
        }


        static bool[] _LogFilters = new bool[(int)LogFilterType.COUNT];
        static bool[] rowLastSelected = new bool[3];
        static byte[] textFilterValue = new byte[500];
        static string _logSort = "Time<";
        private void DrawLogsTab()
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("logtableframe"), ImGui.GetContentRegionAvail()))
            {
                Logging.LOG_EVENT[] msgs = Logging.GetLogMessages(null, _LogFilters);
                int activeCount = _LogFilters.Where(x => x == true).Count();

                string label = $"{msgs.Length} log entries displayed from ({activeCount}/{_LogFilters.Length}) sources";
                bool isOpen = ImGui.TreeNode("##FiltersTree", label);
                if (isOpen)
                {
                    Vector2 boxSize = new Vector2(75, 40);
                    Vector2 marginSize = new Vector2(70, 40);

                    ImGuiSelectableFlags flags = ImGuiSelectableFlags.DontClosePopups;
                    uint tableHdrBG = 0xff333333;


                    var textFilterCounts = Logging.GetTextFilterCounts();
                    var timelineCounts = _rgatstate.ActiveTrace?.GetTimeLineFilterCounts();

                    if (ImGui.BeginTable("LogFilterTable", 7, ImGuiTableFlags.Borders, new Vector2(boxSize.X * 7, 100)))
                    {
                        ImGui.TableNextRow();

                        ImGui.TableSetColumnIndex(0);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                        if (ImGui.Selectable("Message", false, flags, marginSize))
                        {
                            rowLastSelected[0] = !rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextDebug] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextInfo] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextAlert] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextError] = rowLastSelected[0];
                        }


                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Debug ({textFilterCounts[LogFilterType.TextDebug]})",
                            ref _LogFilters[(int)LogFilterType.TextDebug], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Info ({textFilterCounts[LogFilterType.TextInfo]})",
                            ref _LogFilters[(int)LogFilterType.TextInfo], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Alert ({textFilterCounts[LogFilterType.TextAlert]})",
                            ref _LogFilters[(int)LogFilterType.TextAlert], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Error ({textFilterCounts[LogFilterType.TextError]})",
                            ref _LogFilters[(int)LogFilterType.TextError], flags, boxSize);

                        if (timelineCounts != null)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableSetColumnIndex(0);
                            ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                            if (ImGui.Selectable("Timeline", false, flags, marginSize))
                            {
                                rowLastSelected[1] = !rowLastSelected[1];
                                _LogFilters[(int)LogFilterType.TimelineProcess] = rowLastSelected[1];
                                _LogFilters[(int)LogFilterType.TimelineThread] = rowLastSelected[1];
                            }
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Process ({timelineCounts[LogFilterType.TimelineProcess]})",
                                ref _LogFilters[(int)LogFilterType.TimelineProcess], flags, boxSize);

                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Thread ({timelineCounts[LogFilterType.TimelineThread]})",
                                ref _LogFilters[(int)LogFilterType.TimelineThread], flags, boxSize);

                            ImGui.TableNextRow();
                            ImGui.TableSetColumnIndex(0);
                            ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                            if (ImGui.Selectable("API", false, flags, marginSize))
                            {
                                rowLastSelected[2] = !rowLastSelected[2];
                                _LogFilters[(int)LogFilterType.APIFile] = rowLastSelected[2];
                                _LogFilters[(int)LogFilterType.APINetwork] = rowLastSelected[2];
                                _LogFilters[(int)LogFilterType.APIReg] = rowLastSelected[2];
                                _LogFilters[(int)LogFilterType.APIProcess] = rowLastSelected[2];
                                _LogFilters[(int)LogFilterType.APIOther] = rowLastSelected[2];
                            }


                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Data ({timelineCounts[LogFilterType.APIAlgos]})",
                                ref _LogFilters[(int)LogFilterType.APIAlgos], flags, boxSize);
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"File ({timelineCounts[LogFilterType.APIFile]})",
                                ref _LogFilters[(int)LogFilterType.APIFile], flags, boxSize);
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Network ({timelineCounts[LogFilterType.APINetwork]})",
                                ref _LogFilters[(int)LogFilterType.APINetwork], flags, boxSize);
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Process ({timelineCounts[LogFilterType.APIProcess]})",
                                ref _LogFilters[(int)LogFilterType.APIProcess], flags, boxSize);
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Registry ({timelineCounts[LogFilterType.APIReg]})",
                                ref _LogFilters[(int)LogFilterType.APIReg], flags, boxSize);
                            ImGui.TableNextColumn();
                            ImGui.Selectable($"Other ({timelineCounts[LogFilterType.APIOther]})",
                                ref _LogFilters[(int)LogFilterType.APIOther], flags, boxSize);

                        }
                        ImGui.EndTable();
                    }

                    if (ImGui.BeginPopupContextItem("FlterTableRightCtx", ImGuiPopupFlags.MouseButtonRight))
                    {
                        if (ImGui.MenuItem("Clear All Source Filters"))
                        {
                            Array.Clear(_LogFilters, 0, _LogFilters.Length);
                        }
                        if (ImGui.MenuItem("Apply All Source Filters"))
                        {
                            _LogFilters = Enumerable.Repeat(true, _LogFilters.Length).ToArray();
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



                List<LOG_EVENT> shownMsgs = new List<LOG_EVENT>(msgs);
                bool TlProcessShown = _LogFilters[(int)Logging.LogFilterType.TimelineProcess];
                bool TlThreadShown = _LogFilters[(int)Logging.LogFilterType.TimelineThread];
                if (_LogFilters.Any(f => f == true))
                {
                    var TLmsgs = _rgatstate.ActiveTrace?.GetTimeLineEntries();
                    foreach (TIMELINE_EVENT ev in TLmsgs)
                    {
                        if (_LogFilters[(int)ev.Filter])
                            shownMsgs.Add(ev);
                    }
                }

                List<LOG_EVENT> sortedMsgs = shownMsgs;

                int filterLen = Array.FindIndex(textFilterValue, x => x == '\0');
                string textFilterString = Encoding.ASCII.GetString(textFilterValue, 0, filterLen);

                ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.Sortable | ImGuiTableFlags.SortMulti;
                if (ImGui.BeginTable("LogsTable", 3, tableFlags, ImGui.GetContentRegionAvail()))
                {
                    var ss = ImGui.TableGetSortSpecs();
                    //if (ss.SpecsDirty) //todo - caching
                    {
                        switch (ss.Specs.ColumnIndex)
                        {
                            case 0:
                                if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                                    sortedMsgs = shownMsgs.OrderBy(o => o.EventTimeMS).ToList();
                                else
                                    sortedMsgs = shownMsgs.OrderByDescending(o => o.EventTimeMS).ToList();
                                break;
                            case 1:
                                if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                                    sortedMsgs = shownMsgs.OrderBy(o => o.Filter).ToList();
                                else
                                    sortedMsgs = shownMsgs.OrderByDescending(o => o.Filter).ToList();
                                break;
                            case 2:
                                //todo - caching
                                break;
                        }
                        ss.SpecsDirty = false;
                    }

                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 90);
                    ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 100);
                    ImGui.TableSetupColumn("Details");
                    ImGui.TableHeadersRow();

                    foreach (LOG_EVENT msg in sortedMsgs)
                    {
                        DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeMilliseconds(msg.EventTimeMS);
                        string timeString = dateTimeOffset.ToString("HH:mm:ss:ff");

                        string msgString;
                        string sourceString;
                        switch (msg.LogType)
                        {
                            case eLogType.Text:
                                {
                                    Logging.TEXT_LOG_EVENT text_evt = (Logging.TEXT_LOG_EVENT)msg;
                                    sourceString = $"{msg.LogType} - {text_evt._filter}";
                                    msgString = text_evt._text;
                                    break;
                                }

                            case eLogType.TimeLine:
                                {
                                    Logging.TIMELINE_EVENT tl_evt = (Logging.TIMELINE_EVENT)msg;
                                    sourceString = $"{tl_evt.Filter}";
                                    msgString = tl_evt.Label();
                                    break;
                                }
                            default:
                                sourceString = "";
                                msgString = "Other event type " + msg.LogType.ToString();
                                break;

                        }



                        if (filterLen > 0)
                        {
                            if (!msgString.Contains(textFilterString) &&
                                !sourceString.Contains(textFilterString) &&
                                !timeString.Contains(textFilterString))
                                continue;
                        }

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text(timeString);
                        ImGui.TableNextColumn();
                        ImGui.Text(sourceString);
                        ImGui.TableNextColumn();
                        ImGui.TextWrapped(msgString);
                    }
                    ImGui.EndTable(); ;
                }
                ImGui.EndChildFrame();
            }
            ImGui.EndTabItem();
        }


        private unsafe void DrawMainMenu()
        {
            if (ImGui.BeginMenuBar())
            {
                if (ImGui.BeginMenu("Target"))
                {
                    if (ImGui.MenuItem("Select Target Executable")) { _show_select_exe_window = true; }
                    var recentbins = GlobalConfig.RecentBinaries;
                    if (ImGui.BeginMenu("Recent Binaries", recentbins.Any()))
                    {
                        foreach (var entry in recentbins.Take(Math.Min(10, recentbins.Count)))
                        {
                            if (DrawRecentPathEntry(entry, true)) LoadSelectedBinary(entry.path);
                        }
                        ImGui.EndMenu();
                    }
                    var recenttraces = GlobalConfig.RecentTraces;
                    if (ImGui.BeginMenu("Recent Traces", recenttraces.Any()))
                    {
                        foreach (var entry in recenttraces.Take(Math.Min(10, recenttraces.Count)))
                        {
                            if (DrawRecentPathEntry(entry, true)) LoadTraceByPath(entry.path);
                        }
                        ImGui.EndMenu();
                    }
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
                ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X - 30);
                bool isShown = _show_test_harness;
                if (ImGui.MenuItem("Tests", null, ref isShown, true))
                {
                    ToggleTestHarness();
                }
                ImGui.EndMenuBar();
            }
        }

        /// <summary>
        /// Draws a dropdown allowing selection of one of the loaded target binaries
        /// </summary>
        /// <returns>true if at least one binary is loaded, otherwise false</returns>
        private unsafe bool DrawTargetBar()
        {

            if (_rgatstate.targets.count() == 0)
            {
                ImGui.Text("No target selected or trace loaded");
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                return false;
            }

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            //there shouldn't actually be a way to select a null target once one is loaded
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
            return true;
        }

        bool _SwitchToLogsTab = false;
        bool _SwitchToVisualiserTab = false;
        int _WaitingNewTraceCount = -1;
        string _currentTab = "";

        private unsafe void DrawTabs()
        {
            bool tabDrawn = false;
            ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;

            if (_WaitingNewTraceCount != -1 && _rgatstate.InstrumentationCount > _WaitingNewTraceCount)
            {
                _WaitingNewTraceCount = -1;
                _SwitchToVisualiserTab = true;
                MainGraphWidget.SetActiveGraph(null);
                PreviewGraphWidget.SetActiveTrace(null);
                _rgatstate.SelectActiveTrace(newest: true);
            }

            if (ImGui.BeginTabBar("Primary Tab Bar", tab_bar_flags))
            {
                DrawTraceTab(_rgatstate.ActiveTarget);

                //is there a better way to do this?
                if (_SwitchToVisualiserTab)
                {
                    tabDrawn = ImGui.BeginTabItem("Visualiser", ref tabDrawn, ImGuiTabItemFlags.SetSelected);
                    _SwitchToVisualiserTab = false;
                }
                else
                    tabDrawn = ImGui.BeginTabItem("Visualiser");
                if (tabDrawn)
                {
                    _currentTab = "Visualiser";
                    DrawVisTab();
                }


                DrawAnalysisTab(_rgatstate.ActiveTrace);


                DrawMemDataTab();


                if (_SwitchToLogsTab)
                {
                    tabDrawn = ImGui.BeginTabItem("Logs", ref tabDrawn, ImGuiTabItemFlags.SetSelected);
                    _SwitchToLogsTab = false;
                }
                else
                    tabDrawn = ImGui.BeginTabItem("Logs");
                if (tabDrawn)
                {
                    _currentTab = "Logs";
                    DrawLogsTab();
                }

                ImGui.EndTabBar();
            }

        }

        bool LoadSelectedBinary(string path)
        {
            if (!File.Exists(path)) return false;
            FileStream fs = File.OpenRead(path);
            bool isJSON = (fs.ReadByte() == '{' && fs.ReadByte() == '"');
            fs.Close();
            if (isJSON)
            {
                Console.WriteLine("JSON detected, attempting to load file as saved trace instead");
                LoadTraceByPath(path);
            }
            else
            {
                GlobalConfig.RecordRecentPath(path, GlobalConfig.eRecentPathType.Binary);
                _rgatstate.AddTargetByPath(path);
            }
            return true;
        }

        private unsafe void DrawFileSelectBox()
        {
            ImGui.OpenPopup("Select Executable");

            if (ImGui.BeginPopupModal("Select Executable", ref _show_select_exe_window, ImGuiWindowFlags.NoScrollbar))
            {

                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue && LoadSelectedBinary(picker.SelectedFile))
                    {
                        rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    }
                    _show_select_exe_window = false;
                }

                ImGui.EndPopup();
            }
        }

        private void LoadTraceByPath(string filepath)
        {
            GlobalConfig.RecordRecentPath(filepath, GlobalConfig.eRecentPathType.Trace);
            if (!_rgatstate.LoadTraceByPath(filepath, out TraceRecord trace)) return;

            BinaryTarget target = trace.binaryTarg;

            //todo only if signatures not stored in trace + file exists on disk
            _rgatstate.DIELib?.StartDetectItEasyScan(target);
            _rgatstate.YARALib?.StartYARATargetScan(target);

            launch_all_trace_threads(trace, _rgatstate);

            _rgatstate.ActiveTarget = target;
            _rgatstate.SelectActiveTrace(target.GetFirstTrace());

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

            if (ImGui.BeginPopupModal("Select Trace File", ref _show_load_trace_window, ImGuiWindowFlags.NoScrollbar))
            {
                string savedir = GlobalConfig.TraceSaveDirectory;
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
        public bool IsResponsive;
    }
}
