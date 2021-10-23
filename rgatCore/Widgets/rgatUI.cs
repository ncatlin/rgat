using Humanizer;
using ImGuiNET;
using rgat.Config;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.Logging;

namespace rgat
{
    internal partial class rgatUI
    {
        //all-modes state
        private readonly rgatState _rgatState;

        private static ImGuiController? _controller;
        public static ImGuiController Controller { get => _controller!; set => _controller = value; }

        //hardware resources
        private readonly GraphicsDevice _gd;


        //widgets
        private SandboxChart? chart;
        private VisualiserTab? visualiserTab;
        private SplashScreenRenderer? _splashRenderer;

        //dialogs
        private RemoteDialog? _RemoteDialog;
        private TestsWindow? _testHarness;
        private SettingsMenu? _SettingsMenu;
        private readonly LogsWindow? _logsWindow;

        /// <summary>
        /// Causes the UI to fall out of the update loop and initiate rgat shutdown
        /// </summary>
        public bool ExitFlag = false;


        private bool _show_settings_window = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private bool _show_tracelist_selection_window = false;
        private bool _show_test_harness = false;
        private bool _show_logs_window = false;
        private bool _show_remote_dialog = false;
        public static bool ShowStatsDialog { get; private set; } = false;

        private static double _StartupProgress = 0;
        public static double StartupProgress
        {
            get => _StartupProgress; 
            set
            {
                Debug.Assert(value <= 1);
                if (_StartupProgress < 1)
                {
                    _StartupProgress = value;
                }
            }
        }


        public static double UIDrawFPS = 0;
        private List<double> _lastFrameTimeMS = new List<double>();
        private readonly List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        private float _mouseWheelDelta = 0;
        private Vector2 _mouseDragDelta = new Vector2(0, 0);
        private Vector2 _mousePos = new Vector2(0, 0);

        private static bool DialogOpen => Controller.DialogOpen;
        public bool MenuBarVisible => (rgatState.ActiveTarget is not null ||
            _splashHeaderHover ||
            LogsWindow.RecentAlert() ||
            DialogOpen ||
            (DateTime.Now - _lastNotification).TotalMilliseconds < 500);

        private bool _splashHeaderHover = false;
        private DateTime _lastNotification = DateTime.MinValue;

        public static bool ResponsiveKeyHeld = false;

        /// <summary>
        /// Tells the UI that something is happening on the menu bar so it should be displayed
        /// Currently its always displayed except on the splash screen
        /// </summary>
        private void ActivateNotification() => _lastNotification = DateTime.Now;

        private bool _scheduleMissingPathCheck = true;

        public VideoEncoder.CaptureContent PendingScreenshot { get; private set; } = VideoEncoder.CaptureContent.Invalid;

        private VideoEncoder.CaptureContent _lastScreenShot = VideoEncoder.CaptureContent.Invalid;
        private string _lastScreenShotPath = "";
        private DateTime _screenShotTime;


        private readonly object _inputLock = new object();

        /// <summary>
        /// rgat will exit when convenient
        /// This is only handled by the UI runner
        /// </summary>
        public static bool ExitRequested { get; private set; } = false;
        public static void RequestExit() => ExitRequested = true;
        public static bool Exists = false;

        public rgatUI(rgatState state, ImGuiController controller)
        {
            Exists = true;
            _rgatState = state;
            _controller = controller;
            _gd = Controller.GraphicsDevice;
            _logsWindow = new LogsWindow(_rgatState);
        }





        public void InitWidgets(IProgress<float> progress)
        {
            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            Logging.RecordLogEvent("Startup: Initing graph display widgets", Logging.LogFilterType.Debug);

            _splashRenderer = new SplashScreenRenderer(_gd, Controller);
            visualiserTab = new VisualiserTab(_rgatState, Controller);


            Logging.RecordLogEvent($"Startup: Visualiser tab created in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.Debug);
            timer.Restart();
            visualiserTab.Init(_gd, progress);
            visualiserTab.SetDialogStateChangeCallback((bool state) => Controller.DialogChange(opened: state));

            Logging.RecordLogEvent($"Startup: Visualiser tab initialised in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.Debug);
            timer.Restart();

            chart = new SandboxChart(Controller.UnicodeFont);

            Logging.RecordLogEvent($"Startup: Analysis chart loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.Debug);
            timer.Stop();
        }

        public void InitSettingsMenu()
        {
            _SettingsMenu = new SettingsMenu(Controller); //call after config init, so theme gets generated
        }

        //public delegate UpdateProgress(ref float progress)

        public void AddMouseWheelDelta(float delta)
        {
            lock (_inputLock)
            {
                _mouseWheelDelta += delta;
            }
        }

        public void AddMouseDragDelta(Vector2 delta)
        {
            lock (_inputLock)
            
            {
                _mouseDragDelta += delta;
            }
        }
        
        public void SetMousePosition(Vector2 pos)
        {
            lock (_inputLock)
            
            {
                _mousePos += pos;
            }
        }

        public void AddKeyPress(Tuple<Key, ModifierKeys> keypress)
        {
            lock (_inputLock)
            {
                _keyPresses.Add(keypress);
            }
        }



        public void ShortTimerFired()
        {
            UIDrawFPS = Math.Min(101, 1000.0 / (_lastFrameTimeMS.Average()));

            if (_scheduleMissingPathCheck)
            {
                CheckMissingPaths();
                _scheduleMissingPathCheck = false;
            }
            _activeTargetRunnable = rgatState.ActiveTarget != null && rgatState.ActiveTarget.IsAccessible;

            if (ExitRequested)
            {
                ExitFlag = true;
            }
        }

        // keep checking the files in the loading panes so we can highlight if they are deleted (or appear)
        private void CheckMissingPaths()
        {

            rgatSettings.PathRecord[] recentBins = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Binary);
            rgatSettings.PathRecord[] recentTraces = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Trace);
            List<rgatSettings.PathRecord[]> allRecent = new List<rgatSettings.PathRecord[]>() { recentBins, recentTraces };
            foreach (var pathList in allRecent)
            {
                foreach (var path in pathList)
                {
                    if (!_missingPaths.Contains(path.Path) && !File.Exists(path.Path))
                    {
                        _missingPaths.Add(path.Path);
                    }
                }
            }
        }


        public void UpdateFrameStats(long elapsedMS)
        {
            _lastFrameTimeMS.Add(elapsedMS);
            if (_lastFrameTimeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
            {
                _lastFrameTimeMS = _lastFrameTimeMS.TakeLast(GlobalConfig.StatisticsTimeAvgWindow).ToList();
            }

            if (visualiserTab != null)
            {
                visualiserTab.UIFrameAverage = _lastFrameTimeMS.Average();
            }
        }


        public void GetFrameDimensions(VideoEncoder.CaptureContent frameType, out int startX, out int startY, out int width, out int height)
        {
            switch (frameType)
            {
                case VideoEncoder.CaptureContent.Graph:
                    height = (int)visualiserTab!.GraphSize.Y;
                    width = (int)visualiserTab.GraphSize.X;
                    startX = (int)visualiserTab.GraphPosition.X;
                    startY = (int)visualiserTab.GraphPosition.Y;
                    break;
                case VideoEncoder.CaptureContent.GraphAndPreviews:
                    height = (int)visualiserTab!.GraphSize.Y;
                    width = (int)visualiserTab.GraphSize.X + UI.PREVIEW_PANE_WIDTH;
                    startX = (int)visualiserTab.GraphPosition.X;
                    startY = (int)visualiserTab.GraphPosition.Y;
                    break;
                case VideoEncoder.CaptureContent.Window:
                default:
                    startX = 0;
                    startY = 0;
                    height = -1;
                    width = -1;
                    break;
            }
        }

        public bool ThreadsRunning => (visualiserTab != null && visualiserTab.ThreadsRunning);


        public void DrawMain()
        {
            if (rgatState.ActiveTarget == null)
            {
                DrawStartSplash();
            }
            else
            {
                DrawWindowContent();
            }
           
            if (MenuBarVisible)
            {
                DrawMainMenu();
            }
            DrawLoadSaveModal();
        }


        void DrawLoadSaveModal()
        {
            rgatState.SERIALISE_PROGRESS? progress = rgatState.SerialisationProgress;
            if (progress is null || progress.Cancelled is true) return;

            bool isOpen = true;
            ImGuiWindowFlags flags = ImGuiWindowFlags.NoDecoration;

            float windowWidth = 300;
            string? path = progress.FilePath;
            if (path is not null)
            {
                if (path.Length > 300) path = path.Substring(path.Length - 299);
                windowWidth = Math.Max(windowWidth, ImGui.CalcTextSize(path).X + 60);
            }

            ImGui.SetNextWindowSize(new Vector2(windowWidth, 200));
            ImGui.OpenPopup("LoadSaveDLG");

            if (ImGui.BeginPopupModal("LoadSaveDLG", ref isOpen, flags))//##" + rgatState.SerialisationProgress.Operation))
            {
                ImGui.SetWindowPos(ImGui.GetMainViewport().Size / 2 - ImGui.GetWindowSize() / 2);
                ImGuiUtils.DrawHorizCenteredText(progress.Operation);

                if (path is not null)
                {
                    ImGuiUtils.DrawHorizCenteredText(path);
                }

                if (progress.SectionsTotal > 0)
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 12);
                    if (progress.SectionName is not null)
                    {
                        ImGuiUtils.DrawHorizCenteredText($"Section {progress.SectionsComplete}/{progress.SectionsTotal}: " + progress.SectionName);
                    }

                    if (progress.SectionProgress > 0)
                    {
                        ImGui.SetCursorPosX((ImGui.GetWindowSize().X / 2) - 100);
                        SmallWidgets.ProgressBar("#SecProgress", $"{progress.SectionProgress * 100:F1}%", progress.SectionProgress,
                            new Vector2(200, 28), barColour: 0xff999999, BGColour: 0xff222222);
                    }
                }

                ImGui.SetCursorPos(new Vector2(ImGui.GetWindowSize().X / 2 - 40, ImGui.GetWindowSize().Y - 50));
                if (ImGui.Button("Cancel", new Vector2(80, 30)))
                {
                    _rgatState.CancelSerialization();
                }
                ImGui.EndPopup();
            }

        }


        /// <summary>
        /// Draws any open dialogs
        /// </summary>
        /// 
        /// This isn't great but coming up with something more elegant can wait
        public void DrawDialogs()
        {
            if (!Controller.DialogOpen)
            {
                return;
            }

            bool shown;
            if (_show_settings_window && _SettingsMenu != null)
            {
                shown = _show_settings_window;
                _SettingsMenu.Draw(ref shown);
                if (!shown)
                {
                    ToggleSettingsWindow();
                }
            }
            if (_show_select_exe_window)
            {
                shown = _show_select_exe_window;
                DrawFileSelectBox(ref shown);
                if (!shown)
                {
                    ToggleLoadExeWindow();
                }
            }
            if (_show_load_trace_window)
            {
                shown = _show_load_trace_window;
                DrawTraceLoadBox(ref shown);
                if (!shown)
                {
                    ToggleLoadTraceWindow();
                }
            }
            if (_show_tracelist_selection_window)
            {
                shown = _show_tracelist_selection_window;
                DrawTraceListSelectBox(ref shown);
                if (!shown)
                {
                    ToggleTraceListSelectionWindow();
                }
            }
            if (_show_test_harness)
            {
                shown = _show_test_harness;
                _testHarness!.Draw(ref shown);
                if (!shown)
                {
                    ToggleTestHarness();
                }
            }
            if (_show_logs_window)
            {
                shown = _show_logs_window;
                _logsWindow!.Draw(ref shown);
                if (!shown)
                {
                    ToggleLogsWindow();
                }
            }

            if (_show_remote_dialog)
            {
                if (_RemoteDialog == null) { _RemoteDialog = new RemoteDialog(); }
                shown = _show_remote_dialog;
                _RemoteDialog.Draw(ref shown);
                if (!shown)
                {
                    ToggleRemoteDialog();
                }
            }
        }

        public void CleanupFrame()
        {
            if (!_tooltipScrollingActive && _tooltipScroll != 0)
            {
                _tooltipScroll = 0;
            }
        }

        private void DrawWindowContent()
        {
            if (ImGui.BeginChild("MainWindow", ImGui.GetContentRegionAvail(), false, ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoScrollbar))
            {
                DrawTargetBar();

                BinaryTarget? activeTarget = rgatState.ActiveTarget;
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


        public void HandleUserInput()
        {
            if (StartupProgress < 1)
            {
                //Logging.WriteConsole($"Startup progress: {StartupProgress}");
                return;
            }

            if (_mouseWheelDelta != 0)
            {
                if (_tooltipScrollingActive)
                {
                    _tooltipScroll -= _mouseWheelDelta * 60;
                    if (_tooltipScroll < 0)
                    {
                        _tooltipScroll = 0;
                    }

                    _mouseWheelDelta = 0;
                    return;
                }
            }
            _tooltipScrollingActive = false;

            bool currentTabVisualiser = _currentTab == "Visualiser";
            bool currentTabTimeline = _currentTab == "Timeline";
            lock (_inputLock)
            {
                if (!Controller.DialogOpen)
                {
                    bool MouseInMainWidget = currentTabVisualiser && visualiserTab!.MouseInMainWidget;
                    if (_mouseWheelDelta != 0)
                    {

                        visualiserTab!.NotifyMouseWheel(_mouseWheelDelta);

                        chart?.ApplyZoom(_mouseWheelDelta);
                        _mouseWheelDelta = 0;
                    }

                    if (_mouseDragDelta.X != 0 || _mouseDragDelta.Y != 0)
                    {
                        if (ImGui.GetIO().KeyAlt)
                        {
                            visualiserTab!.NotifyMouseRotate(_mouseDragDelta);
                        }
                        else
                        {
                            visualiserTab!.NotifyMouseDrag(_mouseDragDelta);
                            if (currentTabTimeline && chart is not null)
                            {
                                chart.ApplyMouseDrag(_mouseDragDelta);
                            }
                        }

                        _mouseDragDelta = new Vector2(0, 0);
                    }
                }

                foreach (Tuple<Key, ModifierKeys> KeyModifierTuple in _keyPresses)
                {
                    if (_SettingsMenu!.HasPendingKeybind)
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
                                Logging.RecordError($"Unknown keybind setting: {KeyModifierTuple.Item2}_{KeyModifierTuple.Item1}");
                                break;
                            default:
                                _SettingsMenu.AssignPendingKeybind(KeyModifierTuple);
                                Logging.RecordLogEvent($"Known keybind setting: {KeyModifierTuple.Item2}_{KeyModifierTuple.Item1}", LogFilterType.Debug);
                                continue;
                        }
                    }


                    bool isKeybind = GlobalConfig.Settings.Keybinds.Active.TryGetValue(KeyModifierTuple, out KeybindAction boundAction);
                    if (isKeybind)
                    {
                        //cancel any open dialogs
                        if (boundAction == KeybindAction.Cancel)
                        {
                            CloseDialogs();
                        }
                    }


                    //could be a quickmenu shortcut
                    if (visualiserTab!.AlertRawKeyPress(KeyModifierTuple))
                    {
                        continue;
                    }

                    if (isKeybind && !_show_settings_window)
                    {
                        //ingore keybinds if a non-alt keybind used in dialog or user is entering text
                        bool InInputArea = ((DialogOpen && ImGui.GetIO().KeyAlt is false) ||
                                    ImGui.GetIO().WantTextInput);
                        if (InInputArea) continue;

                        switch (boundAction)
                        {
                            case KeybindAction.ToggleVideo:

                                ActivateNotification();
                                if (rgatState.VideoRecorder.Recording)
                                {
                                    rgatState.VideoRecorder.StopRecording();
                                }
                                else
                                {
                                    rgatState.VideoRecorder.StartRecording();
                                }
                                continue;

                            case KeybindAction.PauseVideo:

                                ActivateNotification();
                                if (rgatState.VideoRecorder.Recording)
                                {
                                    rgatState.VideoRecorder.CapturePaused = !rgatState.VideoRecorder.CapturePaused;
                                }
                                continue;

                            case KeybindAction.CaptureGraphImage:
                                PendingScreenshot = VideoEncoder.CaptureContent.Graph;
                                continue;

                            case KeybindAction.CaptureGraphPreviewImage:
                                PendingScreenshot = VideoEncoder.CaptureContent.GraphAndPreviews;
                                continue;

                            case KeybindAction.CaptureWindowImage:
                                PendingScreenshot = VideoEncoder.CaptureContent.Window;
                                continue;

                            default:
                                break;
                        }

                        if (currentTabVisualiser)
                        {
                            visualiserTab.AlertKeybindPressed(boundAction, KeyModifierTuple);
                        }

                        else if (currentTabTimeline && chart is not null)
                        {
                            chart.AlertKeybindPressed(KeyModifierTuple, boundAction);
                        }
                    }


                }
                _keyPresses.Clear();
            }
        }


        private void CloseDialogs()
        {
            if (_SettingsMenu!.HasPendingKeybind)
            {
                _SettingsMenu.HasPendingKeybind = false;
                return;
            }

            //should really be maintaining a list of dialogs rather than this
            if (_show_select_exe_window)
            {
                ToggleLoadExeWindow();
            }

            if (_show_load_trace_window)
            {
                ToggleLoadTraceWindow();
            }

            if (_show_tracelist_selection_window)
            {
                ToggleTraceListSelectionWindow();
            }

            if (_show_settings_window)
            {
                ToggleSettingsWindow();
            }

            if (_show_remote_dialog)
            {
                ToggleRemoteDialog();
            }

            if (_show_test_harness)
            {
                ToggleTestHarness();
            }

            if (_show_logs_window)
            {
                ToggleLogsWindow();
            }

            if (ShowStatsDialog)
            {
                ToggleRenderStatsDialog();
            }

            visualiserTab?.AlertKeybindPressed(KeybindAction.Cancel, null);
            Debug.Assert(DialogOpen is false);
        }

        private void ToggleTestHarness()
        {
            Logging.RecordLogEvent("Test harness toggled", LogFilterType.Debug);
            if (_show_test_harness == false)
            {
                if (_testHarness == null)
                {
                    _testHarness = new TestsWindow(_rgatState, Controller);
                }
            }
            _show_test_harness = !_show_test_harness;
            Controller.DialogChange(_show_test_harness);
        }

        private void ToggleRemoteDialog()
        {
            if (GlobalConfig.Loaded is false) return;
            Logging.RecordLogEvent("Remote dialog toggled", LogFilterType.Debug);
            if (_show_remote_dialog == false)
            {
                if (_RemoteDialog == null)
                {
                    _RemoteDialog = new RemoteDialog();
                }
            }
            _show_remote_dialog = !_show_remote_dialog;
            Controller.DialogChange(_show_remote_dialog);
        }


        public static void ToggleRenderStatsDialog()
        {
            ShowStatsDialog = !ShowStatsDialog;
            Controller.DialogChange(ShowStatsDialog);
        }


        private void ToggleLoadTraceWindow()
        {
            _show_load_trace_window = !_show_load_trace_window;
            Controller.DialogChange(_show_load_trace_window);
        }

        private void ToggleLoadExeWindow()
        {
            _show_select_exe_window = !_show_select_exe_window;
            Controller.DialogChange(_show_select_exe_window);
        }

        private void ToggleTraceListSelectionWindow()
        {
            _show_tracelist_selection_window = !_show_tracelist_selection_window;
            Controller.DialogChange(_show_tracelist_selection_window);
        }

        private void ToggleSettingsWindow()
        {
            _show_settings_window = !_show_settings_window;
            Controller.DialogChange(_show_settings_window);
        }

        private void ToggleLogsWindow()
        {
            Logging.WriteConsole($"Logwindow toggle {_show_logs_window}");
            _show_logs_window = !_show_logs_window;
            Controller.DialogChange(_show_logs_window);
        }

        private bool DrawRecentPathEntry(rgatSettings.PathRecord pathdata, bool menu)
        {

            string pathshort = pathdata.Path;
            bool isMissing = _missingPaths.Contains(pathdata.Path);
            bool isBad = _badPaths.Contains(pathdata.Path);

            if (pathdata.Path.ToLower().EndsWith(".rgat"))
            {
                int dateIdx = pathshort.LastIndexOf("__");
                if (dateIdx > 0)
                {
                    pathshort = pathshort.Substring(0, dateIdx);
                }
            }
            string agoText = $" ({pathdata.LastOpen.Humanize()})";
            if (ImGui.CalcTextSize(pathshort + agoText).X > ImGui.GetContentRegionAvail().X)
            {
                if (pathshort.Length > 50)
                {
                    pathshort = pathshort.Truncate(50, "...", TruncateFrom.Left);
                }
            }
            if (isMissing || isBad)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
            }

            if (menu)
            {
                if (ImGui.MenuItem(pathshort + agoText))
                {
                    return true;
                }
            }
            else
            {
                ImGui.Selectable(pathshort + agoText);
            }

            if (isMissing || isBad)
            {
                ImGui.PopStyleColor();
            }

            if (ImGui.IsItemHovered())
            {
                if (ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
                {
                    return true;
                }
                ImGui.BeginTooltip();
                ImGui.Indent(5);
                ImGui.Text($"{pathdata.Path}");
                ImGui.Text($"Most recently opened {pathdata.LastOpen.Humanize()}");
                ImGui.Text($"First opened {pathdata.FirstOpen.Humanize()}");
                ImGui.Text($"Has been loaded {pathdata.OpenCount} times.");
                if (isMissing)
                {
                    ImGui.Text($"-------Not Found-------");
                    ImGui.Text($"File is missing");
                }
                if (isBad)
                {
                    ImGui.Text($"-------Error-------");
                    ImGui.Text($"Unable to open, may be corrupt or inaccessible");
                }
                ImGui.EndTooltip();
            }
            return false;
        }




        private void DrawMemDataTab()
        {
            if (ImGui.BeginTabItem("Memory Activity"))
            {
                ImGui.Text("Memory data stuff here");
                ImGui.EndTabItem();
            }
        }


        private unsafe void DrawMainMenu()
        {
            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText));
            float logMenuX = 0;
            if (ImGui.BeginMenuBar())
            {
                DrawOuterLeftMenuItems();
                DrawInnerLeftMenuItems();
                DrawInnerRightMenuItems();
                DrawOuterRightMenuItems(out logMenuX);
                ImGui.EndMenuBar();
            }
            ImGui.PopStyleColor(1);
            DrawAlerts(new Vector2(logMenuX, 18));
        }

        private void DrawOuterLeftMenuItems()
        {
            if (ImGui.BeginMenu("Target"))
            {
                if (ImGui.MenuItem("Select Target Executable")) { ToggleLoadExeWindow(); }

                var recentbins = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Binary);
                if (ImGui.BeginMenu("Recent Binaries", recentbins.Any()))
                {
                    foreach (var entry in recentbins.Take(Math.Min(10, recentbins.Length)))
                    {
                        if (DrawRecentPathEntry(entry, true))
                        {
                            LoadSelectedBinary(entry.Path, rgatState.ConnectedToRemote);
                        }
                    }
                    ImGui.EndMenu();
                }

                if (ImGui.MenuItem("Open Saved Trace")) { ToggleLoadTraceWindow(); }

                var recenttraces = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Trace);
                if (ImGui.BeginMenu("Recent Traces", recenttraces.Any()))
                {
                    foreach (var entry in recenttraces.Take(Math.Min(10, recenttraces.Length)))
                    {
                        if (DrawRecentPathEntry(entry, true) && rgatState.SerialisationProgress is null)
                        {
                            System.Threading.Tasks.Task.Run(() => LoadTraceByPath(entry.Path));
                        }
                    }
                    ImGui.EndMenu();
                }

                ImGui.Separator();

                if (rgatState.ActiveTrace is not null && ImGui.MenuItem("Save Trace") && rgatState.SerialisationProgress is null)
                {
                    System.Threading.Tasks.Task.Run(() => rgatState.SaveTrace(rgatState.ActiveTrace));
                }  
                
                if (rgatState.ActiveTarget is not null && ImGui.MenuItem("Save Target") && rgatState.SerialisationProgress is null)
                {
                    System.Threading.Tasks.Task.Run(() => rgatState.SaveTarget(rgatState.ActiveTarget));
                }

                if (ImGui.MenuItem("Save All"))
                {
                    System.Threading.Tasks.Task.Run(() => rgatState.SaveAllTargets());
                } 


                if (ImGui.MenuItem("Export Pajek"))
                {
                    TraceRecord? record = rgatState.ActiveTrace;
                    PlottedGraph? graph = rgatState.ActiveGraph;
                    if (record is not null && graph is not null)
                    {
                        rgatState.ExportTraceAsPajek(record, graph.TID);
                    }
                }
                SmallWidgets.MouseoverText("Export the current graph in a format readable by other graph visualisers");
                ImGui.Separator();
                if (ImGui.MenuItem("Open Screenshot/Video Folder"))
                {
                    OpenDirectoryInFileBrowser(GlobalConfig.GetSettingPath(PathKey.MediaCapturePath), "Media");
                }
                ImGui.Separator();
                ExitFlag = ImGui.MenuItem("Exit");
                ImGui.EndMenu();
            }

            bool settingsVisible = _show_settings_window;
            if (ImGui.MenuItem("Settings", null, ref settingsVisible))
            {
                ToggleSettingsWindow();
            }
        }


        private void DrawInnerLeftMenuItems()
        {
            float quarter = ImGui.GetContentRegionMax().X / 4f;
            ImGui.SetCursorPosX(quarter);
            bool rdlgshown = _show_remote_dialog;
            if (rgatState.ConnectedToRemote)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.Emphasis1));
                if (ImGui.MenuItem(ImGuiController.FA_ICON_NETWORK + " Remote Mode", null, ref rdlgshown))
                {
                    ImGui.PopStyleColor();
                    ToggleRemoteDialog();
                }
                else
                {
                    ImGui.PopStyleColor();
                }
                
                System.Net.IPEndPoint? endpoint = rgatState.NetworkBridge.RemoteEndPoint;
                if (endpoint is not null)
                {
                    SmallWidgets.MouseoverText($"Samples will be executed on {endpoint.Address}");
                }
            }
            else
            {
                uint iconColour = GlobalConfig.Loaded ? 
                    Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText) : 
                    Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1);
                ImGui.PushStyleColor(ImGuiCol.Text, iconColour);
                if (ImGui.MenuItem(ImGuiController.FA_ICON_LOCALCODE + " Local Mode", null, ref rdlgshown))
                {
                    if (GlobalConfig.Loaded)
                        ToggleRemoteDialog();
                }
                ImGui.PopStyleColor();
                SmallWidgets.MouseoverText("Samples will be executed on this computer");
            }
        }


        /// <summary>
        /// Display media actions like recording and screen capture
        /// </summary>
        private void DrawInnerRightMenuItems()
        {
            float iconsStart = 3 * (ImGui.GetContentRegionMax().X / 5f) - 50;

            if (_lastScreenShot != VideoEncoder.CaptureContent.Invalid)
            {
                try
                {
                    ImGui.SetCursorPosX(iconsStart);
                    ActivateNotification();
                    DisplayScreenshotNotification();
                }
                catch (Exception e)
                {
                    Logging.RecordException($"Exception processing screenshot notification: {e.Message}", e);
                    _lastScreenShot = VideoEncoder.CaptureContent.Invalid;
                }
            }


            ImGui.SetCursorPosX(iconsStart + 40);
            DisplayVideoRecordingNotification();

        }


        /// <summary>
        /// Displays the still camera icon on the menu bar
        /// Displays an animated rectangle drawing the eye to it, from the region captured
        /// UI.SCREENSHOT_ICON_LINGER_TIME controls how long the icon is displayed
        /// UI.SCREENSHOT_ANIMATION_RECT_SPEED controls how fast the rectangle travels/disappears
        /// </summary>
        private void DisplayScreenshotNotification()
        {
            const double displaySeconds = UI.SCREENSHOT_ICON_LINGER_TIME;

            TimeSpan timeSince = DateTime.Now - _screenShotTime;
            if (timeSince.TotalSeconds > displaySeconds)
            {
                _lastScreenShot = VideoEncoder.CaptureContent.Invalid;
                return;
            }

            double progress = timeSince.TotalSeconds / displaySeconds;
            double remainingProgress = 1.0 - progress;

            uint alpha = (uint)Math.Max((255.0 * remainingProgress), 255f * 0.25f);
            uint textColour = Themes.GetThemeColourWRF(Themes.eThemeColour.WindowText).ToUint(alpha);
            ImGui.PushStyleColor(ImGuiCol.Text, textColour);
            ImGui.MenuItem($"{ImGuiController.FA_STILL_CAMERA}");
            ImGui.PopStyleColor();
            if (ImGui.IsItemHovered())
            {
                ImGui.BeginTooltip();
                ImGui.Text($"Screenshot saved to {_lastScreenShotPath}");
                ImGui.Text($"Click to open screenshot directory");
                ImGui.EndTooltip();
            }
            if (ImGui.IsItemClicked())
            {
                OpenDirectoryInFileBrowser(Path.GetDirectoryName(_lastScreenShotPath), "Screenshot");
            }

            double animationProgress = progress * UI.SCREENSHOT_ANIMATION_RECT_SPEED;
            if (GlobalConfig.Settings.UI.ScreencapAnimation && animationProgress < 1)
            {
                Vector2? rectSize, startCenter;
                switch (_lastScreenShot)
                {
                    case VideoEncoder.CaptureContent.Graph:
                        Vector2 graphpos = visualiserTab!.GraphPosition;
                        rectSize = visualiserTab.GraphSize;
                        startCenter = new Vector2(graphpos.X + rectSize.Value.X / 2, ImGui.GetWindowSize().Y - (graphpos.Y + rectSize.Value.Y / 2));
                        break;
                    case VideoEncoder.CaptureContent.GraphAndPreviews:
                        Vector2 graphpos2 = visualiserTab!.GraphPosition;
                        rectSize = visualiserTab.GraphSize + new Vector2(CONSTANTS.UI.PREVIEW_PANE_WIDTH, 0);
                        startCenter = new Vector2(graphpos2.X + rectSize.Value.X / 2, ImGui.GetWindowSize().Y - (graphpos2.Y + rectSize.Value.Y / 2));
                        break;
                    case VideoEncoder.CaptureContent.Window:
                    default:
                        rectSize = ImGui.GetWindowSize();
                        startCenter = new Vector2(rectSize.Value.X / 2, rectSize.Value.Y / 2);
                        break;
                }

                rectSize = new Vector2(rectSize.Value.X * (float)(1 - animationProgress), rectSize.Value.Y * (float)(1 - animationProgress));
                Vector2 endCenter = ImGui.GetCursorScreenPos() + new Vector2(-15, ImGui.GetWindowSize().Y - 8);
                float currentXOffset = (endCenter.X - startCenter.Value.X) * (float)animationProgress;
                float currentYOffset = (endCenter.Y - startCenter.Value.Y) * (float)animationProgress;
                Vector2 currentCenter = new Vector2(startCenter.Value.X + currentXOffset, ImGui.GetWindowSize().Y - (startCenter.Value.Y + currentYOffset));
                Vector2 currentCorner = new Vector2(currentCenter.X - rectSize.Value.X / 2, currentCenter.Y - rectSize.Value.Y / 2);
                ImGui.GetForegroundDrawList().AddRect(currentCorner, currentCorner + rectSize.Value, textColour);
            }
        }


        /// <summary>
        /// Displays the video camera icon on the menu bar
        /// 
        /// </summary>
        private void DisplayVideoRecordingNotification()
        {
            double MSago = rgatState.VideoRecorder.RecordingStateChangeTimeAgo;
            const double StateChangeLingerTime = 1000;
            const double StateChangeFadeTime = 400;
            const double StateChangeSolidTime = StateChangeLingerTime - StateChangeFadeTime;

            if (MSago < StateChangeLingerTime)
            {
                ActivateNotification();
                if (rgatState.VideoRecorder.Recording)
                {
                    //fade in
                    uint alpha = MSago > StateChangeFadeTime ? 255 : (uint)(255.0 * (((MSago - StateChangeFadeTime) / StateChangeFadeTime)));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourWRF(Themes.eThemeColour.Emphasis1).ToUint(alpha));
                    ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA} Recording Started");
                    ImGui.PopStyleColor();
                }
                else
                {
                    //fade out
                    uint alpha = MSago < StateChangeSolidTime ? 255 : (uint)(255.0 * (1.0 - ((MSago - StateChangeSolidTime) / StateChangeFadeTime)));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourWRF(Themes.eThemeColour.Emphasis2).ToUint(alpha));
                    if (rgatState.VideoRecorder.Error?.Length > 0)
                        ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA} Recording Error");
                    else
                        ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA} Recording Stopped");
                    ImGui.PopStyleColor();
                }
            }
            else
            {
                if (!rgatState.VideoRecorder.Recording)
                {
                    return;
                }

                ActivateNotification();
                if (rgatState.VideoRecorder.CapturePaused)
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText));
                    ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA} Recording Paused");
                    ImGui.PopStyleColor();
                }
                else
                {
                    ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA}");
                }
            }

            SmallWidgets.MouseoverText("Left click to open output directory. Right click to end recording.");
            if (ImGui.IsItemClicked(mouse_button: ImGuiMouseButton.Left))
            {
                OpenDirectoryInFileBrowser(VideoEncoder.GetCaptureDirectory(), "Video");
            }
            if (ImGui.IsItemClicked(mouse_button: ImGuiMouseButton.Right))
            {
                rgatState.VideoRecorder.StopRecording();
            }
        }


        private static void OpenDirectoryInFileBrowser(string? path, string label)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    path = Path.GetDirectoryName(path);
                }

                if (path is null || !Directory.Exists(path))
                {
                    Logging.RecordError($"Requested {label} directory {path} was not available");
                    return;
                }

                Logging.RecordLogEvent($"Opening {label} directory in file browser: {path}", LogFilterType.Debug);
                System.Diagnostics.ProcessStartInfo openRequestedDir = new System.Diagnostics.ProcessStartInfo() { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(startInfo: openRequestedDir);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception {e.Message} opening {label} directory {path}", e);
                return;
            }
        }


        /// <summary>
        /// Displays less-used utilities like logs, tests 
        /// </summary>
        /// <param name="logMenuX">Set to the center X position of the log menu button, for alert animations</param>
        private void DrawOuterRightMenuItems(out float logMenuX)
        {
            //draw right to left
            float X = ImGui.GetContentRegionMax().X - (ImGui.CalcTextSize("Demo ").X + 15);
            ImGui.SetCursorPosX(X);

            if (GlobalConfig.Settings.UI.EnableImGuiDemo)
            {
                ImGui.MenuItem("Demo", null, ref Controller.ShowDemoWindow, true);
            }

            if (GlobalConfig.Settings.UI.EnableTestHarness)
            {
                X -= (ImGui.CalcTextSize("Tests ").X + 20);
                ImGui.SetCursorPosX(X);
                bool isShown = _show_test_harness;
                if (ImGui.MenuItem("Tests", null, ref isShown, true))
                {
                    ToggleTestHarness();
                }
            }


            Vector2 logBtnTextSize = ImGui.CalcTextSize("Logs (25) ");
            X -= (logBtnTextSize.X + 20);
            logMenuX = X + logBtnTextSize.X / 2f;
            ImGui.SetCursorPosX(X);
            int unseenErrors = Logging.UnseenAlerts;
            uint itemColour = unseenErrors > 0 ? Themes.GetThemeColourUINT(Themes.eThemeColour.WarnStateColour) : Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText);
            ImGui.PushStyleColor(ImGuiCol.Text, itemColour);
            bool menuDrawn = _show_logs_window;
            ImGui.MenuItem($"Logs{(unseenErrors > 0 ? $" ({unseenErrors})" : "")}", null, ref menuDrawn);
            ImGui.PopStyleColor();
            if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByPopup | ImGuiHoveredFlags.AllowWhenOverlapped))
            {
                DrawLogMouseover();
            }
        }

        private void DrawLogMouseover()
        {

            if (ImGui.IsMouseClicked(ImGuiMouseButton.Left))
            {
                ToggleLogsWindow();
                LogsWindow.ShowAlerts();
                Logging.ClearAlertsBox();
            }

            if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
            {
                Logging.ClearAlertsBox();
            }

            if (_show_logs_window)
            {
                return;
            }
            //
            int alertCount = Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alertCount == 0)
            {
                return;
            }

            // problem - can't find a way to force the dialog to appear at a minimum height without specifying an X value
            // this causes the dialog to cover the logs button if the mouse comes down from above the window

            //Vector2 popupBR = new Vector2(Math.Min(ImGui.GetCursorPosX(), windowSize.X - (widestAlert + 100)), ImGui.GetCursorPosY() + 150);

            float origy = ImGui.GetCursorPosY();
            ImGui.SetCursorPosY(25);//SetNextWindowPos(new Vector2(ImGui.GetWindowSize().X - ( 600), 25));
            ImGui.OpenPopup("##AlertsCtx");
            //ImGui.SetCursorScreenPos(ImGui.GetCursorScreenPos() + new Vector2(0, 60));
            if (ImGui.BeginPopup("##AlertsCtx", ImGuiWindowFlags.AlwaysAutoResize))
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
                        ImGui.Text(msg.Text);
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
            ImGui.SetCursorPosY(origy);
        }


        private bool DrawAlerts(Vector2 logMenuPosition)
        {

            const double lingerTime = UI.ALERT_TEXT_LINGER_TIME;
            const double fadeThreshold = 1000;

            double timeSinceLast = Logging.TimeSinceLastAlert.TotalMilliseconds;
            if (timeSinceLast > lingerTime)
            {
                return false;
            }

            Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alerts.Length == 0)
            {
                return false;
            }

            ActivateNotification();

            if (GlobalConfig.Settings.UI.AlertAnimation && timeSinceLast < UI.ALERT_CIRCLE_ANIMATION_TIME)
            {
                uint color = Themes.GetThemeColourWRF(Themes.eThemeColour.WindowText).ToUint(150);
                float radius = (float)(UI.ALERT_CIRCLE_ANIMATION_RADIUS * (1 - (timeSinceLast / UI.ALERT_CIRCLE_ANIMATION_TIME)));
                ImGui.GetForegroundDrawList().AddCircle(logMenuPosition, radius, color);
            }


            double boxTimeRemaining = timeSinceLast - lingerTime; //fade out over a second
            uint opacity = 255;
            if (boxTimeRemaining < 1000)
            {
                opacity = ((uint)(boxTimeRemaining / (float)fadeThreshold));
            }

            uint textColour = Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText);
            WritableRgbaFloat errColour = Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour);
            WritableRgbaFloat alertColour = Themes.GetThemeColourWRF(Themes.eThemeColour.Emphasis1);

            List<Tuple<TEXT_LOG_EVENT, uint>> displayItems = new();

            long nowTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            for (var i = 0; i < alerts.Length; i++)
            {
                TEXT_LOG_EVENT item = (TEXT_LOG_EVENT)alerts[i];
                long alertAge = nowTime - item.EventTimeMS;
                long timeRemaining = (long)lingerTime - alertAge;
                int alpha = 255;
                if (timeRemaining < fadeThreshold) //fade out over a second
                {
                    float fade = (timeRemaining / (float)fadeThreshold);
                    alpha = (int)(Math.Min(255f, 255f * fade));
                    alpha = Math.Max(alpha, 0);
                }
                if (alpha > 0)
                    displayItems.Add(new Tuple<TEXT_LOG_EVENT, uint>(item, (uint)alpha));
            }

            displayItems = displayItems.TakeLast(2).ToList();


            float widestAlert = 0;
            float height = 5;
            foreach (var item in displayItems)
            {
                Vector2 logSize = ImGui.CalcTextSize(item.Item1.Text);
                widestAlert = Math.Max(widestAlert, logSize.X + 50);
                height += logSize.Y;
            }

            Vector2 windowSize = ImGui.GetWindowSize();
            float width = Math.Min(widestAlert + 10, (windowSize.X / 2f) - 30);
            Vector2 size = new Vector2(width, height);
            ImGui.SetCursorScreenPos(new Vector2(windowSize.X - width - 50, 32));

            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourWRF(Themes.eThemeColour.AlertWindowBg).ToUint(customAlpha: opacity));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 1));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(1, 0));
            if (ImGui.BeginChild("##alertpopchildfrm", size))
            {
                foreach (Tuple<TEXT_LOG_EVENT, uint> item in displayItems)
                {
                    TEXT_LOG_EVENT logItem = item.Item1;
                    uint alpha = item.Item2;
                    if (logItem.Filter == LogFilterType.Alert)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, alertColour.ToUint(alpha));
                        ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 2);
                        ImGui.Text($" {ImGuiController.FA_ICON_BELL} ");
                        ImGui.PopStyleColor();
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, errColour.ToUint(alpha));
                        ImGui.Text($" {ImGuiController.FA_ICON_WARNING} ");
                        ImGui.PopStyleColor();
                    }
                    ImGui.SameLine();
                    textColour = new WritableRgbaFloat(textColour).ToUint(alpha);
                    ImGui.PushStyleColor(ImGuiCol.Text, textColour);
                    ImGui.Text(logItem.Text);
                    ImGui.PopStyleColor();
                }
                ImGui.EndChild();

            }

            ImGui.PopStyleVar(2);
            ImGui.PopStyleColor();

            return true;
        }







        /// <summary>
        /// Call this after a screenshot is complete to begin the screenshot display animation
        /// </summary>
        /// <param name="savePath">Path of the screenshot, for use in the mouseover text</param>
        public void NotifyScreenshotComplete(string savePath)
        {
            _lastScreenShot = PendingScreenshot;
            _lastScreenShotPath = savePath;
            PendingScreenshot = VideoEncoder.CaptureContent.Invalid;
            _screenShotTime = DateTime.Now;
            ActivateNotification();
        }



        /// <summary>
        /// Draws a dropdown allowing selection of one of the loaded target binaries
        /// </summary>
        /// <returns>true if at least one binary is loaded, otherwise false</returns>
        private unsafe bool DrawTargetBar()
        {

            if (rgatState.targets.Count == 0)
            {
                ImGui.Text("No target selected or trace loaded");
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                return false;
            }

            BinaryTarget? activeTarget = rgatState.ActiveTarget;
            //there shouldn't actually be a way to select a null target once one is loaded
            string activeString = (activeTarget == null) ? "No target selected" : activeTarget.FilePath;
            if (activeTarget is not null && activeTarget.IsRemoteBinary && activeTarget.RemoteHost is not null)
                activeString = $"[{activeTarget.RemoteHost}]:{activeString}";

            List<string> paths = rgatState.targets.GetTargetPaths();
            ImGuiComboFlags flags = 0;
            float textWidth = ImGui.CalcTextSize(activeString).X;
            float ctrlWidth = Math.Max(ImGui.GetContentRegionAvail().X / 2.5f, textWidth + 50);
            textWidth = Math.Min(ImGui.GetContentRegionAvail().X - 300, ctrlWidth);
            ImGui.SetNextItemWidth(textWidth);
            if (textWidth < ctrlWidth && activeTarget !=  null)
            {
                activeString = activeTarget.FileName;
            }
            if (ImGui.BeginCombo("Active Target", activeString, flags))
            {
                foreach (string path in paths)
                {
                    bool is_selected = activeTarget != null && activeTarget.FilePath == path;
                    string label = path;
                    if (activeTarget is not null && activeTarget.IsRemoteBinary && activeTarget.RemoteHost is not null)
                        label = $"[{activeTarget.RemoteHost}]:{path}";
                    if (ImGui.Selectable(label, is_selected))
                    {
                        rgatState.SetActiveTarget(path);
                    }

                    // Set the initial focus when opening the combo (scrolling + keyboard navigation focus)
                    if (is_selected)
                    {
                        ImGui.SetItemDefaultFocus();
                    }
                }
                ImGui.EndCombo();
            }
            return true;
        }


        // these are gross
        private bool _SwitchToTraceSelectTab = false;
        private bool _SwitchToVisualiserTab = false;
        private int _OldTraceCount = -1;
        private string _currentTab = "";

        private unsafe void DrawTabs()
        {
            bool tabDrawn = false;
            ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;

            if (_OldTraceCount != -1 && rgatState.TotalTraceCount > _OldTraceCount)
            {
                _OldTraceCount = -1;
                _SwitchToVisualiserTab = true;
                visualiserTab!.ClearPreviewTrace();
                rgatState.SelectActiveTrace(newest: true);
            }

            if (ImGui.BeginTabBar("Primary Tab Bar", tab_bar_flags))
            {
                if (_SwitchToTraceSelectTab)
                {
                    tabDrawn = ImGui.BeginTabItem("Start Trace", ref tabDrawn, ImGuiTabItemFlags.SetSelected);
                    _SwitchToTraceSelectTab = false;
                }
                else
                {
                    tabDrawn = ImGui.BeginTabItem("Start Trace");
                }

                if (tabDrawn)
                {
                    _currentTab = "TraceSelect";
                    DrawTraceTab(rgatState.ActiveTarget);
                    ImGui.EndTabItem();
                }
                else
                {
                    _tooltipScrollingActive = false;
                }


                //is there a better way to do this?
                if (_SwitchToVisualiserTab)
                {
                    tabDrawn = true;
                    tabDrawn = ImGui.BeginTabItem("Visualiser", ref tabDrawn, ImGuiTabItemFlags.SetSelected);
                    if (tabDrawn)
                        _SwitchToVisualiserTab = false;
                }
                else
                {
                    tabDrawn = ImGui.BeginTabItem("Visualiser");
                }

                if (tabDrawn)
                {
                    _currentTab = "Visualiser";
                    visualiserTab!.Draw();
                    ImGui.EndTabItem();
                }
                else
                {
                    if (ShowStatsDialog) ToggleRenderStatsDialog();
                }

                DrawAnalysisTab(rgatState.ActiveTrace);

                //DrawMemDataTab();
                ImGui.EndTabBar();
            }

        }

        public static bool IsrgatSavedTrace(string filestart)
        {
            try
            {
                if (filestart.StartsWith("{\""))
                {
                    return true;
                }

                if (filestart.StartsWith("RGZ"))
                {
                    return true;
                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to check if file is a saved trace [{e.Message}]. Assuming it isn't", LogFilterType.Debug);
            }


            return false;
        }

        public bool LoadSelectedBinary(string? path, bool isRemote)
        {
            if (path is null)
            {
                return false;
            }

            try
            {
                if (isRemote)
                {
                    return LoadRemoteBinary(path);
                }

                if (!File.Exists(path))
                {
                    Logging.RecordLogEvent($"Loading binary {path} failed: File does not exist", filter: LogFilterType.Alert);
                    return false;
                }

                FileStream fs = File.OpenRead(path);
                if (fs.Length < 4)
                {
                    Logging.RecordLogEvent($"Loading binary {path} failed: File too small ({fs.Length} bytes)", filter: LogFilterType.Alert);
                    return false;
                }

                byte[] preview = new byte[4];
                fs.Read(preview, 0, preview.Length);
                fs.Close();

                if (IsrgatSavedTrace(ASCIIEncoding.ASCII.GetString(preview)))
                {
                    System.Threading.Tasks.Task.Run(() => LoadTraceByPath(path));
                    _SwitchToTraceSelectTab = true;
                }
                else
                {
                    rgatState.SetActiveTarget(path: null);
                    GlobalConfig.Settings.RecentPaths.RecordRecentPath(rgatSettings.PathType.Binary, path);
                    rgatState.AddTargetByPath(path);
                    _SwitchToTraceSelectTab = true;
                }
            }
            catch (Exception e)
            {
                Logging.RecordException($"Error loading target binary: {e.Message}", e);
                return false;
            }

            return true;
        }

        private bool LoadRemoteBinary(string path)
        {
            if (!rgatState.ConnectedToRemote)
            {
                Logging.RecordLogEvent($"Loading remote binary {path} failed: Not Connected", filter: LogFilterType.Alert);
                return false;
            }

            rgatState.SetActiveTarget(path: null);
            BinaryTarget target = _rgatState.AddRemoteTargetByPath(path, rgatState.NetworkBridge.LastAddress);
            rgatState.NetworkBridge.SendCommand("LoadTarget", "GUI", target.InitialiseFromRemoteData, path);

            return true;
        }


        public void DrawFileSelectBox(ref bool show_select_exe_window)
        {
            string title = "Select Binary";
            if (rgatState.ConnectedToRemote)
            {
                title += " (Remote Machine)";
            }

            ImGui.SetNextWindowSize(new Vector2(600, 600), ImGuiCond.FirstUseEver);
            ImGui.OpenPopup(title);
            if (ImGui.BeginPopupModal(title, ref show_select_exe_window, ImGuiWindowFlags.NoScrollbar))
            {

                rgatFilePicker.FilePicker picker;
                bool isRemote = rgatState.ConnectedToRemote;
                if (isRemote)
                {
                    picker = rgatFilePicker.FilePicker.GetRemoteFilePicker(this);
                }
                else
                {
                    picker = rgatFilePicker.FilePicker.GetFilePicker(this, Environment.CurrentDirectory);
                }

                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        LoadSelectedBinary(picker.SelectedFile, rgatState.ConnectedToRemote);
                        rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    }
                    show_select_exe_window = false;
                }

                ImGui.EndPopup();
            }
        }


        private bool LoadTraceByPath(string? filepath)
        {
            if (rgatState.SerialisationProgress is not null)
            {
                Logging.RecordError("Serialization already in progress");
                return false;
            }

            if (filepath is null || !File.Exists(filepath))
            {
                Logging.RecordError($"Failed to load missing trace file: {filepath}");
                return false;
            }

            if (!_rgatState.LoadTraceByPath(filepath, out TraceRecord? trace) || trace is null)
            {
                return false;
            }
            GlobalConfig.Settings.RecentPaths.RecordRecentPath(rgatSettings.PathType.Trace, filepath);

            BinaryTarget target = trace.Target;

            //todo only if signatures not stored in trace + file exists on disk
            rgatState.DIELib?.StartDetectItEasyScan(target);
            rgatState.YARALib?.StartYARATargetScan(target);

            StartTraceDisplayWorkers(trace, _rgatState);

            rgatState.ActiveTarget = target;
            rgatState.SelectActiveTrace(target.GetFirstTrace());

            //_rgatState.SwitchTrace = trace;

            //ui.dynamicAnalysisContentsTab.setCurrentIndex(eVisualiseTab);
            return true;
        }

        private void StartTraceDisplayWorkers(TraceRecord trace, rgatState clientState)
        {
            ProcessLaunching.launch_saved_process_threads(trace, clientState);

            foreach (TraceRecord childTrace in trace.Children)
            {
                StartTraceDisplayWorkers(childTrace, clientState);
            }
        }


        public void DrawTraceLoadBox(ref bool shown)
        {
            ImGui.SetNextWindowSize(new Vector2(600, 600), ImGuiCond.FirstUseEver);
            ImGui.OpenPopup("Select Trace File");

            if (ImGui.BeginPopupModal("Select Trace File", ref shown, ImGuiWindowFlags.NoScrollbar))
            {
                string savedir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TraceSaveDirectory);
                if (!Directory.Exists(savedir))
                {
                    savedir = Environment.CurrentDirectory;
                }

                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, savedir);
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        System.Threading.Tasks.Task.Run(() => LoadTraceByPath(picker.SelectedFile));
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    shown = false;
                }

                ImGui.EndPopup();
            }
        }


        public void DrawTraceListSelectBox(ref bool shown)
        {

            string? startdir = rgatState.ActiveTarget != null ? Path.GetDirectoryName(rgatState.ActiveTarget.FilePath) : null;
            if (startdir is null || !Directory.Exists(startdir))
            {
                startdir = Environment.CurrentDirectory;
            }

            var picker = rgatFilePicker.FilePicker.GetFilePicker(this, startdir, allowMulti: true);

            string title = "Select Files to List";
            if (picker != null && picker.AllowMultiSelect)
            {
                title += $" ({picker.SelectedFiles.Count + picker.SelectedDirectories.Count} selected)";
            }
            title += "###TraceListSelector";
            ImGui.SetNextWindowSize(new Vector2(600, 600), ImGuiCond.FirstUseEver);
            ImGui.OpenPopup(title);
            if (picker is not null && ImGui.BeginPopupModal(title, ref shown, ImGuiWindowFlags.NoScrollbar))
            {
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        AddDirectoriesToTracingList(picker.SelectedDirectories);
                        AddFilesToTracingList(picker.SelectedFiles);
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    shown = false;
                }

                ImGui.EndPopup();
            }
        }

        public void AddDirectoriesToTracingList(List<string> files)
        {
            BinaryTarget? activeTarget = rgatState.ActiveTarget;
            if (activeTarget is not null)
            {
                TraceChoiceSettings moduleChoices = activeTarget.LaunchSettings.TraceChoices;
                if (moduleChoices.TracingMode == ModuleTracingMode.eDefaultIgnore)
                {
                    foreach (string f in files)
                    {
                        moduleChoices.AddTracedDirectory(f);
                    }
                }
                else
                {
                    foreach (string f in files)
                    {
                        moduleChoices.AddIgnoredDirectory(f);
                    }
                }
            }
        }

        public void AddFilesToTracingList(List<string> files)
        {

            BinaryTarget? activeTarget = rgatState.ActiveTarget;
            if (activeTarget is not null)
            {
                TraceChoiceSettings moduleChoices = activeTarget.LaunchSettings.TraceChoices;
                if (moduleChoices.TracingMode == ModuleTracingMode.eDefaultIgnore)
                {
                    foreach (string f in files)
                    {
                        moduleChoices.AddTracedFile(f);
                    }
                }
                else
                {
                    foreach (string f in files)
                    {
                        moduleChoices.AddIgnoredFile(f);
                    }
                }
            }
        }
    }

}
