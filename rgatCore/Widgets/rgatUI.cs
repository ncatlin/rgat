using Humanizer;
using ImGuiNET;
using rgat.Config;
using rgat.Widgets;
using System;
using System.Collections.Generic;
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

        //hardware resources
        private readonly ImGuiController _controller;
        private readonly GraphicsDevice _gd;

        //widgets
        private SandboxChart? chart;
        private VisualiserTab? visualiserTab;

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
        private double _StartupProgress = 0;
        public double StartupProgress
        {
            get => _StartupProgress; set
            {
                if (_StartupProgress < 1)
                {
                    _StartupProgress = value;
                }
            }
        }


        public static double UIDrawFPS = 0;
        private List<double> _lastFrameTimeMS = new List<double>();
        private int _selectedInstrumentationLevel = 0;
        private readonly List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        private float _mouseWheelDelta = 0;
        private Vector2 _mouseDragDelta = new Vector2(0, 0);

        private bool DialogOpen => _controller.DialogOpen;
        public bool MenuBarVisible => (_rgatState.ActiveTarget is not null || 
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
            _gd = _controller.graphicsDevice;
            _logsWindow = new LogsWindow(_rgatState);

        }

        ~rgatUI() { }

        public void InitWidgets(IProgress<float> progress)
        {
            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            Logging.RecordLogEvent("Startup: Initing graph display widgets", Logging.LogFilterType.TextDebug);

            visualiserTab = new VisualiserTab(_rgatState, _controller);


            Logging.RecordLogEvent($"Startup: Visualiser tab created in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Restart();
            visualiserTab.Init(_gd, progress);
            visualiserTab.SetDialogStateChangeCallback((bool state) => _controller.DialogChange(opened: state));

            Logging.RecordLogEvent($"Startup: Visualiser tab initialised in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Restart();

            chart = new SandboxChart(_controller._unicodeFont);

            Logging.RecordLogEvent($"Startup: Analysis chart loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Stop();
        }

        public void InitSettingsMenu()
        {
            _SettingsMenu = new SettingsMenu(_controller); //call after config init, so theme gets generated
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
            _activeTargetRunnable = _rgatState.ActiveTarget != null && _rgatState.ActiveTarget.IsAccessible;

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

            if (_rgatState?.ActiveTarget == null)
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
        }


        /// <summary>
        /// Draws any open dialogs
        /// </summary>
        /// 
        /// This isn't great but coming up with something more elegant can wait
        public void DrawDialogs()
        {
            if (!_controller.DialogOpen)
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

                BinaryTarget? activeTarget = _rgatState.ActiveTarget;
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
                Logging.WriteConsole($"Startup progress: {StartupProgress}");
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
                if (!_controller.DialogOpen)
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
                                Logging.RecordLogEvent($"Known keybind setting: {KeyModifierTuple.Item2}_{KeyModifierTuple.Item1}", LogFilterType.TextDebug);
                                continue;
                        }
                    }


                    bool isKeybind = GlobalConfig.Settings.Keybinds.Active.TryGetValue(KeyModifierTuple, out eKeybind boundAction);
                    if (isKeybind)
                    {
                        //cancel any open dialogs
                        if (boundAction == eKeybind.Cancel)
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
                        switch (boundAction)
                        {
                            case eKeybind.ToggleVideo:
                                if (DialogOpen)
                                {
                                    continue;
                                }

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

                            case eKeybind.PauseVideo:
                                if (DialogOpen)
                                {
                                    continue;
                                }

                                ActivateNotification();
                                if (rgatState.VideoRecorder.Recording)
                                {
                                    rgatState.VideoRecorder.CapturePaused = !rgatState.VideoRecorder.CapturePaused;
                                }
                                continue;

                            case eKeybind.CaptureGraphImage:
                                if (DialogOpen)
                                {
                                    continue;
                                }

                                PendingScreenshot = VideoEncoder.CaptureContent.Graph;

                                continue;
                            case eKeybind.CaptureGraphPreviewImage:
                                if (DialogOpen)
                                {
                                    continue;
                                }

                                PendingScreenshot = VideoEncoder.CaptureContent.GraphAndPreviews;

                                continue;
                            case eKeybind.CaptureWindowImage:
                                if (DialogOpen)
                                {
                                    continue;
                                }

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
        }

        private void ToggleTestHarness()
        {
            if (_show_test_harness == false)
            {
                if (_testHarness == null)
                {
                    _testHarness = new TestsWindow(_rgatState, _controller);
                }
            }
            _show_test_harness = !_show_test_harness;
            _controller.DialogChange(_show_test_harness);
        }

        private void ToggleRemoteDialog()
        {
            if (_show_remote_dialog == false)
            {
                if (_RemoteDialog == null)
                {
                    _RemoteDialog = new RemoteDialog();
                }
            }
            _show_remote_dialog = !_show_remote_dialog;
            _controller.DialogChange(_show_remote_dialog);
        }

        private void ToggleLoadTraceWindow()
        {
            _show_load_trace_window = !_show_load_trace_window;
            _controller.DialogChange(_show_load_trace_window);
        }

        private void ToggleLoadExeWindow()
        {
            _show_select_exe_window = !_show_select_exe_window;
            _controller.DialogChange(_show_select_exe_window);
        }

        private void ToggleTraceListSelectionWindow()
        {
            _show_tracelist_selection_window = !_show_tracelist_selection_window;
            _controller.DialogChange(_show_tracelist_selection_window);
        }

        private void ToggleSettingsWindow()
        {
            _show_settings_window = !_show_settings_window;
            _controller.DialogChange(_show_settings_window);
        }

        private void ToggleLogsWindow()
        {
            Logging.WriteConsole($"Logwindow toggle {_show_logs_window}");
            _show_logs_window = !_show_logs_window;
            _controller.DialogChange(_show_logs_window);
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
                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
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
            float logMenuX = 0;
            if (ImGui.BeginMenuBar())
            {
                DrawOuterLeftMenuItems();
                DrawInnerLeftMenuItems();
                DrawInnerRightMenuItems();
                DrawOuterRightMenuItems(out logMenuX);
                ImGui.EndMenuBar();
            }
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
                    foreach (var entry in recentbins.Take(Math.Min(10, recentbins.Length)).Reverse())
                    {
                        if (DrawRecentPathEntry(entry, true))
                        {
                            LoadSelectedBinary(entry.Path, rgatState.ConnectedToRemote);
                        }
                    }
                    ImGui.EndMenu();
                }

                var recenttraces = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Trace);
                if (ImGui.BeginMenu("Recent Traces", recenttraces.Any()))
                {
                    foreach (var entry in recenttraces.Take(Math.Min(10, recenttraces.Length)).Reverse())
                    {
                        if (DrawRecentPathEntry(entry, true))
                        {
                            LoadTraceByPath(entry.Path);
                        }
                    }
                    ImGui.EndMenu();
                }
                if (ImGui.MenuItem("Open Saved Trace")) { ToggleLoadTraceWindow(); }
                ImGui.Separator();
                if (ImGui.MenuItem("Save Thread Trace")) { } //todo
                if (ImGui.MenuItem("Save Process Traces")) { } //todo
                if (ImGui.MenuItem("Save All Traces")) { rgatState.SaveAllTargets(); }
                if (ImGui.MenuItem("Export Pajek"))
                {
                    TraceRecord? record = _rgatState.ActiveTrace;
                    PlottedGraph? graph = _rgatState.ActiveGraph;
                    if (record is not null && graph is not null)
                    {
                        rgatState.ExportTraceAsPajek(record, graph.TID);
                    }
                }
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
                if (ImGui.MenuItem(ImGuiController.FA_ICON_NETWORK + " Remote Mode", null, ref rdlgshown))
                {
                    ToggleRemoteDialog();
                }
                System.Net.IPEndPoint? endpoint = rgatState.NetworkBridge.RemoteEndPoint;
                if (endpoint is not null)
                {
                    SmallWidgets.MouseoverText($"Samples will be executed on {endpoint.Address}");
                }
            }
            else
            {
                if (ImGui.MenuItem(ImGuiController.FA_ICON_LOCALCODE + " Local Mode", null, ref rdlgshown))
                {
                    ToggleRemoteDialog();
                }
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
                    Logging.RecordError($"Exception processing screenshot notification: {e.Message}");
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
            uint textColour = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.Text)).ToUint(alpha);
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
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourWRF(Themes.eThemeColour.eTextEmphasis1).ToUint(alpha));
                    ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA} Recording Started");
                    ImGui.PopStyleColor();
                }
                else
                {
                    //fade out
                    uint alpha = MSago < StateChangeSolidTime ? 255 : (uint)(255.0 * (1.0 - ((MSago - StateChangeSolidTime) / StateChangeFadeTime)));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourWRF(Themes.eThemeColour.eTextEmphasis2).ToUint(alpha));
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
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
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

                Logging.RecordLogEvent($"Opening {label} directory in file browser: {path}", LogFilterType.TextDebug);
                System.Diagnostics.ProcessStartInfo openRequestedDir = new System.Diagnostics.ProcessStartInfo() { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(startInfo: openRequestedDir);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Exception {e.Message} opening {label} directory {path}");
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
            ImGui.MenuItem("Demo", null, ref _controller.ShowDemoWindow, true);


            X -= (ImGui.CalcTextSize("Tests ").X + 20);
            ImGui.SetCursorPosX(X);
            bool isShown = _show_test_harness;
            if (ImGui.MenuItem("Tests", null, ref isShown, true))
            {
                ToggleTestHarness();
            }


            Vector2 logBtnTextSize = ImGui.CalcTextSize("Logs (25) ");
            X -= (logBtnTextSize.X + 20);
            logMenuX = X + logBtnTextSize.X / 2f;
            ImGui.SetCursorPosX(X);
            int unseenErrors = Logging.UnseenAlerts;
            uint itemColour = unseenErrors > 0 ? Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour) : Themes.GetThemeColourImGui(ImGuiCol.Text);
            ImGui.PushStyleColor(ImGuiCol.Text, itemColour);
            bool menuDrawn = _show_logs_window;
            ImGui.MenuItem($"Logs{(unseenErrors > 0 ? $" ({unseenErrors})" : "")}", null, ref menuDrawn);
            ImGui.PopStyleColor();
            if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByPopup))
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
            //Vector2 popupBR = new Vector2(Math.Min(ImGui.GetCursorPosX(), windowSize.X - (widestAlert + 100)), ImGui.GetCursorPosY() + 150);
            //ImGui.SetNextWindowPos(new Vector2(popupBR.X, popupBR.Y));
            int alertCount = Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alertCount == 0)
            {
                return;
            }

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
        }

        private bool DrawAlerts(Vector2 logMenuPosition)
        {

            const double lingerTime = UI.ALERT_TEXT_LINGER_TIME;
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

            Vector2 originalCursorPos = ImGui.GetCursorScreenPos();
            if (GlobalConfig.Settings.UI.AlertAnimation && timeSinceLast < UI.ALERT_CIRCLE_ANIMATION_TIME)
            {
                uint color = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.Text)).ToUint(150);
                float radius = (float)(UI.ALERT_CIRCLE_ANIMATION_RADIUS * (1 - (timeSinceLast / UI.ALERT_CIRCLE_ANIMATION_TIME)));
                ImGui.GetForegroundDrawList().AddCircle(logMenuPosition, radius, color);
            }

            float widestAlert = 0;

            for (var i = Math.Max(alerts.Length - 2, 0); i < alerts.Length; i++)
            {
                widestAlert = Math.Max(widestAlert, ImGui.CalcTextSize(((TEXT_LOG_EVENT)alerts[i]).Text).X + 50);
            }

            Vector2 windowSize = ImGui.GetWindowSize();
            float width = Math.Min(widestAlert + 10, windowSize.X / 2f);
            Vector2 size = new Vector2(width, 38);
            ImGui.SetCursorScreenPos(new Vector2(windowSize.X - width, 32));


            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBg));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 1));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(1, 0));
            if (ImGui.BeginChild("##alertpopchildfrm", size))
            {
                uint textColour = Themes.GetThemeColourImGui(ImGuiCol.Text);
                WritableRgbaFloat errColour = Themes.GetThemeColourWRF(Themes.eThemeColour.eBadStateColour);
                WritableRgbaFloat alertColour = Themes.GetThemeColourWRF(Themes.eThemeColour.eTextEmphasis1);

                long nowTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                for (var i = Math.Max(alerts.Length - 2, 0); i < alerts.Length; i++)
                {
                    TEXT_LOG_EVENT item = (TEXT_LOG_EVENT)alerts[i];
                    long alertAge = nowTime - item.EventTimeMS;
                    long timeRemaining = (long)lingerTime - alertAge;
                    int alpha = 255;
                    if (timeRemaining < 1000) //fade out over a second
                    {
                        float fade = (timeRemaining / 1000f);
                        alpha = (int)(Math.Min(255f, 255f * fade));
                        alpha = Math.Max(alpha, 0);
                    }
                    if (item.Filter == LogFilterType.TextAlert)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, alertColour.ToUint((uint?)alpha));
                        ImGui.Text($"{ImGuiController.FA_ICON_WARNING} ");
                        ImGui.PopStyleColor();
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, errColour.ToUint((uint?)alpha));
                        ImGui.Text($"{ImGuiController.FA_ICON_EXCLAIM} ");
                        ImGui.PopStyleColor();
                    }
                    ImGui.SameLine();
                    textColour = new WritableRgbaFloat(textColour).ToUint((uint?)alpha);
                    ImGui.PushStyleColor(ImGuiCol.Text, textColour);
                    ImGui.Text(item.Text);
                    ImGui.PopStyleColor();

                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleColor();

            ImGui.SetCursorScreenPos(originalCursorPos);
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

            BinaryTarget? activeTarget = _rgatState.ActiveTarget;
            //there shouldn't actually be a way to select a null target once one is loaded
            string activeString = (activeTarget == null) ? "No target selected" : activeTarget.FilePath;
            List<string> paths = rgatState.targets.GetTargetPaths();
            ImGuiComboFlags flags = 0;
            float textWidth = Math.Max(ImGui.GetContentRegionAvail().X / 2.5f, ImGui.CalcTextSize(activeString).X + 50);
            textWidth = Math.Min(ImGui.GetContentRegionAvail().X - 300, textWidth);
            ImGui.SetNextItemWidth(textWidth);
            if (ImGui.BeginCombo("Selected Binary", activeString, flags))
            {
                foreach (string path in paths)
                {
                    bool is_selected = activeTarget != null && activeTarget.FilePath == path;
                    if (ImGui.Selectable(path, is_selected))
                    {
                        _rgatState.SetActiveTarget(path);
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
                _rgatState.SelectActiveTrace(newest: true);
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
                    DrawTraceTab(_rgatState.ActiveTarget);
                }
                else
                {
                    _tooltipScrollingActive = false;
                }


                //is there a better way to do this?
                if (_SwitchToVisualiserTab)
                {
                    tabDrawn = ImGui.BeginTabItem("Visualiser", ref tabDrawn, ImGuiTabItemFlags.SetSelected);
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
                }

                DrawAnalysisTab(_rgatState.ActiveTrace);


                DrawMemDataTab();
                ImGui.EndTabBar();
            }

        }

        public static bool IsrgatSavedTrace(string filestart)
        {
            if (filestart.StartsWith("{\""))
            {
                return true;
            }

            if (filestart.StartsWith("RGZ"))
            {
                return true;
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
                    Logging.RecordLogEvent($"Loading binary {path} failed: File does not exist", filter: LogFilterType.TextAlert);
                    return false;
                }

                FileStream fs = File.OpenRead(path);
                if (fs.Length < 4)
                {
                    Logging.RecordLogEvent($"Loading binary {path} failed: File too small ({fs.Length} bytes)", filter: LogFilterType.TextAlert);
                    return false;
                }

                byte[] preview = new byte[4];
                fs.Read(preview, 0, preview.Length);
                fs.Close();
                bool isSavedTrace = false;
                try
                {
                    isSavedTrace = IsrgatSavedTrace(ASCIIEncoding.ASCII.GetString(preview));
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Unable to check if file {path} is a saved trace [{e.Message}]. Assuming it isn't", LogFilterType.TextDebug);
                }


                if (isSavedTrace)
                {
                    if (!LoadTraceByPath(path))
                    {
                        Logging.RecordLogEvent($"Failed loading invalid trace: {path}", filter: LogFilterType.TextAlert);
                        return false;
                    }
                    _SwitchToTraceSelectTab = true;
                }
                else
                {
                    _rgatState.SetActiveTarget(path: null);
                    GlobalConfig.Settings.RecentPaths.RecordRecentPath(rgatSettings.PathType.Binary, path);
                    _rgatState.AddTargetByPath(path);
                    _SwitchToTraceSelectTab = true;
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading target binary: {e.Message}");
                return false;
            }

            return true;
        }

        private bool LoadRemoteBinary(string path)
        {
            if (!rgatState.ConnectedToRemote)
            {
                Logging.RecordLogEvent($"Loading remote binary {path} failed: Not Connected", filter: LogFilterType.TextAlert);
                return false;
            }

            _rgatState.SetActiveTarget(path: null);
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
            if (filepath is null || !File.Exists(filepath))
            {
                Logging.RecordError($"Failed to load missing trace file: {filepath}");
                return false;
            }

            if (!_rgatState.LoadTraceByPath(filepath, out TraceRecord? trace) || trace is null)
            {
                Logging.RecordError($"Failed to load invalid trace: {filepath}");
                return false;
            }
            GlobalConfig.Settings.RecentPaths.RecordRecentPath(rgatSettings.PathType.Trace, filepath);

            BinaryTarget target = trace.Target;

            //todo only if signatures not stored in trace + file exists on disk
            rgatState.DIELib?.StartDetectItEasyScan(target);
            rgatState.YARALib?.StartYARATargetScan(target);

            StartTraceDisplayWorkers(trace, _rgatState);

            _rgatState.ActiveTarget = target;
            _rgatState.SelectActiveTrace(target.GetFirstTrace());

            //_rgatState.SwitchTrace = trace;

            //ui.dynamicAnalysisContentsTab.setCurrentIndex(eVisualiseTab);
            return true;
        }

        private void StartTraceDisplayWorkers(TraceRecord trace, rgatState clientState)
        {
            ProcessLaunching.launch_saved_process_threads(trace, clientState);

            foreach (TraceRecord childTrace in trace.children)
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
                        LoadTraceByPath(picker.SelectedFile);
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    shown = false;
                }

                ImGui.EndPopup();
            }
        }


        public void DrawTraceListSelectBox(ref bool shown)
        {

            string? startdir = _rgatState.ActiveTarget != null ? Path.GetDirectoryName(_rgatState.ActiveTarget.FilePath) : null;
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
            BinaryTarget? activeTarget = _rgatState.ActiveTarget;
            if (activeTarget is not null)
            {
                if (activeTarget.TraceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
                {
                    foreach (string f in files)
                    {
                        activeTarget.TraceChoices.AddTracedDirectory(f);
                    }
                }
                else
                {
                    foreach (string f in files)
                    {
                        activeTarget.TraceChoices.AddIgnoredDirectory(f);
                    }
                }
            }
        }

        public void AddFilesToTracingList(List<string> files)
        {

            BinaryTarget? activeTarget = _rgatState.ActiveTarget;
            if (activeTarget is not null)
            {
                if (activeTarget.TraceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
                {
                    foreach (string f in files)
                    {
                        activeTarget.TraceChoices.AddTracedFile(f);
                    }
                }
                else
                {
                    foreach (string f in files)
                    {
                        activeTarget.TraceChoices.AddIgnoredFile(f);
                    }
                }
            }
        }
    }

}
