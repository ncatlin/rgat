using Humanizer;
using ImGuiNET;
using rgat.Config;
using rgat.Threads;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Veldrid;
using Veldrid.Sdl2;
using static rgat.Logging;
using static rgat.RGAT_CONSTANTS;

namespace rgat
{
    partial class rgatUI
    {
        //all-modes state
        rgatState _rgatState;

        //hardware resources
        ImGuiController _controller;
        GraphicsDevice _gd;

        //widgets
        SandboxChart chart;
        VisualiserTab visualiserTab;

        //dialogs
        RemoteDialog _RemoteDialog;
        TestsWindow _testHarness;
        SettingsMenu _SettingsMenu;
        LogsWindow _logsWindow;

        /// <summary>
        /// Causes the UI to fall out of the update loop and initiate rgat shutdown
        /// </summary>
        public bool ExitFlag = false;


        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private bool _show_test_harness = false;
        private bool _show_logs_window = false;
        private bool _show_remote_dialog = false;

        public double StartupProgress;
        List<double> _lastFrameTimeMS = new List<double>();
        private int _selectedInstrumentationLevel = 0;

        List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        float _mouseWheelDelta = 0;
        Vector2 _mouseDragDelta = new Vector2(0, 0);

        public bool MenuBarVisible => (_rgatState.ActiveTarget != null || _splashHeaderHover || _activeNotification || _logsWindow.RecentAlert());
        bool _splashHeaderHover = false;
        bool _activeNotification = false;
        bool _scheduleMissingPathCheck = true;

        public VideoEncoder.CaptureContent PendingScreenshot { get; private set; } = VideoEncoder.CaptureContent.Invalid;
        VideoEncoder.CaptureContent _lastScreenShot = VideoEncoder.CaptureContent.Invalid;
        string _lastScreenShotPath = "";
        DateTime _screenShotTime;


        private readonly object _inputLock = new object();


        public rgatUI(rgatState state, ImGuiController controller)
        {
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

            visualiserTab = new VisualiserTab(_rgatState);


            Logging.RecordLogEvent($"Startup: Visualiser tab created in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Restart();
            visualiserTab.Init(_gd, _controller, progress);

            Logging.RecordLogEvent($"Startup: Visualiser tab initialised in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Restart();

            chart = new SandboxChart();

            Logging.RecordLogEvent($"Startup: Analysis chart loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Stop();
        }

        public void InitSettingsMenu()
        {
            _SettingsMenu = new SettingsMenu(_controller, _rgatState); //call after config init, so theme gets generated
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
            rgatState.UIDrawFPS = Math.Min(101, 1000.0 / (_lastFrameTimeMS.Average()));


            if (_scheduleMissingPathCheck)
            {
                CheckMissingPaths();
                _scheduleMissingPathCheck = false;
            }
            _activeTargetRunnable = _rgatState.ActiveTarget != null && _rgatState.ActiveTarget.IsRunnable;

        }

        // keep checking the files in the loading panes so we can highlight if they are deleted (or appear)
        void CheckMissingPaths()
        {
            foreach (var path in GlobalConfig.RecentBinaries.Concat(GlobalConfig.RecentTraces))
            {
                if (!_missingPaths.Contains(path.path) && !File.Exists(path.path))
                {
                    _missingPaths.Add(path.path);
                }
            }
        }


        public void UpdateFrameStats(long elapsedMS)
        {
            _lastFrameTimeMS.Add(elapsedMS);
            if (_lastFrameTimeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
                _lastFrameTimeMS = _lastFrameTimeMS.TakeLast(GlobalConfig.StatisticsTimeAvgWindow).ToList();

            if (visualiserTab != null)
                visualiserTab.UIFrameAverage = _lastFrameTimeMS.Average();
        }


        public void GetFrameDimensions(VideoEncoder.CaptureContent frameType, out int startX, out int startY, out int width, out int height)
        {
            switch (frameType)
            {
                case VideoEncoder.CaptureContent.Graph:
                    height = (int)visualiserTab.GraphSize.Y;
                    width = (int)visualiserTab.GraphSize.X;
                    startX = (int)visualiserTab.GraphPosition.X;
                    startY = (int)visualiserTab.GraphPosition.Y;
                    break;
                case VideoEncoder.CaptureContent.GraphAndPreviews:
                    height = (int)visualiserTab.GraphSize.Y;
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
                DrawMainMenu();
        }


        public void DrawDialogs()
        {
            if (_settings_window_shown && _SettingsMenu != null) _SettingsMenu.Draw(ref _settings_window_shown);
            if (_show_select_exe_window) DrawFileSelectBox(ref _show_select_exe_window);
            if (_show_load_trace_window) DrawTraceLoadBox(ref _show_load_trace_window);
            if (_show_test_harness) _testHarness.Draw(ref _show_test_harness);
            if (_show_logs_window) _logsWindow.Draw(ref _show_logs_window);
            if (_show_remote_dialog)
            {
                if (_RemoteDialog == null) { _RemoteDialog = new RemoteDialog(_rgatState); }
                _RemoteDialog.Draw(ref _show_remote_dialog);
            }
        }

        public void CleanupFrame()
        {
            if (!_tooltipScrollingActive && _tooltipScroll != 0)
                _tooltipScroll = 0;
        }




        void DrawWindowContent()
        {
            if (ImGui.BeginChild("MainWindow", ImGui.GetContentRegionAvail(), false, ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoScrollbar))
            {
                DrawTargetBar();

                BinaryTarget activeTarget = _rgatState.ActiveTarget;
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
            if (StartupProgress < 1) return;
            if (_mouseWheelDelta != 0)
            {
                if (_tooltipScrollingActive)
                {
                    _tooltipScroll -= _mouseWheelDelta * 60;
                    if (_tooltipScroll < 0) _tooltipScroll = 0;
                    _mouseWheelDelta = 0;
                    return;
                }
            }
            _tooltipScrollingActive = false;

            bool currentTabVisualiser = _currentTab == "Visualiser";
            bool currentTabTimeline = _currentTab == "Timeline";
            lock (_inputLock)
            {
                bool MouseInMainWidget = currentTabVisualiser && visualiserTab.MouseInMainWidget;
                if (_mouseWheelDelta != 0)
                {
                    visualiserTab.NotifyMouseWheel(_mouseWheelDelta);

                    chart?.ApplyZoom(_mouseWheelDelta);
                    _mouseWheelDelta = 0;
                }

                if (_mouseDragDelta.X != 0 || _mouseDragDelta.Y != 0)
                {
                    if (ImGui.GetIO().KeyAlt)
                    {
                        visualiserTab.NotifyMouseRotate(_mouseDragDelta);
                    }
                    else
                    {
                        visualiserTab.NotifyMouseDrag(_mouseDragDelta);
                        if (currentTabTimeline)
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
                        if (visualiserTab.AlertKeybindPressed(boundAction, KeyModifierTuple)) continue;

                        //cancel any open dialogs
                        if (boundAction == eKeybind.Cancel)
                            CloseDialogs();
                    }


                    //could be a quickmenu shortcut
                    if (visualiserTab.AlertRawKeyPress(KeyModifierTuple)) continue;

                    if (isKeybind && !_settings_window_shown)
                    {
                        switch (boundAction)
                        {
                            case eKeybind.ToggleVideo:
                                if (rgatState.VideoRecorder.Recording)
                                {
                                    rgatState.VideoRecorder.Done();
                                }
                                else
                                {
                                    rgatState.VideoRecorder.StartRecording();
                                }
                                continue;

                            case eKeybind.PauseVideo:
                                if (rgatState.VideoRecorder.Recording)
                                {
                                    rgatState.VideoRecorder.CapturePaused = !rgatState.VideoRecorder.CapturePaused;
                                }
                                continue;

                            case eKeybind.CaptureGraphImage:
                                if (currentTabVisualiser)
                                {
                                    PendingScreenshot = VideoEncoder.CaptureContent.Graph;
                                }
                                continue;
                            case eKeybind.CaptureGraphPreviewImage:
                                if (currentTabVisualiser)
                                {
                                    PendingScreenshot = VideoEncoder.CaptureContent.GraphAndPreviews;
                                }
                                continue;
                            case eKeybind.CaptureWindowImage:
                                PendingScreenshot = VideoEncoder.CaptureContent.Window;
                                continue;
                            default:
                                break;
                        }


                        if (currentTabVisualiser)
                        {
                            visualiserTab.AlertKeybindPressed(boundAction, KeyModifierTuple);
                        }

                        else if (currentTabTimeline)
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
            if (_SettingsMenu.HasPendingKeybind)
            {
                _SettingsMenu.HasPendingKeybind = false;
                return;
            }

            _show_load_trace_window = false;
            _settings_window_shown = false;
            _show_remote_dialog = false;
            _show_test_harness = false;
            _show_select_exe_window = false;
        }


        void ToggleTestHarness()
        {
            if (_show_test_harness == false)
            {
                if (_testHarness == null) _testHarness = new TestsWindow(_rgatState, _controller);
            }
            _show_test_harness = !_show_test_harness;
        }

        void ToggleRemoteDialog()
        {
            if (_show_remote_dialog == false)
            {
                if (_RemoteDialog == null) _RemoteDialog = new RemoteDialog(_rgatState);// _rgatState, _controller);
            }
            _show_remote_dialog = !_show_remote_dialog;
        }


        bool DrawRecentPathEntry(GlobalConfig.CachedPathData pathdata, bool menu)
        {

            string pathshort = pathdata.path;
            bool isMissing = _missingPaths.Contains(pathdata.path);
            bool isBad = _badPaths.Contains(pathdata.path);

            if (pathdata.path.ToLower().EndsWith(".rgat"))
            {
                int dateIdx = pathshort.LastIndexOf("__");
                if (dateIdx > 0)
                    pathshort = pathshort.Substring(0, dateIdx);
            }
            string agoText = $" ({pathdata.lastSeen.Humanize()})";
            if (ImGui.CalcTextSize(pathshort + agoText).X > ImGui.GetContentRegionAvail().X)
            {
                if (pathshort.Length > 50)
                    pathshort = pathshort.Truncate(50, "...", TruncateFrom.Left);
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
                ImGui.Text($"{pathdata.path}");
                ImGui.Text($"Most recently opened {pathdata.lastSeen.Humanize()}");
                ImGui.Text($"First opened {pathdata.firstSeen.Humanize()}");
                ImGui.Text($"Has been loaded {pathdata.count} times.");
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
            _activeNotification = false;
            if (ImGui.BeginMenuBar())
            {
                DrawOuterLeftMenuItems();
                DrawInnerLeftMenuItems();
                DrawInnerRightMenuItems();
                DrawOuterRightMenuItems();
                ImGui.EndMenuBar();
            }
            DrawAlerts(new Vector2(ImGui.GetWindowSize().X - 235, 18));
        }


        void DrawOuterLeftMenuItems()
        {
            if (ImGui.BeginMenu("Target"))
            {
                if (ImGui.MenuItem("Select Target Executable")) { _show_select_exe_window = true; }
                var recentbins = GlobalConfig.RecentBinaries;
                if (ImGui.BeginMenu("Recent Binaries", recentbins.Any()))
                {
                    foreach (var entry in recentbins.Take(Math.Min(10, recentbins.Count)))
                    {
                        if (DrawRecentPathEntry(entry, true))
                        {
                            LoadSelectedBinary(entry.path, rgatState.ConnectedToRemote);
                        }
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
                if (ImGui.MenuItem("Save Thread Trace")) { } //todo
                if (ImGui.MenuItem("Save Process Traces")) { } //todo
                if (ImGui.MenuItem("Save All Traces")) { _rgatState.SaveAllTargets(); }
                if (ImGui.MenuItem("Export Pajek")) { _rgatState.ExportTraceAsPajek(_rgatState.ActiveTrace, _rgatState.ActiveGraph.tid); }
                ImGui.Separator();
                ExitFlag = ImGui.MenuItem("Exit");
                ImGui.EndMenu();
            }

            ImGui.MenuItem("Settings", null, ref _settings_window_shown);
        }


        void DrawInnerLeftMenuItems()
        {
            float quarter = ImGui.GetContentRegionMax().X / 4f;
            ImGui.SetCursorPosX(quarter);
            if (rgatState.ConnectedToRemote)
            {
                ImGui.MenuItem(ImGuiController.FA_ICON_NETWORK + " Remote Mode", null, ref _show_remote_dialog);
                SmallWidgets.MouseoverText($"Samples will be executed on {rgatState.NetworkBridge.RemoteEndPoint.Address}");
            }
            else
            {
                ImGui.MenuItem(ImGuiController.FA_ICON_LOCALCODE + " Local Mode", null, ref _show_remote_dialog);
                SmallWidgets.MouseoverText("Samples will be executed on this computer");
            }
        }


        //todo recording status
        //todo screencap fade effect

        void DrawInnerRightMenuItems()
        {
            float quarter = 3 * (ImGui.GetContentRegionMax().X / 5f) - 50;
            ImGui.SetCursorPosX(quarter);

            //ImGui.MenuItem($"{ImGuiController.FA_VIDEO_CAMERA}" , false);

            if (_lastScreenShot != VideoEncoder.CaptureContent.Invalid)
            {
                _activeNotification = true;
                try
                {
                    DisplayScreenshotNotification();
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Exception processing screenshot notification: {e.Message}");
                    _lastScreenShot = VideoEncoder.CaptureContent.Invalid;
                }
            }
        }

        /// <summary>
        /// Displays the video camera icon on the menu bar
        /// Displays an animated rectangle drawing the eye to it, from the region captured
        /// UI.SCREENSHOT_ICON_LINGER_TIME controls how long the icon is displayed
        /// UI.SCREENSHOT_ANIMATION_RECT_SPEED controls how fast the rectangle travels/disappears
        /// </summary>
        void DisplayScreenshotNotification()
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
                string screenshotDirectory = Path.GetDirectoryName(_lastScreenShotPath);
                if (Directory.Exists(screenshotDirectory))
                {
                    Logging.RecordLogEvent($"Opening screenshot directory in file browser: {screenshotDirectory}", LogFilterType.TextDebug);
                    var openScreenshotDir = new System.Diagnostics.ProcessStartInfo() { FileName = screenshotDirectory, UseShellExecute = true };
                    System.Diagnostics.Process.Start(openScreenshotDir);
                }
                else if (File.Exists(screenshotDirectory))
                {
                    //probably a bit paranoid but no harm in being careful around process.start
                    Logging.RecordError("Screenshot directory became a file. Unconfiguring it");
                    GlobalConfig.SetDirectoryPath("MediaCapturePath", "", true);
                }
                else
                {
                    Logging.RecordError($"Screenshot directory {screenshotDirectory} was not found");
                }
            }

            double animationProgress = progress * UI.SCREENSHOT_ANIMATION_RECT_SPEED;
            if (animationProgress < 1)
            {
                Vector2? rectSize, startCenter;
                switch (_lastScreenShot)
                {
                    case VideoEncoder.CaptureContent.Graph:
                        Vector2 graphpos = visualiserTab.GraphPosition;
                        rectSize = visualiserTab.GraphSize;
                        startCenter = new Vector2(graphpos.X + rectSize.Value.X / 2, ImGui.GetWindowSize().Y - (graphpos.Y + rectSize.Value.Y / 2));
                        break;
                    case VideoEncoder.CaptureContent.GraphAndPreviews:
                        Vector2 graphpos2 = visualiserTab.GraphPosition;
                        rectSize = visualiserTab.GraphSize + new Vector2(RGAT_CONSTANTS.UI.PREVIEW_PANE_WIDTH, 0);
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
        /// Displays less-used utilities like logs, tests 
        /// </summary>
        void DrawOuterRightMenuItems()
        {
            int unseenErrors = Logging.UnseenAlerts;

            if (unseenErrors > 0) ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour));
            ImGui.SetCursorPosX(ImGui.GetContentRegionMax().X - 250);
            if(ImGui.MenuItem($"Logs{(unseenErrors > 0 ? $" ({unseenErrors})" : "")}", null, ref _show_logs_window))
            {
                _logsWindow.ShowAlerts();
            }
            if (unseenErrors > 0) ImGui.PopStyleColor();

            bool isShown = _show_test_harness;
            if (ImGui.MenuItem("Tests", null, ref isShown, true))
            {
                ToggleTestHarness();
            }

            ImGui.MenuItem("Demo", null, ref _controller.ShowDemoWindow, true);
        }



   
        bool DrawAlerts(Vector2 logMenuPosition)
        {

            const long lingerTime = UI.ALERT_TEXT_LINGER_TIME;
            double timeSinceLast = Logging.TimeSinceLastAlert.TotalMilliseconds;
            if (timeSinceLast > lingerTime) return false;

            int alertCount = Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alerts.Length == 0) return false;
            _activeNotification = true;

            Vector2 originalCursorPos = ImGui.GetCursorScreenPos();

            float animCircleTime = 600;
            float animCircleRadius = 100;
            if (timeSinceLast < animCircleTime)
            {
                uint color = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.Text)).ToUint(150);
               ImGui.GetForegroundDrawList().AddCircle(logMenuPosition, (float)(animCircleRadius * (1 - (timeSinceLast / animCircleTime))), color);
            }

            float widestAlert = 0;
            if (alerts.Length <= 2)
            {
                for (var i = Math.Max(alerts.Length - 2, 0); i < alerts.Length; i++)
                {
                    widestAlert = ImGui.CalcTextSize(((TEXT_LOG_EVENT)alerts[i])._text).X + 50;
                }
            }
            else
            {
                widestAlert = ImGui.CalcTextSize(((TEXT_LOG_EVENT)alerts[^1])._text).X + 50;
            }
            Vector2 windowSize = ImGui.GetWindowSize();
            float width = Math.Min(widestAlert + 10, windowSize.X/2f);
            Vector2 size = new Vector2(width, 38);
            ImGui.SetCursorScreenPos(new Vector2(windowSize.X - width, 32));


            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBg));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 1));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(1, 0));
            Vector2 popupBR = new Vector2(Math.Min(ImGui.GetCursorPosX(), windowSize.X - (widestAlert + 100)), ImGui.GetCursorPosY() + 150);
            if (ImGui.BeginChild("##alertpopchildfrm", size))
            {
                uint textColour = Themes.GetThemeColourImGui(ImGuiCol.Text);
                uint errColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                uint alertColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eTextEmphasis1);

                long nowTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                for (var i = Math.Max(alerts.Length - 2, 0); i < alerts.Length; i++)
                {
                    TEXT_LOG_EVENT item = (TEXT_LOG_EVENT)alerts[i];
                    long alertAge = nowTime - item.EventTimeMS;
                    long timeRemaining = lingerTime - alertAge;
                    uint alpha = 255;
                    if (timeRemaining < 1000) //fade out over a second
                    {
                        float fade = (timeRemaining / 1000);
                        alpha = (uint)(Math.Min(255f, 255f * fade));
                    }

                    if (item.Filter == LogFilterType.TextAlert)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(alertColour).ToUint(alpha));
                        ImGui.Text($"{ImGuiController.FA_ICON_WARNING} ");
                        ImGui.PopStyleColor();
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, new WritableRgbaFloat(errColour).ToUint(alpha));
                        ImGui.Text($"{ImGuiController.FA_ICON_EXCLAIM} ");
                        ImGui.PopStyleColor();
                    }
                    ImGui.SameLine();
                    textColour = new WritableRgbaFloat(textColour).ToUint(alpha);
                    ImGui.PushStyleColor(ImGuiCol.Text, textColour);
                    ImGui.Text(item._text);
                    ImGui.PopStyleColor();

                }
                ImGui.EndChild();
            }
            ImGui.PopStyleVar();
            ImGui.PopStyleVar();
            ImGui.PopStyleColor();

            if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByPopup))
            {
                if (ImGui.IsMouseClicked(ImGuiMouseButton.Left))
                {
                    _logsWindow.ShowAlerts();
                    _show_logs_window = true;

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
            _activeNotification = true;
        }



        /// <summary>
        /// Draws a dropdown allowing selection of one of the loaded target binaries
        /// </summary>
        /// <returns>true if at least one binary is loaded, otherwise false</returns>
        private unsafe bool DrawTargetBar()
        {

            if (rgatState.targets.count() == 0)
            {
                ImGui.Text("No target selected or trace loaded");
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                return false;
            }

            BinaryTarget activeTarget = _rgatState.ActiveTarget;
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
                        ImGui.SetItemDefaultFocus();
                }
                ImGui.EndCombo();
            }
            return true;
        }

        bool _SwitchToVisualiserTab = false;
        int _OldTraceCount = -1;
        string _currentTab = "";

        private unsafe void DrawTabs()
        {
            bool tabDrawn = false;
            ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;

            if (_OldTraceCount != -1 && rgatState.TotalTraceCount > _OldTraceCount)
            {
                _OldTraceCount = -1;
                _SwitchToVisualiserTab = true;
                visualiserTab.ClearPreviewTrace();
                _rgatState.SelectActiveTrace(newest: true);
            }

            if (ImGui.BeginTabBar("Primary Tab Bar", tab_bar_flags))
            {
                DrawTraceTab(_rgatState.ActiveTarget);

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
                    visualiserTab.Draw();
                }


                DrawAnalysisTab(_rgatState.ActiveTrace);


                DrawMemDataTab();
                ImGui.EndTabBar();
            }

        }

        public bool LoadSelectedBinary(string path, bool isRemote)
        {
            if (isRemote)
                return LoadRemoteBinary(path);

            if (!File.Exists(path))
            {
                Logging.RecordLogEvent($"Loading binary {path} failed: File does not exist", filter: LogFilterType.TextAlert);
                return false;
            }

            FileStream fs = File.OpenRead(path);
            bool isJSON = (fs.ReadByte() == '{' && fs.ReadByte() == '"');
            fs.Close();
            if (isJSON)
            {
                if (!LoadTraceByPath(path))
                {
                    Logging.RecordLogEvent($"Failed loading invalid trace: {path}", filter: LogFilterType.TextAlert);
                    return false;
                }
            }
            else
            {
                GlobalConfig.RecordRecentPath(path, GlobalConfig.eRecentPathType.Binary);
                _rgatState.AddTargetByPath(path);
            }
            return true;
        }


        bool LoadRemoteBinary(string path)
        {
            if (!rgatState.ConnectedToRemote)
            {
                Logging.RecordLogEvent($"Loading remote binary {path} failed: Not Connected", filter: LogFilterType.TextAlert);
                return false;
            }

            BinaryTarget target = _rgatState.AddRemoteTargetByPath(path, rgatState.NetworkBridge.LastAddress);
            rgatState.NetworkBridge.SendCommand("LoadTarget", "GUI", target.InitialiseFromRemoteData, path);

            return true;
        }


        public void DrawFileSelectBox(ref bool show_select_exe_window)
        {
            string title = "Select Executable";
            if (rgatState.ConnectedToRemote) title += " (Remote Machine)";
            ImGui.OpenPopup(title);
            if (ImGui.BeginPopupModal(title, ref show_select_exe_window, ImGuiWindowFlags.NoScrollbar))
            {

                rgatFilePicker.FilePicker picker;
                bool isRemote = rgatState.ConnectedToRemote;
                if (isRemote)
                {
                    picker = rgatFilePicker.FilePicker.GetRemoteFilePicker(this, rgatState.NetworkBridge);
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


        private bool LoadTraceByPath(string filepath)
        {
            if (!File.Exists(filepath))
            {
                Logging.RecordLogEvent($"Failed to load missing trace file: {filepath}", filter: LogFilterType.TextAlert);
                return false;
            }

            if (!_rgatState.LoadTraceByPath(filepath, out TraceRecord trace))
            {
                Logging.RecordLogEvent($"Failed to load invalid trace: {filepath}", filter: LogFilterType.TextAlert);
                return false;
            }
            GlobalConfig.RecordRecentPath(filepath, GlobalConfig.eRecentPathType.Trace);

            BinaryTarget target = trace.binaryTarg;

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


        void StartTraceDisplayWorkers(TraceRecord trace, rgatState clientState)
        {
            ProcessLaunching.launch_saved_process_threads(trace, clientState);

            foreach (TraceRecord childTrace in trace.children)
            {
                StartTraceDisplayWorkers(childTrace, clientState);
            }
        }


        public void DrawTraceLoadBox(ref bool show_load_trace_window)
        {
            ImGui.OpenPopup("Select Trace File");

            if (ImGui.BeginPopupModal("Select Trace File", ref show_load_trace_window, ImGuiWindowFlags.NoScrollbar))
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
                    show_load_trace_window = false;
                }

                ImGui.EndPopup();
            }
        }
    }

}
