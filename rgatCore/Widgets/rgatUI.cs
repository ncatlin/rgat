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



        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private bool _show_load_trace_window = false;
        private bool _show_test_harness = false;
        private bool _show_remote_dialog = false;

        public double StartupProgress;
        List<double> _lastFrameTimeMS = new List<double>();
        private int _selectedInstrumentationLevel = 0;

        List<Tuple<Key, ModifierKeys>> _keyPresses = new List<Tuple<Key, ModifierKeys>>();
        float _mouseWheelDelta = 0;
        Vector2 _mouseDragDelta = new Vector2(0, 0);


        bool _splashHeaderHover = false;
        bool _scheduleMissingPathCheck = true;

        public VideoEncoder.CaptureContent PendingScreenshot = VideoEncoder.CaptureContent.Invalid;

        private readonly object _inputLock = new object();


        public rgatUI(rgatState state, ImGuiController controller)
        {
            _rgatState = state;
            _controller = controller;
            _gd = _controller.graphicsDevice;
        }

        ~rgatUI()
        {
        }

        public void InitWidgets()
        {
            StartupProgress = 0.55;


            Logging.RecordLogEvent("Startup: Initing graph display widgets", Logging.LogFilterType.TextDebug);

            StartupProgress = 0.60;
            visualiserTab = new VisualiserTab(_rgatState);
            visualiserTab.Init(_gd, _controller);


            chart = new SandboxChart();

            StartupProgress = 0.9;

            _SettingsMenu = new SettingsMenu(_controller, _rgatState); //call after config init, so theme gets generated




            _LogFilters[(int)Logging.LogFilterType.TextDebug] = true;
            _LogFilters[(int)Logging.LogFilterType.TextInfo] = true;
            _LogFilters[(int)Logging.LogFilterType.TextError] = true;
            _LogFilters[(int)Logging.LogFilterType.TextAlert] = true;
        }

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
                DrawMainMenu();
                DrawWindowContent();
            }
        }


        public void DrawDialogs()
        {
            if (_settings_window_shown) _SettingsMenu.Draw(ref _settings_window_shown);
            if (_show_select_exe_window) DrawFileSelectBox(ref _show_select_exe_window);
            if (_show_load_trace_window) DrawTraceLoadBox(ref _show_load_trace_window);
            if (_show_test_harness) _testHarness.Draw(ref _show_test_harness);
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
                if (DrawAlertBox())
                {
                    //raise the tabs up so the alert box nestles into the space
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 12);
                }

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


        bool DrawAlertBox()
        {
            int alertCount = Logging.GetAlerts(8, out LOG_EVENT[] alerts);
            if (alerts.Length == 0) return false;

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

            float width = Math.Max(widestAlert, 250);
            width = Math.Min(widestAlert, ImGui.GetContentRegionAvail().X - 30);
            Vector2 size = new Vector2(width, 38);
            ImGui.SameLine(ImGui.GetWindowContentRegionMax().X - (width + 6));


            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBg));
            ImGui.PushStyleColor(ImGuiCol.Border, Themes.GetThemeColourUINT(Themes.eThemeColour.eAlertWindowBorder));
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 1));
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(1, 0));
            Vector2 popupBR = new Vector2(Math.Min(ImGui.GetCursorPosX(), ImGui.GetWindowSize().X - (widestAlert + 100)), ImGui.GetCursorPosY() + 150);
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

                    if (isKeybind)
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
                    if (ImGui.MenuItem("Exit"))
                    {
                        ExitFlag = true;
                        // Task.Run(() => { Exit(); });
                    }
                    ImGui.EndMenu();
                }


                ImGui.MenuItem("Settings", null, ref _settings_window_shown);
                ImGui.MenuItem("Network", null, ref _show_remote_dialog);

                ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X - 30);
                bool isShown = _show_test_harness;
                if (ImGui.MenuItem("Tests", null, ref isShown, true))
                {
                    ToggleTestHarness();
                }

                ImGui.MenuItem("Demo", null, ref _controller.ShowDemoWindow, true);
                ImGui.EndMenuBar();
            }
        }

        public bool ExitFlag = false;

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

        bool _SwitchToLogsTab = false;
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
