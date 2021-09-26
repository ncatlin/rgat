using ImGuiNET;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgat
{
    internal partial class rgatUI
    {
        private void DrawTraceTab(BinaryTarget? activeTarget)
        {
            _SwitchToTraceSelectTab = false;
            _currentTab = "Start Trace";

            if (activeTarget is not null)
            {
                DrawTraceTab_FileInfo(activeTarget, ImGui.GetContentRegionAvail().X, ImGui.GetContentRegionAvail().Y/2);

                ImGui.BeginGroup();
                {
                    DrawTraceTab_InstrumentationSettings(activeTarget, ImGui.GetContentRegionAvail().X /2.5f);
                    ImGui.SameLine();
                    DrawTraceTab_ExecutionSettings(activeTarget, ImGui.GetContentRegionAvail().X);
                    ImGui.EndGroup();
                }
            }
            ImGui.EndTabItem();
        }

        private void DrawTraceTab_FileInfo(BinaryTarget activeTarget, float width, float height)
        {
            ImGui.BeginChildFrame(22, new Vector2(width, height), ImGuiWindowFlags.AlwaysAutoResize);

            if (activeTarget.RemoteHost != null && !activeTarget.RemoteInitialised)
            {
                if (rgatState.ConnectedToRemote)
                {
                    ImguiUtils.DrawRegionCenteredText("Initialising from remote host");
                }
                else
                {
                    ImguiUtils.DrawRegionCenteredText("Disconnected from remote host before metadata could be retrieved");
                }

                ImGui.EndChildFrame();
                return;
            }

            ImGui.BeginGroup();
            {
                if (ImGui.BeginTable("#BasicStaticFields", 2, ImGuiTableFlags.Borders , ImGui.GetContentRegionAvail()))
                {
                    ImGui.TableSetupColumn("#FieldName", ImGuiTableColumnFlags.WidthFixed, 135);
                    ImGui.TableSetupColumn("#FieldValue");

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Filename (Size)");
                    ImGui.TableNextColumn();
                    string fileStr = string.Format("{0} ({1})", activeTarget.FileName, activeTarget.GetFileSizeString());
                    byte[] _dataInput = Encoding.UTF8.GetBytes(fileStr);
                    ImGui.SetNextItemWidth(500);
                    ImGui.InputText("##filenameinp", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("SHA1 Hash");
                    ImGui.TableNextColumn();
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA1Hash());
                    ImGui.SetNextItemWidth(500);
                    ImGui.InputText("##s1hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("SHA256 Hash");
                    ImGui.TableNextColumn();
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA256Hash());
                    ImGui.SetNextItemWidth(500);
                    ImGui.InputText("##s256hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Hex Preview");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(500);
                    Controller.PushOriginalFont(); //original imgui font is monospace and UTF8, good for this
                    {
                        _dataInput = Encoding.UTF8.GetBytes(activeTarget.HexPreview);
                        ImGui.InputText("##hexprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                        _tooltipScrollingActive = _tooltipScrollingActive || ImGui.IsItemHovered();
                        if (ImGui.IsItemHovered())
                        {
                            ShowHexPreviewTooltip(activeTarget);
                        }
                    }
                    ImGui.PopFont();

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("ASCII Preview");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(500);
                    Controller.PushOriginalFont();
                    {
                        _dataInput = Encoding.ASCII.GetBytes(activeTarget.ASCIIPreview);
                        ImGui.InputText("##ascprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                        _tooltipScrollingActive = _tooltipScrollingActive || ImGui.IsItemHovered();
                        if (ImGui.IsItemHovered())
                        {
                            _tooltipScrollingActive = true;
                            ShowHexPreviewTooltip(activeTarget);
                        }
                    }
                    ImGui.PopFont();


                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text("Signature Scan");
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 12);
                    DrawDetectItEasyProgress(activeTarget, new Vector2(120, 25));
                    DrawYARAProgress(activeTarget, new Vector2(120, 25));


                    ImGui.TableNextColumn();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 12);
                    DrawSignaturesBox(activeTarget, 800);

                    ImGui.EndTable();
                }
            }

            // ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();

            if (_yaraPopupHit != null && !_hitHoverOnly)
            {
                DrawYaraPopup(false);
            }
        }

        private float _tooltipScroll = 0;
        private bool _tooltipScrollingActive;
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
                ImGui.SetScrollY(_tooltipScroll);
                float BoxSize = Math.Max(ImGui.GetContentRegionAvail().Y, (hexline.Length / 4608f) * 845f);
                ImGui.InputTextMultiline("##inplin1", ref hexline, (uint)hexline.Length, new Vector2(530, BoxSize), flags);
                if (_tooltipScroll > ImGui.GetScrollMaxY())
                {
                    _tooltipScroll = ImGui.GetScrollMaxY();
                }

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
            if (ImGui.BeginChild("TraceInstruSettings", new Vector2(width, ImGui.GetContentRegionAvail().Y - 20)))
            {
                if (activeTarget.IsLibrary)
                {
                    DrawDLLTraceSettings(activeTarget);
                    DrawModuleFilterControls(activeTarget, ImGui.GetContentRegionAvail().Y);
                }
                else
                {
                    DrawModuleFilterControls(activeTarget, ImGui.GetContentRegionAvail().Y);
                }
                ImGui.EndChild();
            }
        }


        private static void DrawDLLTraceSettings(BinaryTarget activeTarget)
        {
            ImGui.Indent(8);
            if (ImGui.BeginTable("#DLLSettingsTable", 2))
            {
                ImGui.TableSetupColumn("##DllSettingCaption", ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Export");
                ImGui.TableNextColumn();
                DrawExportPickerCombo(activeTarget);
                SmallWidgets.MouseoverText("Choose an export to run from the DLL");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Loader Name");
                ImGui.TableNextColumn();
                string loaderName = activeTarget.LoaderName;
                if (ImGui.InputText("##LoaderName", ref loaderName, 255))
                {
                    activeTarget.LoaderName = loaderName;
                }
                SmallWidgets.MouseoverText("If the DLL checks the name of the binary that launches it, enter a custom name here.\n" +
                    "The filename should not exist in the DLL directory.");
                ImGui.EndTable();
            }
            ImGui.Indent(-8);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 12);
        }

        private static void DrawExportPickerCombo(BinaryTarget activeTarget)
        {

            string preview = "";
            if (activeTarget.SelectedExportIndex == -1)
            {
                preview = "DllMain Only";
            }
            else
            {
                if (activeTarget.Exports.Count > activeTarget.SelectedExportIndex)
                {
                    var previewExport = activeTarget.Exports[activeTarget.SelectedExportIndex];
                    if (previewExport != null)
                    {
                        preview = $"{previewExport}";
                        preview += $" [#{previewExport.Item2}]";
                    }
                    else
                    {
                        preview = $"#{previewExport?.Item2}";
                    }
                }
            }

            if (ImGui.BeginCombo("##CmbExport", preview))
            {
                if (ImGui.Selectable("DllMain only"))
                {
                    activeTarget.SelectedExportIndex = -1;
                }
                for (int ordI = 0; ordI < activeTarget.Exports.Count; ordI++)
                {
                    var export = activeTarget.Exports[ordI];
                    string comboText = "";
                    string? name = export.Item1;
                    if (name != null)
                    {
                        comboText = $"{name} [#{export.Item2}]";
                    }
                    else
                    {
                        comboText = $"{export.Item2}";
                    }
                    if (ImGui.Selectable(comboText))
                    {
                        activeTarget.SelectedExportIndex = ordI;
                    }
                }
                ImGui.EndCombo();
            }

        }

        private void DrawModuleFilterControls(BinaryTarget activeTarget, float height)
        {
            ImGui.Indent(8);
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF992200);

                if (ImGui.BeginChild("ModFilterToggleChild", new Vector2(ImGui.GetContentRegionAvail().X, 40)))
                {
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text("Module Selection Mode");
                    ImGui.SameLine();
                    ImguiUtils.HelpMarker("Customise which libraries rgat will instrument. Tracing more code affects performance and makes resulting graphs more complex.");
                    ImGui.SameLine();
                    string TraceLabel = $"Default Trace [{activeTarget.TraceChoices.TraceDirCount + activeTarget.TraceChoices.TraceFilesCount}]";

                    int traceModeRef = activeTarget.TraceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore ? 0 : 1;
                    if (ImGui.RadioButton(TraceLabel, ref traceModeRef, 0))
                    {
                        activeTarget.TraceChoices.TracingMode = (eModuleTracingMode)traceModeRef;
                    };
                    ImGui.SameLine();
                    ImguiUtils.HelpMarker("Only specified libraries will be traced");
                    ImGui.SameLine();
                    string IgnoreLabel = $"Default Ignore [{activeTarget.TraceChoices.IgnoreDirsCount + activeTarget.TraceChoices.ignoreFilesCount}]";
                    if (ImGui.RadioButton(IgnoreLabel, ref traceModeRef, 1))
                    {
                        activeTarget.TraceChoices.TracingMode = (eModuleTracingMode)traceModeRef;
                    };
                    ImGui.SameLine();
                    ImguiUtils.HelpMarker("All libraries will be traced except for those on the ignore list");
                    ImGui.EndChild();
                }

                void DrawClickablePaths(List<string> paths, Action<string> clicked)
                {
                    ImGui.PushStyleColor(ImGuiCol.HeaderHovered, Themes.GetThemeColourWRF(Themes.eThemeColour.eBadStateColour).ToUint(160));
                    foreach (string fstr in paths)
                    {
                        ImGui.Selectable(fstr);
                        if (ImGui.IsItemClicked())
                        {
                            activeTarget.TraceChoices.RemoveIgnoredDirectory(fstr);
                        }
                    }
                    ImGui.PopStyleColor();
                }

                if (ImGui.BeginChild("ModFilterContentChild", new Vector2(ImGui.GetContentRegionAvail().X, ImGui.GetContentRegionAvail().Y)))
                {
                    ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFFdddddd);

                    if (ImGui.BeginChildFrame(ImGui.GetID("exclusionlist_contents"), ImGui.GetContentRegionAvail()))
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);
                        if (activeTarget.TraceChoices.TracingMode == eModuleTracingMode.eDefaultTrace)
                        {
                            int ignoredDirCount = activeTarget.TraceChoices.IgnoreDirsCount;
                            ImGui.SetNextItemOpen(true, ImGuiCond.Once);
                            if (ImGui.TreeNode($"Ignored Directories ({ignoredDirCount})"))
                            {
                                DrawClickablePaths(activeTarget.TraceChoices.GetIgnoredDirs(), (x) => { activeTarget.TraceChoices.RemoveIgnoredDirectory(x); });
                                ImGui.TreePop();
                            }
                            if (ignoredDirCount > 0 && ImGui.BeginPopupContextItem("IgnoreDirsClear", ImGuiPopupFlags.MouseButtonRight))
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                                if (ImGui.Selectable("Clear all ignored directories"))
                                {
                                    activeTarget.TraceChoices.ClearIgnoredDirs();
                                }

                                ImGui.PopStyleColor();
                                ImGui.EndPopup();
                            }

                            int ignoredFileCount = activeTarget.TraceChoices.ignoreFilesCount;
                            ImGui.SetNextItemOpen(true, ImGuiCond.Once);
                            if (ImGui.TreeNode($"Ignored Files ({ignoredFileCount})"))
                            {
                                DrawClickablePaths(activeTarget.TraceChoices.GetIgnoredFiles(), (x) => { activeTarget.TraceChoices.RemoveIgnoredFile(x); });
                                ImGui.TreePop();
                            }
                            if (ignoredFileCount > 0 && ImGui.BeginPopupContextItem("IgnoreFilesClear", ImGuiPopupFlags.MouseButtonRight))
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                                if (ImGui.Selectable("Clear all ignored files"))
                                {
                                    activeTarget.TraceChoices.ClearIgnoredFiles();
                                }

                                ImGui.PopStyleColor();
                                ImGui.EndPopup();
                            }

                            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(136, 35));
                            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(5, 9));
                            if (ImGui.Button($"{ImGuiController.FA_ICON_ADDFILE} Add Files/Directories"))
                            {
                                ToggleTraceListSelectionWindow();
                            }
                            ImGui.PopStyleVar();
                            SmallWidgets.MouseoverText("Add files/directories to this filter");
                        }
                        else if (activeTarget.TraceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
                        {
                            ImGui.SetNextItemOpen(true, ImGuiCond.Once);
                            if (ImGui.TreeNode($"Traced Directories ({activeTarget.TraceChoices.TraceDirCount})"))
                            {
                                DrawClickablePaths(activeTarget.TraceChoices.GetTracedDirs(), (x) => { activeTarget.TraceChoices.RemoveTracedDirectory(x); });
                                ImGui.TreePop();
                            }
                            if (ImGui.BeginPopupContextItem("TraceDirsClear", ImGuiPopupFlags.MouseButtonRight))
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                                if (ImGui.Selectable("Clear all traced directories"))
                                {
                                    activeTarget.TraceChoices.ClearTracedDirs();
                                }

                                ImGui.PopStyleColor();
                                ImGui.EndPopup();
                            }

                            ImGui.SetNextItemOpen(true, ImGuiCond.Once);
                            if (ImGui.TreeNode($"Traced Files ({activeTarget.TraceChoices.TraceFilesCount})"))
                            {
                                DrawClickablePaths(activeTarget.TraceChoices.GetTracedFiles(), (x) => { activeTarget.TraceChoices.RemoveTracedFile(x); });
                                ImGui.TreePop();
                            }
                            if (ImGui.BeginPopupContextItem("TraceDirsClear", ImGuiPopupFlags.MouseButtonRight))
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                                if (ImGui.Selectable("Clear all traced files"))
                                {
                                    activeTarget.TraceChoices.ClearTracedFiles();
                                }

                                ImGui.PopStyleColor();
                                ImGui.EndPopup();
                            }

                            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(136, 35));
                            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(5, 9));
                            if (ImGui.Button($"{ImGuiController.FA_ICON_ADDFILE} Add Files/Directories"))
                            {
                                ToggleTraceListSelectionWindow();
                            }
                            ImGui.PopStyleVar();
                            SmallWidgets.MouseoverText("Add files/directories to this filter");
                        }
                        ImGui.PopStyleColor();
                        ImGui.EndChildFrame();
                    }
                    ImGui.PopStyleColor();

                    ImGui.EndChild();
                }


                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();

            ImGui.Indent(-8);
        }

        private bool _checkStartPausedState;
        private bool _recordVideoOnStart;
        private bool _diagnosticMode;
        private bool _activeTargetRunnable;
        private void DrawTraceTab_ExecutionSettings(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBg));
                ImGui.BeginChildFrame(10, new Vector2(width, ImGui.GetContentRegionAvail().Y - 20));
                ImGui.Text("Execution Settings");

                ImGui.BeginChildFrame(18, new Vector2(500, 80));
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

                ImGui.AlignTextToFramePadding();
                ImGui.Text("Instrumentation Level: ");
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBgHovered));
                ImGui.RadioButton("Single Shot", ref _selectedInstrumentationLevel, 0);
                ImGui.SameLine();
                ImGui.RadioButton("Continuous", ref _selectedInstrumentationLevel, 1);
                ImGui.SameLine();
                ImGui.RadioButton("Data", ref _selectedInstrumentationLevel, 2);
                ImGui.PopStyleColor(1);



                ImGui.EndChildFrame();

                ImGui.AlignTextToFramePadding();

                ImGui.Text("Command Line");
                ImGui.SameLine();
                ImguiUtils.HelpMarker("Command line arguments passed to the program being executed");
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBgHovered));
                byte[] _dataInput = new byte[1024];
                ImGui.InputText("##cmdline", _dataInput, 1024);

                ImGui.PopStyleColor(2);


                ImGui.SameLine();

                if (ImGui.Checkbox("Start Paused", ref _checkStartPausedState) && _rgatState.ActiveTarget is not null)
                {
                    _rgatState.ActiveTarget.SetTraceConfig("PAUSE_ON_START", _checkStartPausedState ? "TRUE" : "FALSE");
                }
                if (rgatState.VideoRecorder.Loaded)
                {
                    ImGui.SameLine();
                    if (rgatState.VideoRecorder.Loaded)
                    {
                        ImGui.Checkbox("Capture Video", ref _recordVideoOnStart);
                    }
                    else
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, 0xFF858585);
                        ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF454545);
                        ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, 0xFF454545);
                        _recordVideoOnStart = false;
                        if (ImGui.Checkbox("Capture Video", ref _recordVideoOnStart))
                        {
                            rgatState.RecordVideoOnNextTrace = _recordVideoOnStart;
                        }

                        ImGui.PopStyleColor(3);
                        SmallWidgets.MouseoverText("Requires FFmpeg - configure in settings");
                    }
                }



                string pintoolpath = activeTarget.BitWidth == 32 ? GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath32) :
                    GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath64);

                if (GlobalConfig.BadSigners(out List<Tuple<string, string>>? issues))
                {
                    string pinpath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinPath);
                    issues = issues!.Where(i => (i.Item1 == pintoolpath || i.Item1 == pinpath)).ToList();
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

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + width - 140);
                StartButton(activeTarget, pintoolpath);

                ImGui.EndChildFrame();

                ImGui.EndGroup();
            }
        }

        private void StartButton(BinaryTarget activeTarget, string pintoolpath)
        {

            bool runnable = _activeTargetRunnable;
            ImGui.PushStyleColor(ImGuiCol.Button, runnable ? Themes.GetThemeColourImGui(ImGuiCol.Button) : Themes.GetThemeColourUINT(Themes.eThemeColour.eTextDull1));
            ImGui.AlignTextToFramePadding();

            ImGui.PushStyleVar(ImGuiStyleVar.FrameBorderSize, 1f);
            if (
                (activeTarget.RemoteBinary || activeTarget.PEFileObj != null)
                && ImGui.Button("Start Trace " + ImGuiController.FA_PLAY_CIRCLE, new Vector2(100, 40)) && runnable)
            {
                _OldTraceCount = rgatState.TotalTraceCount;
                int ordinal = (activeTarget.IsLibrary && activeTarget.SelectedExportIndex > -1) ? activeTarget.Exports[activeTarget.SelectedExportIndex].Item2 : 0;
                if (activeTarget.RemoteBinary)
                {
                    ProcessLaunching.StartRemoteTrace(activeTarget, ordinal: ordinal);
                }
                else
                {
                    if (_selectedInstrumentationLevel == 0)
                    {
                        _rgatState.ActiveTarget!.SetTraceConfig("SINGLE_SHOT_INSTRUMENTATION", "TRUE");
                    }

                    //todo loadername, ordinal
                    System.Diagnostics.Stopwatch watch = new System.Diagnostics.Stopwatch();
                    System.Diagnostics.Process? p = ProcessLaunching.StartLocalTrace(pintoolpath, activeTarget.FilePath,
                        loaderName: activeTarget.LoaderName, ordinal: ordinal, targetPE: activeTarget.PEFileObj);
                    if (p != null)
                    {
                        watch.Start();
                        if (p.WaitForExit(80)) //in testing it takes under 30ms to fail if pin can't load it
                        {
                            if (p.ExitCode != 0)
                            {
                                Logging.RecordError($"Trace error after {watch.ElapsedMilliseconds} ms: Exit code {p.ExitCode}. Target binary may be invalid or incompatible");
                            }
                        }
                    }

                }
            }
            ImGui.PopStyleVar();
            ImGui.PopStyleColor();
            if (!runnable)
            {
                SmallWidgets.MouseoverText("File not available");
            }
        }


        private static void DrawDetectItEasyProgress(BinaryTarget activeTarget, Vector2 barSize)
        {
            if (rgatState.DIELib == null)
            {
                ImGui.Text("DiE Not Loaded");
                SmallWidgets.MouseoverText("See error in logs");
                return;
            }
            DiELibDotNet.DieScript.SCANPROGRESS? DEProgress = rgatState.DIELib.GetDIEScanProgress(activeTarget);
            ImGui.BeginGroup();
            {
                uint textColour = Themes.GetThemeColourImGui(ImGuiCol.Text);
                if (DEProgress is null)
                {
                    ImGui.Text("Not Inited");
                }
                else if (DEProgress.errored)
                {
                    float dieProgress = DEProgress.scriptCount == 0 ? 0f : DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"Failed ({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    uint errorColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, errorColour, 0xff111111, textColour);
                }
                else if (DEProgress.loading)
                {
                    SmallWidgets.ProgressBar("DieProgBar", $"Loading Scripts", 0, barSize, 0xff117711, 0xff111111);
                }
                else if (DEProgress.running)
                {
                    float dieProgress = DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"DiE:{DEProgress.scriptsFinished}/{DEProgress.scriptCount}";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111);
                }
                else if (DEProgress.StopRequestFlag)
                {
                    float dieProgress = DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"Cancelled ({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    uint cancelColor = Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour);
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, cancelColor, 0xff111111, 0xff000000);
                }
                else
                {
                    float dieProgress = DEProgress.scriptsFinished / (float)DEProgress.scriptCount;
                    string caption = $"DIE:({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
                    SmallWidgets.ProgressBar("DieProgBar", caption, dieProgress, barSize, 0xff117711, 0xff111111, textColour);
                }

                if (DEProgress is not null)
                {
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
                            rgatState.DIELib.CancelDIEScan(activeTarget);
                        }
                    }
                    else if (!DEProgress.running && !DEProgress.loading)
                    {
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.BeginTooltip();
                            ImGui.Text($"{DEProgress.scriptsFinished} Detect-It-Easy scripts were executed out of {DEProgress.scriptCount} loaded for this file format");
                            ImGui.Text($"Note that rgat does not use the original DIE codebase - the original may provide better results.");
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
                        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
                        {
                            rgatState.DIELib.StartDetectItEasyScan(activeTarget);
                        }
                        if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                        {
                            rgatState.DIELib.StartDetectItEasyScan(activeTarget, reload: true);
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
            }
            ImGui.EndGroup();
        }



        //YARA
        private static void DrawYARAProgress(BinaryTarget activeTarget, Vector2 barSize)
        {
            if (rgatState.YARALib == null)
            {
                ImGui.Text("YARA Not Loaded");
                SmallWidgets.MouseoverText("See error in logs");
                return;
            }
            YARAScanner.eYaraScanProgress progress = rgatState.YARALib.Progress(activeTarget);
            string caption;
            float progressAmount = 0;
            uint barColour = 0;
            switch (progress)
            {
                case YARAScanner.eYaraScanProgress.eNotStarted:
                    caption = "YARA: No Scan";
                    break;
                case YARAScanner.eYaraScanProgress.eComplete:
                    {
                        uint rulecount = rgatState.YARALib.LoadedRuleCount();
                        caption = $"YARA:{rulecount}/{rulecount}"; //wrong if reloaded?
                        barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eGoodStateColour);
                        progressAmount = 1;
                        break;
                    }
                case YARAScanner.eYaraScanProgress.eFailed:
                    caption = "YARA: Error";
                    barColour = Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour);
                    progressAmount = 0;
                    break;
                case YARAScanner.eYaraScanProgress.eRunning:
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
                ImGui.Text($"{caption} with {rgatState.YARALib.LoadedRuleCount()} loaded rules");
                ImGui.Separator();
                ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                ImGui.Text("Left Click  - Rescan");
                ImGui.Text("Right Click - Reload & Rescan");
                ImGui.PopStyleColor();
                ImGui.EndTooltip();
            }
            if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            {
                rgatState.YARALib.StartYARATargetScan(activeTarget, reload: false);
            }
            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
            {
                rgatState.YARALib.StartYARATargetScan(activeTarget, reload: true);
            }

        }


        private void DrawSignaturesBox(BinaryTarget activeTarget, float width)
        {
            if (ImGui.BeginTable("#SigHitsTable", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.SizingStretchProp |
                ImGuiTableFlags.ScrollX | ImGuiTableFlags.Resizable, new Vector2(width, ImGui.GetContentRegionAvail().Y - 6)))
            {
                
                ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Rule");
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableHeadersRow();

                if (activeTarget.GetDieHits(out string[] diehits))
                {
                    foreach (string hit in diehits)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("DIE");
                        ImGui.TableNextColumn();
                        Controller.PushOriginalFont();
                        ImGui.AlignTextToFramePadding();
                        ImGui.Text(hit);
                        ImGui.PopFont();
                    }
                }

                if (activeTarget.GetYaraHits(out YARAScanner.YARAHit[] yarahits))
                {
                    foreach (YARAScanner.YARAHit hit in yarahits)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("YARA");
                        ImGui.TableNextColumn();
                        Controller.PushOriginalFont();
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
                            if (_yaraPopupHit == null)
                            {
                                _hitHoverOnly = true;
                                _yaraPopupHit = hit;
                            }
                            if (ImGui.IsItemClicked())
                            {
                                _hitHoverOnly = false;
                                _hitClickTime = DateTime.Now;
                            }
                            if (_hitHoverOnly)
                            {
                                DrawYaraPopup(true);
                            }
                        }
                        else
                        {
                            if (_hitHoverOnly == true)
                            {
                                _yaraPopupHit = null;
                            }
                        }

                    }
                }

                ImGui.EndTable();
            }
        }

        private YARAScanner.YARAHit? _yaraPopupHit = null;
        private DateTime _hitClickTime;
        private bool _hitHoverOnly;
        private void DrawYaraPopup(bool tooltip)
        {
            if (tooltip)
            {
                ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(3, 4));
                ImGui.BeginTooltip();
                YaraTooltipContents(true);
                ImGui.EndTooltip();
                ImGui.PopStyleVar();
            }
            else
            {
                ImGui.OpenPopup("#YaraHitPopup");
                if (ImGui.BeginPopup("#YaraHitPopup"))
                {
                    if (ImGui.BeginChild("#YaraHitPopupWind", new Vector2(650, 300), true, ImGuiWindowFlags.NoScrollbar))
                    {
                        YaraTooltipContents(false);
                        ImGui.EndChild();
                    }
                    ImGui.EndPopup();
                }
            }
        }

        private void YaraTooltipContents(bool tooltip)
        {
            if (_yaraPopupHit is null)
            {
                return;
            }

            Vector2 start = ImGui.GetCursorScreenPos();
            if (ImGui.BeginTable("#YaraHitTableMetaToolTip", 2, ImGuiTableFlags.Borders))
            {
                ImGui.TableSetupColumn("Meta");
                ImGui.TableSetupColumn("Value");
                ImGui.TableHeadersRow();

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Rule Name");
                ImGui.TableNextColumn();
                ImGui.Text(_yaraPopupHit.MatchingRule.Identifier);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Tags");
                ImGui.TableNextColumn();
                string tags = "";
                foreach (string tag in _yaraPopupHit.MatchingRule.Tags)
                {
                    tags += $" [{tag}]";
                }

                ImGui.Text(tags);

                foreach (var kvp in _yaraPopupHit.MatchingRule.Metas)
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text(kvp.Key);
                    ImGui.TableNextColumn();
                    ImGui.Text(kvp.Value.ToString());
                }
                ImGui.EndTable();
            }


            int displayCount = 0;
            int allMatchCount = _yaraPopupHit.Matches.Sum(x => x.Value.Count);

            if (allMatchCount > 0 && ImGui.BeginTable("#YaraHitTablToolTip", 4, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.ScrollX))
            {
                ImGui.TableSetupColumn("Match Name");
                ImGui.TableSetupColumn("Offset", ImGuiTableColumnFlags.WidthFixed, 65);
                ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 45);
                ImGui.TableSetupColumn("Match Data", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableHeadersRow();

                foreach (var matchList in _yaraPopupHit.Matches)
                {
                    for (var matchi = 0; matchi < matchList.Value.Count; matchi++)
                    {
                        YARAScanner.YARAHit.YaraHitMatch match = matchList.Value[matchi];
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
                        {
                            strillus += "...";
                        }

                        strillus += "  {";
                        strillus += BitConverter.ToString(match.Data, 0, previewLen).Replace("-", " ");
                        strillus += "}";

                        ImGui.Text($"{strillus}");
                        displayCount += 1;
                        if (tooltip && displayCount > 15)
                        {
                            break;
                        }

                        if (tooltip && matchi > 3 && matchList.Value.Count > 4)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            ImGui.Text($"And {(matchList.Value.Count - matchi)} more hits of {matchList.Key} (click to display)");
                            break;
                        }

                    }
                    if (tooltip && displayCount > 15)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text($"And {(allMatchCount - displayCount)} more hits (click to display)");
                        break;
                    }

                }
                ImGui.EndTable();
            }

            if (ImGui.IsMouseClicked(ImGuiMouseButton.Left) && !ImGui.IsMouseHoveringRect(start, start + ImGui.GetContentRegionMax()))
            {
                if (DateTime.Now > _hitClickTime.AddMilliseconds(600))
                {
                    _yaraPopupHit = null;
                }
            }

        }



    }
}
