﻿using ImGuiNET;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgat
{
    partial class rgatUI
    {
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
                _tooltipScrollingActive = false;
            }
        }

        private void DrawTraceTab_FileInfo(BinaryTarget activeTarget, float width)
        {
            ImGui.BeginChildFrame(22, new Vector2(width, 300), ImGuiWindowFlags.AlwaysAutoResize);

            if (activeTarget.RemoteHost != null && !activeTarget.RemoteInitialised)
            {
                if (rgatState.ConnectedToRemote)
                    ImguiUtils.DrawRegionCenteredText("Initialising from remote host");
                else
                    ImguiUtils.DrawRegionCenteredText("Disconnected from remote host before metadata could be retrieved");

                ImGui.EndChildFrame();
                return;
            }

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
                    _controller.PushOriginalFont(); //original imgui font is monospace and UTF8, good for this
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
                    _controller.PushOriginalFont();
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

                    DrawSignaturesBox(activeTarget, 530);

                    ImGui.EndTable();
                }
            }

            // ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();

            if (_yaraPopupHit != null && !_hitHoverOnly) DrawYaraPopup(false);
        }

        float _tooltipScroll = 0;
        bool _tooltipScrollingActive;
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
                    _tooltipScroll = ImGui.GetScrollMaxY();

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
            {
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
            }
            ImGui.EndGroup();

        }

        bool _checkStartPausedState;
        bool _recordVideoOnStart;
        bool _diagnosticMode;
        bool _activeTargetRunnable;
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

                ImGui.AlignTextToFramePadding();

                ImGui.Text("Command Line");
                ImGui.SameLine();
                ImguiUtils.HelpMarker("Command line arguments passed to the program being executed");
                ImGui.SameLine();

                byte[] _dataInput = new byte[1024];
                ImGui.InputText("##cmdline", _dataInput, 1024);
                ImGui.PopStyleColor();

                string pintoolpath = _rgatState.ActiveTarget.BitWidth == 32 ? GlobalConfig.PinToolPath32 : GlobalConfig.PinToolPath64;


                bool runnable = _activeTargetRunnable;

                ImGui.PushStyleColor(ImGuiCol.Button, runnable ? Themes.GetThemeColourImGui(ImGuiCol.Button) : Themes.GetThemeColourUINT(Themes.eThemeColour.eTextDull1));
                ImGui.AlignTextToFramePadding();
                if (ImGui.Button("Start Trace "+ ImGuiController.FA_PLAY_CIRCLE) && runnable)
                {
                    _OldTraceCount = rgatState.TotalTraceCount;
                    if (_rgatState.ActiveTarget.RemoteBinary)
                    {
                        ProcessLaunching.StartRemoteTrace(_rgatState.ActiveTarget);
                    }
                    else
                    {
                        System.Diagnostics.Process p = ProcessLaunching.StartLocalTrace(pintoolpath, _rgatState.ActiveTarget.FilePath);
                        Console.WriteLine($"Started local process id {p.Id}");
                    }
                }
                if (!runnable)
                {
                    SmallWidgets.MouseoverText("File not available");
                }

                ImGui.PopStyleColor();
                ImGui.SameLine();

                if (ImGui.Checkbox("Start Paused", ref _checkStartPausedState))
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
                        ImGui.Checkbox("Capture Video", ref _recordVideoOnStart);
                        ImGui.PopStyleColor(3);
                        SmallWidgets.MouseoverText("Requires FFmpeg - configure in settings");
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
                ImGui.EndGroup();
            }
        }


        private void DrawDetectItEasyProgress(BinaryTarget activeTarget, Vector2 barSize)
        {
            if (rgatState.DIELib == null)
            {
                ImGui.Text("Not Loaded");
                return;
            }
            DiELibDotNet.DieScript.SCANPROGRESS DEProgress = rgatState.DIELib.GetDIEScanProgress(activeTarget);
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
                    string caption = $"DIE:({DEProgress.scriptsFinished}/{DEProgress.scriptCount})";
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
                    if (rgatState.DIELib.ScriptsLoaded && ImGui.IsItemClicked(ImGuiMouseButton.Left))
                    {
                        rgatState.DIELib.StartDetectItEasyScan(activeTarget);
                    }
                    if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                    {
                        rgatState.DIELib.ReloadDIEScripts(GlobalConfig.DiESigsPath);
                        if (rgatState.DIELib.ScriptsLoaded)
                            rgatState.DIELib.StartDetectItEasyScan(activeTarget);
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
            if (rgatState.YARALib == null)
            {
                ImGui.Text("Not Loaded");
                return;
            }
            YARAScan.eYaraScanProgress progress = rgatState.YARALib.Progress(activeTarget);
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
                        uint rulecount = rgatState.YARALib.LoadedRuleCount();
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
                ImGui.Text($"{caption} with {rgatState.YARALib.LoadedRuleCount()} loaded rules");
                ImGui.Separator();
                ImGui.PushStyleColor(ImGuiCol.Text, 0xffeeeeff);
                ImGui.Text("Left Click  - Rescan");
                ImGui.Text("Right Click - Reload & Rescan");
                ImGui.PopStyleColor();
                ImGui.EndTooltip();
            }
            if (rgatState.YARALib.LoadedRuleCount() > 0 && ImGui.IsItemClicked(ImGuiMouseButton.Left))
            {
                rgatState.YARALib.StartYARATargetScan(activeTarget);
            }
            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
            {
                rgatState.YARALib.RefreshRules(forceRecompile: true);
                if (rgatState.YARALib.LoadedRuleCount() > 0)
                    rgatState.YARALib.StartYARATargetScan(activeTarget);
            }

        }


        private void DrawSignaturesBox(BinaryTarget activeTarget, float width)
        {
            if (ImGui.BeginTable("#SigHitsTable", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY |
                ImGuiTableFlags.NoHostExtendX, new Vector2(width, ImGui.GetContentRegionAvail().Y - 6)))
            {
                ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Rule", ImGuiTableColumnFlags.WidthFixed, width - 92);
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
                        _controller.PushOriginalFont();
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
                        _controller.PushOriginalFont();
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
                                _yaraPopupHit = null;
                        }

                    }
                }

                ImGui.EndTable();
            }
        }

        dnYara.ScanResult _yaraPopupHit = null;
        DateTime _hitClickTime;
        bool _hitHoverOnly;
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


        void YaraTooltipContents(bool tooltip)
        {
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
                    tags += $" [{tag}]";
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
                        dnYara.Match match = matchList.Value[matchi];
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
                        displayCount += 1;
                        if (tooltip && displayCount > 15) break;


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
                    _yaraPopupHit = null;
            }

        }



    }
}