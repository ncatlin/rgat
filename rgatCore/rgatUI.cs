﻿using ImGuiNET;
using SharpDX.DXGI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;

namespace rgatCore
{
    class rgatUI
    {
        //rgat ui state
        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;
        private ImGuiController _ImGuiController = null;

        //rgat program state
        private rgatState _rgatstate = null;
        private int _selectedInstrumentationEngine = 0;

        public rgatUI(ImGuiController imguicontroller)
        {
            _rgatstate = new rgatState();
            _ImGuiController = imguicontroller;
        }

        private bool finit = false;
        public void DrawUI()
        {

            if (!finit)
            {


                finit = true;
            }

            ImGui.SetNextWindowPos(new Vector2(0, 0), ImGuiCond.Always);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;
            window_flags |= ImGuiWindowFlags.NoTitleBar;
            window_flags |= ImGuiWindowFlags.MenuBar;


            ImGui.Begin("rgat Primary Window", window_flags);
            DrawMainMenu();


            DrawTargetBar();
            DrawTabs();

            if (_settings_window_shown)   DrawSettingsWindow();
           
            if (_show_select_exe_window)  DrawFileSelectBox();


            ImGui.End();
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
                _ImGuiController.PushOriginalFont(); //it's monospace and UTF8
                {
                    _dataInput = Encoding.UTF8.GetBytes(activeTarget.HexPreview);
                    ImGui.InputText("##hexprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    ImGui.PopFont();
                }

                ImGui.Text("ASCII Preview"); ImGui.NextColumn();
                _ImGuiController.PushOriginalFont();
                {
                    _dataInput = Encoding.ASCII.GetBytes(activeTarget.ASCIIPreview);
                    ImGui.InputText("##ascprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
                    ImGui.PopFont();
                }

                ImGui.Text("Format"); ImGui.NextColumn();
                string formatNotes = activeTarget.FormatNotes;
                ImGui.InputTextMultiline("##fmtnote", ref formatNotes, 400, new Vector2(0, 80), ImGuiInputTextFlags.ReadOnly); ImGui.NextColumn();
            }

            ImGui.Columns(1);
            ImGui.EndGroup();
            ImGui.EndChildFrame();
        }

        private void DrawTraceTab_DiagnosticSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998800);
                ImGui.BeginChildFrame(9, new Vector2(width, 300));
                {
                    ImGui.Button("DynamoRIO Test");
                    ImGui.Button("PIN Test");
                    
                    if(ImGui.BeginCombo("##loglevel", "Essential"))
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
            ImGui.Text("Instrumentation Settings");

            
            ImGui.AlignTextToFramePadding();
            ImGui.Text("Instrumentation Engine");
            ImGui.SameLine();
            ImGui.RadioButton("Intel Pin", ref _selectedInstrumentationEngine, 0);
            ImGui.SameLine();
            ImGui.RadioButton("DynamoRIO", ref _selectedInstrumentationEngine, 1);
            ImGui.EndChildFrame();

            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.AlignTextToFramePadding();
            ImGui.Text("Module Tracing");
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Customise which libraries rgat will instrument. Tracing more code affects performance and makes resulting graphs more complex.");
            ImGui.SameLine();
            string WLLabel = String.Format("Whitelist [{0}]", activeTarget.excludedLibs.whitelistedDirs.Count + activeTarget.excludedLibs.whitelistedFiles.Count);
            ImGui.RadioButton(WLLabel, ref activeTarget.excludedLibs.tracingMode, 0);
            ImGui.SameLine();
            ImguiUtils.HelpMarker("Only whitelisted libraries will be traced");
            ImGui.SameLine();
            string BLLabel = String.Format("Blacklist [{0}]", activeTarget.excludedLibs.blacklistedDirs.Count + activeTarget.excludedLibs.blacklistedFiles.Count);
            ImGui.RadioButton(BLLabel, ref activeTarget.excludedLibs.tracingMode, 1);
            ImGui.SameLine();
            ImguiUtils.HelpMarker("All libraries will be traced except for those on the blacklist");
            ImGui.EndChildFrame();


            ImGui.BeginChildFrame(18, new Vector2(width, 200));
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFFdddddd);
                
            if (ImGui.BeginChildFrame(ImGui.GetID("exclusionlist_contents"), ImGui.GetContentRegionAvail()))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);
                if ((eModuleTracingMode)activeTarget.excludedLibs.tracingMode == eModuleTracingMode.eBlackList)
                {
                    if (ImGui.TreeNode("Blacklisted Directories ("+ activeTarget.excludedLibs.blacklistedDirs.Count+")"))
                    {
                        foreach (string dirstr in activeTarget.excludedLibs.blacklistedDirs)
                            ImGui.Text(dirstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode("Blacklisted Files (" + activeTarget.excludedLibs.blacklistedFiles.Count + ")"))
                    {
                        foreach (string fstr in activeTarget.excludedLibs.blacklistedFiles)
                            ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }

                else if ((eModuleTracingMode)activeTarget.excludedLibs.tracingMode == eModuleTracingMode.eWhiteList)
                {
                    if (ImGui.TreeNode("Whitelisted Directories (" + activeTarget.excludedLibs.whitelistedDirs.Count + ")"))
                    {
                        foreach (string dirstr in activeTarget.excludedLibs.whitelistedDirs)
                            ImGui.Text(dirstr);
                        ImGui.TreePop();
                    }
                    if (ImGui.TreeNode("Whitelisted Files (" + activeTarget.excludedLibs.whitelistedFiles.Count + ")"))
                    {
                        foreach (string fstr in activeTarget.excludedLibs.whitelistedFiles)
                            ImGui.Text(fstr);
                        ImGui.TreePop();
                    }
                }
                ImGui.PopStyleColor();
                ImGui.EndChildFrame();
                ImGui.PopStyleColor();
            }
            if (ImGui.BeginPopupContextItem("exclusionlist_contents", ImGuiMouseButton.Right))
            {
                ImGui.Selectable("Add files/directories");
                ImGui.EndPopup();
            }

            ImGui.EndChildFrame();

            ImGui.PopStyleColor();
            ImGui.EndGroup();

        }

        private void DrawTraceTab_ExecutionSettings(float width)
        {
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF222200);
                ImGui.BeginChildFrame(10, new Vector2(width, 200));
                ImGui.Text("Execution Settings");


                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFF998880);
                ImGui.AlignTextToFramePadding();

                ImGui.Text("Command Line");
                ImGui.SameLine();
                ImguiUtils.HelpMarker("Command line arguments passed to the program being executed");
                ImGui.SameLine();

                byte[] _dataInput = new byte[1024];
                ImGui.InputText("##cmdline", _dataInput, 1024);
                ImGui.PopStyleColor();
                ImGui.Button("Start Trace");
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
            DrawTraceTab_FileInfo(activeTarget, ImGui.GetContentRegionAvail().X - 200);
            ImGui.SameLine();
            DrawTraceTab_DiagnosticSettings(200);
            ImGui.EndGroup();

            ImGui.BeginGroup();
            DrawTraceTab_InstrumentationSettings(activeTarget, 400);
            ImGui.SameLine();
            DrawTraceTab_ExecutionSettings(ImGui.GetContentRegionAvail().X - 400);
            ImGui.EndGroup();

            return;
        }

        private void DrawVisualiserGraphs(float height)
        {
            float tracesGLFrameWidth = 200;
            ImGui.BeginGroup();
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF258880);
                if (ImGui.BeginChild(ImGui.GetID("GLVisMain"), new Vector2(ImGui.GetContentRegionAvail().X - tracesGLFrameWidth, height)))
                {
                    ImGui.Text("GLVisMain");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF253880);
                if (ImGui.BeginChild(ImGui.GetID("GLVisThreads"), new Vector2(tracesGLFrameWidth, height)))
                {

                    ImGui.Text("GLVisThreads");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
            }
            ImGui.EndGroup();
        }

        float sliderPosX = -1;
        float hstretch = 1;

        private unsafe void DrawReplaySlider(float replayControlsSize)
        {
            int progressBarPadding = 6;
            Vector2 progressBarSize = new Vector2(replayControlsSize - (progressBarPadding * 2), 30);

            //ImGui.SetCursorScreenPos(new Vector2(bar1_pos_x, picker_pos.Y));
            ImGui.InvisibleButton("Replay Progress", progressBarSize);
            Vector2 progressSliderPos = ImGui.GetItemRectMin();
            progressSliderPos.X += progressBarPadding;
            if (sliderPosX < progressSliderPos.X) sliderPosX = progressSliderPos.X;


            if (ImGui.IsItemActive())
            {
                //col[3] = 1.0f - ImguiUtils.ImSaturate((- picker_pos.Y) / (sv_picker_size - 1));
                sliderPosX = ImGui.GetIO().MousePos.X;
                if (sliderPosX < progressSliderPos.X) sliderPosX = progressSliderPos.X;
                if (sliderPosX > progressSliderPos.X + progressBarSize.X) sliderPosX = progressSliderPos.X + progressBarSize.X;
                //value_changed = true;
            }
            ImGui.GetForegroundDrawList().AddRectFilledMultiColor(new Vector2(progressSliderPos.X, progressSliderPos.Y), new Vector2(progressSliderPos.X + progressBarSize.X, progressSliderPos.Y + progressBarSize.Y), 0xff004400, 0xfff04420, 0xff994400, 0xff004477);

            ImguiUtils.RenderArrowsForHorizontalBar(ImGui.GetForegroundDrawList(), new Vector2(sliderPosX, progressSliderPos.Y), new Vector2(4, 7), progressBarSize.Y, 255f);

        }

        private unsafe void DrawPlaybackControls(float otherControlsHeight)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF555555);
            float replayControlsSize = ImGui.GetContentRegionAvail().X - 300f;
            if (ImGui.BeginChild(ImGui.GetID("ReplayControls"), new Vector2(replayControlsSize, otherControlsHeight)))
            {
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
                ImGui.Text("Trace Replay: Paused");
                DrawReplaySlider(replayControlsSize);

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 6);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 6);
                if (ImGui.BeginChild("ctrls2354"))
                {
                    ImGui.BeginGroup();
                    if (ImGui.Button("Play", new Vector2(36, 36))) Console.WriteLine("Play clicked");
                    if (ImGui.Button("Reset", new Vector2(36, 36))) Console.WriteLine("Reset clicked");
                    ImGui.EndGroup();
                    ImGui.SameLine();
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
        }

        private unsafe void DrawVisualiserControls()
        {
            float topControlsBarHeight = 40;
            float otherControlsHeight = 150;



            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF257810);
                {
                    if (ImGui.BeginChild(ImGui.GetID("ControlTopBar"), new Vector2(ImGui.GetContentRegionAvail().X, topControlsBarHeight)))
                    {
                        ImGui.PushItemWidth(100);
                        if (ImGui.BeginCombo("##GraphTypeSelectCombo", "Cylinder"))
                        {
                            if (ImGui.Selectable("Cylinder", true))
                            {
                                Console.WriteLine("Cylinder selected");
                            }
                            if (ImGui.Selectable("Tree", false))
                            {
                                Console.WriteLine("Tree selected");
                            }
                            ImGui.EndCombo();
                        }
                        ImGui.PopItemWidth();
                        ImGui.SameLine();
                        ImGui.Button("Lines");
                        ImGui.SameLine();
                        ImGui.Button("Nodes");
                        ImGui.SameLine();
                        ImGui.Button("Wireframe");
                        ImGui.SameLine();
                        ImGui.Button("Symbols");
                        ImGui.SameLine();
                        ImGui.Button("Instructions");
                        ImGui.SameLine();
                        ImGui.PushItemWidth(100);
                        if (ImGui.BeginCombo("##TraceTypeSelectCombo", "Trace"))
                        {
                            if (ImGui.Selectable("Trace", true))
                            {
                                Console.WriteLine("Trace selected");
                            }
                            if (ImGui.Selectable("Heatmap", false))
                            {
                                Console.WriteLine("Heatmap selected");
                            }
                            if (ImGui.Selectable("Conditionals", false))
                            {
                                Console.WriteLine("Conditionals selected");
                            }
                            ImGui.EndCombo();
                        }
                        ImGui.PopItemWidth();
                        ImGui.SameLine();
                        ImGui.Button("Highlight");
                        ImGui.SameLine();
                        ImGui.Button("Rerender");

                        ImGui.EndChild();
                    }
                }

                ImGui.PopStyleColor();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF553180);
                {

                    bool value_changed = false;
                    if (ImGui.BeginChild(ImGui.GetID("ControlsOhter"), new Vector2(ImGui.GetContentRegionAvail().X, otherControlsHeight + 15)))
                    {
                        ImGui.BeginGroup();
                        {


                            DrawPlaybackControls(otherControlsHeight);
                            ImGui.SameLine();

                            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF259183);
                            float sizeControlsFrameWidth = 150f;
                            if (ImGui.BeginChild(ImGui.GetID("SizeControls"), new Vector2(sizeControlsFrameWidth, otherControlsHeight)))
                            {
                                ImGui.Text("SizeControls");

                            ImGui.Text("Zoom: 38.5");

                            ImGui.Text("Horizontal Stretch");
                            ImGui.BeginGroup();
                            ImGui.Button("-", new Vector2(20, 24));
                            ImGui.SameLine();
                            ImGui.SetNextItemWidth(32.0f);
                            ImGui.InputFloat("##inphstr", ref hstretch);
                            ImGui.SameLine();
                            ImGui.Button("+", new Vector2(20, 24));
                            ImGui.EndGroup();

                            ImGui.Text("Vertical Stretch");
                            ImGui.Text("Plot Size");
                            ImGui.EndChild();
                            }

                            ImGui.SameLine();

                            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);
                            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(150, otherControlsHeight)))
                            {
                                ImGui.Text("TraceSelect");
                                ImGui.EndChild();
                            }
                        }
                        ImGui.EndGroup();

                    ImGui.EndChild();
                    }
                }

                ImGui.PopStyleColor();

        }






        private void DrawVisTab()
        {
            float controlsHeight = 200;

            DrawVisualiserGraphs(ImGui.GetContentRegionAvail().Y - controlsHeight);

            DrawVisualiserControls();

        }
        private void DrawAnalysisTab()
        {
            ImGui.Text("Trace start stuff here");
        }
        private void DrawCompareTab()
        {
            ImGui.Text("Trace start stuff here");
        }
        private unsafe void DrawSettingsTab()
        {
            ImGui.Text("Trace start stuff here");
        }

        private unsafe void DrawMainMenu()
        {
            if (ImGui.BeginMenuBar())
            {
                if (ImGui.BeginMenu("Target"))
                {
                    if (ImGui.MenuItem("Select Target Executable")) { _show_select_exe_window = !_show_select_exe_window; }
                    if (ImGui.MenuItem("Recent Targets")) { }
                    if (ImGui.MenuItem("Open Saved Trace")) { }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Save Thread Trace")) { }
                    if (ImGui.MenuItem("Save Process Traces")) { }
                    if (ImGui.MenuItem("Save All Traces")) { }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Exit")) { }
                    ImGui.EndMenu();
                }


                if (ImGui.MenuItem("Settings", null, ref _settings_window_shown)) { }

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
            if (ImGui.BeginCombo("Active Target", activeString, flags))
            {
                foreach (string path in paths)
                {
                    bool is_selected = activeTarget.FilePath == path;
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
                
                ImGui.EndTabBar();
            }


        }

        private unsafe void DrawSettingsWindow()
        {
            ImGui.SetNextWindowPos(new Vector2(200, 200), ImGuiCond.Appearing);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;

            ImGui.Begin("Settings", ref _settings_window_shown, window_flags);
            ImGui.InputText("f", Encoding.ASCII.GetBytes("CHUNK THE FUNK"), 120);
            ImGui.Text("Here be settings");
            ImGui.End();
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
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                       _rgatstate.AddTargetByPath(picker.SelectedFile);
                    }
                    rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    _show_select_exe_window = false;
                }
                ImGui.EndPopup();
            }
        }
    }
}