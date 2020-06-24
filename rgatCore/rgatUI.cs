using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Xml.Linq;

namespace rgatCore
{
    class rgatUI
    {
        //rgat ui state
        private bool _settings_window_shown = false;
        private bool _show_select_exe_window = false;

        //rgat program state
        private rgatState _rgatstate = null;

        public rgatUI()
        {
            _rgatstate = new rgatState();
        }

        private bool finit = false;
        public void DrawUI()
        {
            /*
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff0ff000);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0fff00);
            ImGui.PushStyleColor(ImGuiCol.WindowBg, 0xff0ffff0);
            ImGui.PushStyleColor(ImGuiCol.Border, 0xfffffff0);
            ImGui.PushStyleColor(ImGuiCol.Tab, 0xff0f0f00);
            */

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

            /*
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            */

            ImGui.End();
        }
        
        private void DrawTraceTab()
        {

            BinaryTarget activeTarget = _rgatstate.ActiveTarget;
            if (activeTarget == null)
            {
                String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁킶ф";
                ImguiUtils.DrawCenteredText(msg);
                return;
            }

            ImGui.BeginGroup();
            {

                ImGui.Columns(2);
                ImGui.SetColumnWidth(0, 120);
                ImGui.SetColumnWidth(1, 800);
                ImGui.Separator();

                byte[] _dataInput = null;

                ImGui.AlignTextToFramePadding();
                ImGui.Text("File");  ImGui.NextColumn();
                string fileStr = String.Format("{0} ({1})", activeTarget.FileName, activeTarget.GetFileSizeString());
                _dataInput = Encoding.UTF8.GetBytes(fileStr);
                ImGui.InputText("##filenameinp", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);  ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA1 Hash"); ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA1Hash());
                ImGui.InputText("##s1hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);  ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("SHA256 Hash");  ImGui.NextColumn();
                _dataInput = Encoding.UTF8.GetBytes(activeTarget.GetSHA256Hash());
                ImGui.InputText("##s256hash", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);  ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("Hex Preview");  ImGui.NextColumn();

                _dataInput = Encoding.UTF8.GetBytes(activeTarget.HexPreview);
                ImGui.InputText("##hexprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);  ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                ImGui.Text("ASCII Preview");  ImGui.NextColumn();
                _dataInput = Encoding.ASCII.GetBytes(activeTarget.ASCIIPreview);
                ImGui.InputText("##ascprev", _dataInput, 400, ImGuiInputTextFlags.ReadOnly);  ImGui.NextColumn(); 
            }

            ImGui.Columns(1);
            ImGui.EndGroup();
            return;
        }
        private void DrawVisTab()
        {
            ImGui.InputText("f", Encoding.ASCII.GetBytes("CHUNK THE FUNK"), 120);
            ImGui.Text("Trace start stuff here");
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
                    DrawTraceTab(); ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Visualiser"))
                {
                    DrawVisTab(); ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Trace Analysis"))
                {
                    DrawAnalysisTab(); ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Graph Comparison"))
                {
                    DrawCompareTab(); ImGui.EndTabItem();
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
