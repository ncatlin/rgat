﻿using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgatCore.Widgets
{
    class SettingsMenu
    {
        static bool[] optionsSelectStates;
        static List<string> settingsNames = new List<string>();
        enum eSettingsCategory { eSetting1, eSetting2, eText, eKeybinds, eSetting5, eSetting6 };

        public SettingsMenu()
        {
            InitSettings();
        }


        PendingKeybind _pendingKeybind = new PendingKeybind();
        public bool HasPendingKeybind
        {
            get => _pendingKeybind.active;
            set => _pendingKeybind.active = value;
        }
        public void AssignPendingKeybind(Tuple<Key, ModifierKeys> keybind)
        {
            GlobalConfig.SetKeybind(_pendingKeybind.action, _pendingKeybind.bindIndex, keybind.Item1, keybind.Item2);
            _pendingKeybind.active = false;
        }

  
        

        void InitSettings()
        {
            settingsNames = new List<string>();
            settingsNames.Add("Setting1");
            settingsNames.Add("Setting2");
            settingsNames.Add("Text");
            settingsNames.Add("Keybinds");
            settingsNames.Add("Setting5");
            settingsNames.Add("Setting6");
            optionsSelectStates = new bool[settingsNames.Count];
            optionsSelectStates[(int)eSettingsCategory.eText] = true;
            optionsSelectStates[(int)eSettingsCategory.eKeybinds] = true;
        }

        public void Draw(ref bool window_shown_flag)
        {
            //ImGui.SetNextWindowPos(new Vector2(700, 500), ImGuiCond.Appearing);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;

            ImGui.Begin("Settings", ref window_shown_flag, window_flags);

            ImGui.BeginGroup();
            if (ImGui.BeginChildFrame(ImGui.GetID("SettingsCategories"), new Vector2(200, ImGui.GetContentRegionAvail().Y - 28)))
            {
                for (int i = 0; i < settingsNames.Count; i++)
                {
                    if (ImGui.Selectable(settingsNames[i], ref optionsSelectStates[i]))
                    {
                        Array.Clear(optionsSelectStates, 0, optionsSelectStates.Length);
                        optionsSelectStates[i] = true;
                    }
                }
                ImGui.EndChildFrame();
            }

            if (ImGui.Button("Close", new Vector2(65, 25)))
            {
                window_shown_flag = false;
            }
            ImGui.EndGroup();
            ImGui.SameLine();
            if (ImGui.BeginChildFrame(ImGui.GetID("SettingContent"), ImGui.GetContentRegionAvail()))
            {
                for (var i = 0; i < optionsSelectStates.Length; i++)
                {
                    if (optionsSelectStates[i])
                    {
                        CreateSettingsContentPane(settingCategoryName: settingsNames[i]);
                        break;
                    }
                }
                ImGui.EndChildFrame();
            }
            ImGui.End();
        }


        void CreateSettingsContentPane(string settingCategoryName)
        {
            switch (settingCategoryName)
            {
                case "Text":
                    CreateOptionsPane_Text();
                    break;
                case "Keybinds":
                    CreateOptionsPane_Keybinds();
                    break;
                default:
                    Console.WriteLine($"Warning: Bad option category '{settingCategoryName}' selected");
                    break;
            }
        }

        void CreateOptionsPane_Text()
        {

            ImGui.Text("todo");
        }

        void CreateOptionsPane_Keybinds()
        {
            if (_pendingKeybind.active)
                ImGui.OpenPopup("Activate New Keybind");

            if (ImGui.BeginPopupModal("Activate New Keybind", ref _pendingKeybind.active, ImGuiWindowFlags.AlwaysAutoResize))
            {
                if (ImGui.BeginChildFrame(ImGui.GetID("KBPopFrame"), new Vector2(280, 110)))
                {
                    ImGui.Text("Binding: " + _pendingKeybind.actionText);

                    ImGui.Text($"Current keybind: [{_pendingKeybind.currentKey}]");

                    string msg = "Press new keybind now";

                    float msgWidth = ImGui.CalcTextSize(msg).X;

                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X / 2) - msgWidth / 2);
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 15);
                    ImGui.Text(msg);
                    ImGui.EndChildFrame();
                }
                ImGui.EndPopup();
            }

            int index = 0;
            ImGui.Columns(3, "kbcols", false);
            ImGui.SetColumnWidth(0, ImGui.GetItemRectSize().X - 300);
            ImGui.SetColumnWidth(1, 150);
            ImGui.SetColumnWidth(2, 150);
            ImGui.Text("Action");
            ImGui.NextColumn();
            ImGui.Text("Keybind");
            ImGui.NextColumn();
            ImGui.Text("Alternate Keybind");
            ImGui.Columns(1);
            CreateKeybindInput("Move Graph Up", eKeybind.eMoveUp, index++);
            CreateKeybindInput("Move Graph Down", eKeybind.eMoveDown, index++);
            CreateKeybindInput("Move Graph Left", eKeybind.eMoveLeft, index++);
            CreateKeybindInput("Move Graph Right", eKeybind.eMoveRight, index++);
            CreateKeybindInput("Graph Pitch + (X axis)", eKeybind.ePitchXFwd, index++);
            CreateKeybindInput("Graph Pitch - (X axis)", eKeybind.ePitchXBack, index++);
            CreateKeybindInput("Graph Roll +  (Y axis)", eKeybind.eRollGraphZClock, index++);
            CreateKeybindInput("Graph Roll -  (Y axis)", eKeybind.eRollGraphZAnti, index++);
            CreateKeybindInput("Graph Yaw +   (Z axis)", eKeybind.eYawYRight, index++);
            CreateKeybindInput("Graph Yaw -   (Z axis)", eKeybind.eYawYLeft, index++);
            CreateKeybindInput("Toggle Heatmap", eKeybind.eToggleHeatmap, index++);
            CreateKeybindInput("Toggle Conditionals", eKeybind.eToggleConditional, index++);
            CreateKeybindInput("Force Direction Temperature +", eKeybind.eRaiseForceTemperature, index++);
            CreateKeybindInput("Center Graph In View", eKeybind.eCenterFrame, index++);
            CreateKeybindInput("Lock Graph Centered", eKeybind.eLockCenterFrame, index++);
            CreateKeybindInput("Toggle All Text", eKeybind.eToggleText, index++);
            CreateKeybindInput("Toggle Instruction Text", eKeybind.eToggleInsText, index++);
            CreateKeybindInput("Toggle Dynamic Text", eKeybind.eToggleLiveText, index++);
            CreateKeybindInput("Graph QuickMenu", eKeybind.eQuickMenu, index++);
        }



        void CreateKeybindInput(string caption, eKeybind keyAction, int rowIndex)
        {

            if ((rowIndex % 2) == 0)
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xafcc3500);
            else
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xafdc4500);

            if (ImGui.BeginChildFrame(ImGui.GetID(caption), new Vector2(ImGui.GetContentRegionAvail().X, 30), ImGuiWindowFlags.NoScrollbar))
            {
                ImGui.Columns(3, "kcols" + caption, false);
                ImGui.SetColumnWidth(0, ImGui.GetItemRectSize().X - 300);
                ImGui.SetColumnWidth(1, 150);
                ImGui.SetColumnWidth(2, 150);
                ImGui.AlignTextToFramePadding();
                ImGui.Text(caption);
                ImGui.NextColumn();
                ImGui.AlignTextToFramePadding();

                string kstring = "";
                if (GlobalConfig.PrimaryKeybinds.TryGetValue(keyAction, out var kmval))
                {
                    if (kmval.Item2 != ModifierKeys.None)
                        kstring += kmval.Item2.ToString() + "+";
                    kstring += kmval.Item1;
                }
                else
                {
                    kstring = "[Click To Set]";
                }
                if (ImGui.Button($"[{kstring}]")) DoClickToSetKeybind(caption, action: keyAction, 1);

                ImGui.NextColumn();

                ImGui.AlignTextToFramePadding();
                kstring = "";
                if (GlobalConfig.AlternateKeybinds.TryGetValue(keyAction, out kmval))
                {
                    if (kmval.Item2 != ModifierKeys.None)
                        kstring += kmval.Item2.ToString() + "+";
                    kstring += kmval.Item1;
                }
                else
                {
                    kstring = "[Click To Set]";
                }
                if (ImGui.Button($"[{kstring}]")) DoClickToSetKeybind(caption, action: keyAction, 2);

                ImGui.Columns(1);
                ImGui.EndChildFrame();
            }
            ImGui.PopStyleColor();
        }


        void DoClickToSetKeybind(string caption, eKeybind action, int bindIndex)
        {
            _pendingKeybind.active = true;
            _pendingKeybind.actionText = caption;
            _pendingKeybind.bindIndex = bindIndex;
            _pendingKeybind.action = action;

            _pendingKeybind.currentKey = "";
            if (GlobalConfig.PrimaryKeybinds.TryGetValue(action, out var kmval))
            {
                if (kmval.Item2 != ModifierKeys.None)
                    _pendingKeybind.currentKey += kmval.Item2.ToString() + "+";
                _pendingKeybind.currentKey += kmval.Item1;
            }

        }

    }
}