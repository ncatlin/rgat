using ImGuiNET;
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
        enum eSettingsCategory { eSetting1, eSetting2, eText, eKeybinds, eUITheme, eGraphTheme };

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
            settingsNames.Add("Theme - GUI");
            optionsSelectStates = new bool[settingsNames.Count];
            optionsSelectStates[(int)eSettingsCategory.eText] = false;
            optionsSelectStates[(int)eSettingsCategory.eKeybinds] = false;
            optionsSelectStates[(int)eSettingsCategory.eText] = false;
            optionsSelectStates[(int)eSettingsCategory.eUITheme] = true;
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
                case "Theme - GUI":
                    CreateOptionsPane_UITheme();
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
            CreateKeybindInput("Move Graph Up", eKeybind.MoveUp, index++);
            CreateKeybindInput("Move Graph Down", eKeybind.MoveDown, index++);
            CreateKeybindInput("Move Graph Left", eKeybind.MoveLeft, index++);
            CreateKeybindInput("Move Graph Right", eKeybind.MoveRight, index++);
            CreateKeybindInput("Graph Pitch + (X axis)", eKeybind.PitchXFwd, index++);
            CreateKeybindInput("Graph Pitch - (X axis)", eKeybind.PitchXBack, index++);
            CreateKeybindInput("Graph Roll +  (Y axis)", eKeybind.RollGraphZClock, index++);
            CreateKeybindInput("Graph Roll -  (Y axis)", eKeybind.RollGraphZAnti, index++);
            CreateKeybindInput("Graph Yaw +   (Z axis)", eKeybind.YawYRight, index++);
            CreateKeybindInput("Graph Yaw -   (Z axis)", eKeybind.YawYLeft, index++);
            CreateKeybindInput("Toggle Heatmap", eKeybind.ToggleHeatmap, index++);
            CreateKeybindInput("Toggle Conditionals", eKeybind.ToggleConditionals, index++);
            CreateKeybindInput("Force Direction Temperature +", eKeybind.RaiseForceTemperature, index++);
            CreateKeybindInput("Center Graph In View", eKeybind.CenterFrame, index++);
            CreateKeybindInput("Lock Graph Centered", eKeybind.LockCenterFrame, index++);
            CreateKeybindInput("Toggle All Text", eKeybind.ToggleAllText, index++);
            CreateKeybindInput("Toggle Instruction Text", eKeybind.ToggleInsText, index++);
            CreateKeybindInput("Toggle Dynamic Text", eKeybind.ToggleLiveText, index++);
            CreateKeybindInput("Graph QuickMenu", eKeybind.QuickMenu, index++);
        }


        void ApplyUIJSON()
        {
            Console.WriteLine("Apply UI JSON");
        }



        string _theme_UI_JSON = "fffffffffff";
        string _theme_UI_JSON_Text = "fffffffffff";
        bool _UI_JSON_edited = false;

        unsafe void CreateOptionsPane_UITheme()
        {

            if(ImGui.BeginCombo("Preset Themes", "Default"))
            {
                if (ImGui.Selectable("Default", true)) ActivateUIThemePreset("Default");
                if (ImGui.Selectable("Theme 2", false)) ActivateUIThemePreset("Theme 2");
                if (ImGui.Selectable("Theme 3", false)) ActivateUIThemePreset("Theme 3");
                if (ImGui.Selectable("Theme 4", false)) ActivateUIThemePreset("Theme 4");
                ImGui.EndCombo();
            }

            if (ImGui.InputTextMultiline("", ref _theme_UI_JSON_Text, 10000, new Vector2(ImGui.GetContentRegionAvail().X - 70, 65)))
            {
                _UI_JSON_edited = (_theme_UI_JSON != _theme_UI_JSON_Text);
            }
            if (!_UI_JSON_edited)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, 0xff444444);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0xff444444);
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0xff444444);
            }
            ImGui.BeginGroup();
            if (ImGui.Button("Apply Imported Theme"))
            {
                if (_UI_JSON_edited) RegenerateUIThemeJSON();
            }
            if (!_UI_JSON_edited)
            {
                ImGui.PopStyleColor();
                ImGui.PopStyleColor();
                ImGui.PopStyleColor();
            }
            ImGui.SameLine();
            if (ImGui.Button("Save As Preset"))
            {
                Console.WriteLine("Todo save preset");
            }
            ImGui.EndGroup();

            if (!ImGui.CollapsingHeader("Customise Theme"))
            {
                return;
            }

            bool changed = false;
            if (ImGui.TreeNode("Base Widget Colours"))
            {
                for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
                {
                    ImGuiCol stdCol = (ImGuiCol)colI;
                    Vector4 colval = new WritableRgbaFloat(GlobalConfig.GetThemeColour(stdCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(ImGuiCol), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        GlobalConfig.ThemeColoursStandard[stdCol] = new WritableRgbaFloat(colval).ToUint();
                    }

                }
                ImGui.TreePop();
            }

            if (ImGui.TreeNode("rgat Custom Colours"))
            {
                for (int colI = 0; colI < (int)(GlobalConfig.ThemeColoursCustom.Count); colI++)
                {
                    GlobalConfig.eThemeColour customCol = (GlobalConfig.eThemeColour)colI;
                    Vector4 colval = new WritableRgbaFloat(GlobalConfig.GetThemeColour(customCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(GlobalConfig.eThemeColour), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        GlobalConfig.ThemeColoursCustom[customCol] = new WritableRgbaFloat(colval).ToUint();
                    }

                }
                ImGui.TreePop();
            }

            if (ImGui.TreeNode("Dimensions"))
            {
                for (int dimI = 0; dimI < (int)(GlobalConfig.ThemeSizesCustom.Count); dimI++)
                {
                    GlobalConfig.eThemeSize sizeEnum = (GlobalConfig.eThemeSize)dimI;
                    int size = (int)GlobalConfig.GetThemeSize(sizeEnum);
                    Vector2 sizelimit = GlobalConfig.ThemeSizeLimits[sizeEnum];
                    if (ImGui.SliderInt(Enum.GetName(typeof(GlobalConfig.eThemeColour), dimI), ref size, (int)sizelimit.X, (int)sizelimit.Y))
                    {
                        changed = true;
                        GlobalConfig.ThemeSizesCustom[sizeEnum] = (float)size;
                    }

                }
                ImGui.TreePop();
            }


            if (changed)
            {
                RegenerateUIThemeJSON();
            }

        }

        void RegenerateUIThemeJSON()
        {
            _theme_UI_JSON = "";

            foreach (KeyValuePair<ImGuiCol, uint> kvp in GlobalConfig.ThemeColoursStandard)
            { 
                ImGuiCol col = kvp.Key;
                uint colval = kvp.Value;
                _theme_UI_JSON += $"{Enum.GetName(typeof(ImGuiCol), (int)col)}:#{colval:X}";
            }
            _theme_UI_JSON_Text = _theme_UI_JSON;
        }

        void ActivateUIThemePreset(string name)
        {

            //todo
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
