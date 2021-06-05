using ImGuiNET;
using Newtonsoft.Json.Linq;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Veldrid;

namespace rgatCore.Widgets
{
    class SettingsMenu
    {
        static bool[] optionsSelectStates;
        static List<string> settingsNames = new List<string>();
        enum eSettingsCategory { eSetting1, eFiles, eText, eKeybinds, eUITheme, eGraphTheme };

        public SettingsMenu()
        {
            InitSettings();
        }

        readonly static uint INVALID_VALUE_TEXTBOX_COLOUR = 0xcc5555ff;


        PendingKeybind _pendingKeybind = new PendingKeybind();
        public bool HasPendingKeybind
        {
            get => _pendingKeybind.active;
            set => _pendingKeybind.active = value;
        }

        public void AssignPendingKeybind(Tuple<Key, ModifierKeys> keybind)
        {
            GlobalConfig.SetKeybind(_pendingKeybind.action, _pendingKeybind.bindIndex, keybind.Item1, keybind.Item2, true);
            _pendingKeybind.active = false;
        }




        void InitSettings()
        {
            RegenerateUIThemeJSON();

            settingsNames = new List<string>();
            settingsNames.Add("Files");
            settingsNames.Add("Setting2");
            settingsNames.Add("Text");
            settingsNames.Add("Keybinds");
            settingsNames.Add("Theme - GUI");
            optionsSelectStates = new bool[settingsNames.Count];
            optionsSelectStates[(int)eSettingsCategory.eFiles] = false;
            optionsSelectStates[(int)eSettingsCategory.eText] = false;
            optionsSelectStates[(int)eSettingsCategory.eKeybinds] = false;
            optionsSelectStates[(int)eSettingsCategory.eText] = false;
            optionsSelectStates[(int)eSettingsCategory.eUITheme] = true;
        }

        void DeclareError(string msg, long MSDuration = 5500)
        {
            _errorExpiryTime = DateTime.Now.AddMilliseconds(MSDuration);
            _errorBanner = msg;
        }

        public void Draw(ref bool window_shown_flag)
        {
            ImGui.SetNextWindowSize(new Vector2(700, 500), ImGuiCond.FirstUseEver);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.None;

            string title = "Settings";
            bool hasError = _errorExpiryTime > DateTime.Now;

            if (hasError)
            {
                title += " -- " + _errorBanner;
                ImGui.PushStyleColor(ImGuiCol.TitleBgActive, 0xff2525FF);
            }

            ImGui.Begin(title + "###Settings", ref window_shown_flag, window_flags);

            ImGui.BeginGroup();
            if (ImGui.BeginChildFrame(ImGui.GetID("SettingsCategories"), new Vector2(200, ImGui.GetContentRegionAvail().Y - 35)))
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

            if (hasError)
            {
                ImGui.PopStyleColor();
            }
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
                case "Files":
                    CreateOptionsPane_Files();
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

        string _errorBanner = "";
        DateTime _errorExpiryTime = DateTime.MinValue;
        string _pendingPathSetting;

        bool mush = false;
        void CreateOptionsPane_Files()
        {
            string selectedSetting = "";
            uint pid = ImGui.GetID("##FilesDLG");
            if (ImGui.BeginTable("#PathsTable", 2))//, ImGuiTableFlags.PreciseWidths, ImGui.GetContentRegionAvail()))
            {
                ImGui.TableSetupColumn("Setting", ImGuiTableColumnFlags.WidthFixed, 180);
                ImGui.TableSetupColumn("Path");

                ImGui.TableHeadersRow();
                ImGui.TableNextRow();
                ImGui.TableNextColumn();

                ImGui.PushStyleColor(ImGuiCol.Text, 0xeeeeeeee);
                if (ImGui.Selectable($"Pin.exe", mush, ImGuiSelectableFlags.SpanAllColumns))
                {
                    selectedSetting = "PinPath";
                }
                ImGui.PopStyleColor();
                ImGui.TableNextColumn();
                ImGui.Text($"{GlobalConfig.PinPath}");



                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.PushStyleColor(ImGuiCol.Text, 0xeeeeeeee);

                if (ImGui.Selectable($"Pintool32.dll", mush, ImGuiSelectableFlags.SpanAllColumns))
                {
                    selectedSetting = "PinToolPath32";
                }
                ImGui.PopStyleColor();
                ImGui.TableNextColumn();
                ImGui.Text($"{GlobalConfig.PinToolPath32}");


                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.PushStyleColor(ImGuiCol.Text, 0xeeeeeeee);

                if (ImGui.Selectable($"Pintool64.dll", mush, ImGuiSelectableFlags.SpanAllColumns))
                {
                    selectedSetting = "PinToolPath64";
                }
                ImGui.PopStyleColor();
                ImGui.TableNextColumn();
                ImGui.Text($"{GlobalConfig.PinToolPath64}");

                ImGui.EndTable();
            }

            //doesn't seem to work inside table (ID issue?), so do it after
            if (selectedSetting.Length > 0)
            {
                LaunchFileSelectBox(selectedSetting, "##FilesDLG");
            }

            DrawFileSelectBox();
        }


        void ChoseSettingPath(string setting, string path)
        {
            switch (setting)
            {
                case "PinPath":
                    GlobalConfig.SetBinaryPath("PinPath", path);
                    break;
                case "PinToolPath32":
                    GlobalConfig.SetBinaryPath("PinToolPath32", path);
                    break;
                case "PinToolPath64":
                    GlobalConfig.SetBinaryPath("PinToolPath64", path);
                    break;
                default:
                    Logging.RecordLogEvent("Bad path setting " + setting, Logging.LogFilterType.TextAlert);
                    break;
            }
        }


        void LaunchFileSelectBox(string setting, string popupID)
        {

            ImGui.SetNextWindowSize(new Vector2(800, 820), ImGuiCond.Appearing);
            ImGui.OpenPopup(popupID);
            _pendingPathSetting = setting;
        }


        bool f = true;
        private void DrawFileSelectBox()
        {
            if (ImGui.BeginPopupModal("##FilesDLG", ref f))
            {

                var picker = rgatFilePicker.FilePicker.GetFilePicker(this, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(this);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        if (File.Exists(picker.SelectedFile))
                        {
                            ChoseSettingPath(_pendingPathSetting, picker.SelectedFile);
                        }
                        else
                        {
                            DeclareError($"Error: Path {picker.SelectedFile} does not exist");
                        }
                        rgatFilePicker.FilePicker.RemoveFilePicker(this);
                    }

                }
            }
            ImGui.EndPopup();

        }



        void CreateOptionsPane_Keybinds()
        {
            if (_pendingKeybind.active)
                ImGui.OpenPopup("Activate New Keybind");

            if (ImGui.BeginPopupModal("Activate New Keybind", ref _pendingKeybind.active, ImGuiWindowFlags.AlwaysAutoResize))
            {
                float frameHeight = 110 + (_pendingKeybind.IsResponsive ? 20 : 0);
                if (ImGui.BeginChildFrame(ImGui.GetID("KBPopFrame"), new Vector2(280, frameHeight)))
                {
                    ImGui.Text("Binding: " + _pendingKeybind.actionText);

                    ImGui.Text($"Current keybind: [{_pendingKeybind.currentKey}]");

                    string msg = "Press new keybind now";

                    float msgWidth = ImGui.CalcTextSize(msg).X;

                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X / 2) - msgWidth / 2);
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 15);
                    ImGui.Text(msg);
                    if (_pendingKeybind.IsResponsive)
                    {
                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 15);
                        ImGui.Separator();
                        ImGui.Text("Note: Modifier keys are invalid for this action");
                        ImGui.Separator();
                    }
                    ImGui.EndChildFrame();
                }
                ImGui.EndPopup();
            }

            int index = 0;
            ImGuiTableFlags tableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.NoHostExtendX 
                | ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders | ImGuiTableFlags.Resizable;
            if (ImGui.BeginTable("KeybindSelectTable", 3, tableFlags, ImGui.GetContentRegionAvail()- new Vector2(0, 80)))
            {
                ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, 350);
                ImGui.TableSetupColumn("Keybind", ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("Alternate Keybind", ImGuiTableColumnFlags.None);
                ImGui.TableHeadersRow();

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
                ImGui.EndTable();
            }

            ImGui.SetCursorPos(ImGui.GetCursorPos() + new Vector2((ImGui.GetContentRegionMax().X / 2) - 70, 17));
            if (ImGui.Button("Restore Defaults", new Vector2(140, 34)))
            {
                GlobalConfig.ResetKeybinds();
            }


        }


        void ApplyUIJSON()
        {
            Console.WriteLine("Apply UI JSON");
        }



        string _theme_UI_JSON = "fffffffffff";
        string _theme_UI_JSON_Text = "fffffffffff";
        bool _UI_JSON_edited = false;
        bool _expanded_theme_json = false;
        string pendingPresetName = "";
        bool popejn = true;

        unsafe void CreateOptionsPane_UITheme()
        {
            if (Themes.UnsavedTheme)
            {
                ImGui.Text($"Current Theme: {Themes.ThemeMetadata["Name"]} [Modified - Unsaved]. Save as a preset to keep changes.");
            }
            else
            {
                ImGui.Text($"Current Theme: {Themes.ThemeMetadata["Name"]}");
            }

            ImGui.SameLine();
            if (ImGui.Button("Save As Preset"))
            {
                pendingPresetName = Themes.ThemeMetadata["Name"];
                ImGui.OpenPopup("##SavePreset");
                ImGui.SetNextWindowSize(new Vector2(300, 160));
            }
            else
            {
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Store the currently applied theme so it can be reloaded from the above dropdown.");
            }

            DrawSavePresetPopUp();


            if (ImGui.BeginCombo("Preset Themes", Themes.ThemeMetadata["Name"]))
            {
                foreach (string themeName in Themes.ThemesMetadataCatalogue.Keys)
                {
                    string themeLabel = themeName;
                    if (Themes.DefaultTheme == themeName)
                        themeLabel += "  [Default]";
                    if (ImGui.Selectable(themeName, true))
                        ActivateUIThemePreset(themeName);
                    if (ImGui.IsItemHovered())
                    {
                        string tipDescription = $"Name: {themeName}\r\n";
                        if (Themes.ThemeMetadata.TryGetValue("Description", out string themeDescription)) tipDescription += $"Description: {themeDescription}\r\n";
                        if (Themes.ThemeMetadata.TryGetValue("Author", out string auth1)) tipDescription += $"Source: {auth1}";
                        if (Themes.ThemeMetadata.TryGetValue("Author2", out string auth2)) tipDescription += $" ({auth2})";

                        ImGui.SetTooltip(tipDescription);
                    }


                }
                ImGui.EndCombo();
            }

            if (ImGui.CollapsingHeader("Manage Theme"))
            {
                CreateJSONEditor();
                ImGui.NextColumn();
            }

            if (ImGui.CollapsingHeader("Test Theme"))
            {
                CreateThemeTester();
                ImGui.NextColumn();
            }

            if (ImGui.CollapsingHeader("Customise Theme"))
            {
                ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff000000);
                ImGui.PushStyleColor(ImGuiCol.Text, 0xffffffff);
                CreateThemeSelectors();
                ImGui.PopStyleColor(2);
                ImGui.NextColumn();
            }


        }

        void DrawSavePresetPopUp()
        {
            if (ImGui.BeginPopupModal("##SavePreset"))
            {
                bool validName = !Themes.BuiltinThemes.ContainsKey(pendingPresetName) && !pendingPresetName.Contains('"');

                if (!validName)
                {
                    ImGui.PushStyleColor(ImGuiCol.FrameBg, INVALID_VALUE_TEXTBOX_COLOUR);
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xff333333);
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0xff333333);
                    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0xff333333);
                }
                ImGui.Text("Theme Name");
                if (ImGui.InputText("", ref pendingPresetName, 255, ImGuiInputTextFlags.EnterReturnsTrue) && validName)
                {
                    Themes.SavePresetTheme(pendingPresetName);
                    ImGui.CloseCurrentPopup();
                }
                if (validName && ImGui.Button("Save"))
                {
                    Themes.SavePresetTheme(pendingPresetName);
                    ImGui.CloseCurrentPopup();
                }
                if (!validName)
                {
                    ImGui.Text("Invalid name");
                    ImGui.PopStyleColor(4);
                }
                ImGui.EndPopup();
            }

        }

        void CreateJSONEditor()
        {
            //This widget doesn't have wrapping https://github.com/ocornut/imgui/issues/952
            //the json generator makes nice newline pretty printed text so not worth implementing a custom fix
            float height = _expanded_theme_json ? 500 : 70;
            if (ImGui.InputTextMultiline("", ref _theme_UI_JSON_Text, 10000, new Vector2(ImGui.GetContentRegionAvail().X - 70, height)))
            {
                _UI_JSON_edited = (_theme_UI_JSON != _theme_UI_JSON_Text);
            }

            bool disableRestore = !_UI_JSON_edited;
            if (disableRestore)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, 0xff444444);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0xff444444);
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0xff444444);
            }
            ImGui.BeginGroup();
            if (ImGui.Button("Apply Imported Theme"))
            {
                if (_UI_JSON_edited) ApplyNewThemeJSONToUI();
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip("Apply the theme from the JSON editor to the UI. Any settings not specified will be unchanged.");

            ImGui.SameLine();
            if (ImGui.Button("Cancel"))
            {
                RegenerateUIThemeJSON();
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip("Restore export text from the currently applied theme. The changes will be lost.");

            if (disableRestore) { ImGui.PopStyleColor(3); }


            ImGui.SameLine();
            if (ImGui.Button("Copy"))
            {
                ImGui.LogToClipboard();
                int blockSize = 255; //LogText won't copy more than this at once
                for (var written = 0; written < _theme_UI_JSON_Text.Length; written += blockSize)
                    if (written < _theme_UI_JSON_Text.Length)
                        ImGui.LogText(_theme_UI_JSON_Text.Substring(written, Math.Min(blockSize, _theme_UI_JSON_Text.Length - written)));
                ImGui.LogFinish();
            }
            ImGui.SameLine();
            string expandBtnText = _expanded_theme_json ? "Collapse" : "Expand";
            string expandBtnTip = _expanded_theme_json ? "Collapse the JSON editor" : "Expand the JSON editor";
            if (ImGui.Button(expandBtnText))
            {
                _expanded_theme_json = !_expanded_theme_json;
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(expandBtnTip);

            if (Themes.DefaultTheme != Themes.ThemeMetadata["Name"])
            {
                ImGui.SameLine();
                if (ImGui.Button("Set As Default"))
                {
                    Themes.DefaultTheme = Themes.ThemeMetadata["Name"];
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Cause this theme to be activated when rgat is launched");
            }

            if (!Themes.IsBuiltinTheme)
            {
                ImGui.SameLine();
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 20);
                ImGui.PushStyleColor(ImGuiCol.Button, 0x9B331EFF);
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0xff3344ff);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0xff0000ff);
                if (ImGui.Button("Delete"))
                {
                    DeleteCurrentTheme();
                }
                ImGui.PopStyleColor(3);
            }


            ImGui.EndGroup();
        }

        void DeleteCurrentTheme()
        {
            string oldTheme = Themes.ThemeMetadata["Name"];

            //todo load default theme
            if (Themes.BuiltinThemes.Count > 0)
            {
                ActivateUIThemePreset(Themes.BuiltinThemes.Keys.First());
            }
            else
            {
                Logging.RecordLogEvent("Cannot delete theme, no builtin theme to revert to", Logging.LogFilterType.TextError);
                return;
            }

            Themes.DeleteTheme(oldTheme);
        }


        void CreateThemeTester()
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.WindowBg));
            if (ImGui.BeginChild(ImGui.GetID("ThemeTestContainer2"), new Vector2(ImGui.GetContentRegionMax().X, 250), false, ImGuiWindowFlags.AlwaysAutoResize))
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.ChildBg));
                DrawThemeTestFrame();
                ImGui.PopStyleColor();
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        bool testCheck = true;
        float testSlider = 25f;
        void DrawThemeTestFrame()
        {
            float padding = 10;
            ImGui.SetCursorPos(ImGui.GetCursorPos() + new Vector2(padding, padding));

            if (ImGui.BeginChild("#rtghw489", ImGui.GetContentRegionAvail() - new Vector2(padding * 2, padding * 2), true, ImGuiWindowFlags.AlwaysAutoResize))
            {
                if (ImGui.BeginTabBar("#TestTabVar"))
                {
                    if (ImGui.BeginTabItem("General Widgets Tab"))
                    {
                        ImGui.BeginGroup();
                        {
                            ImGui.Text("TestFrame");
                            if (ImGui.BeginCombo("TestCombo", "Item1 (Colour: FrameBg)"))
                            {
                                ImGui.Selectable("Item1");
                                ImGui.Selectable("Item2 (Colour: PopupBg)");
                                ImGui.EndCombo();
                            }
                            ImGui.SameLine();

                            ImGui.Checkbox("CheckBox", ref testCheck);
                            ImGui.Separator();

                            ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("TestFrameTable", 2, tableFlags))
                            {
                                ImGui.TableSetupColumn("Table Column 1", ImGuiTableColumnFlags.WidthFixed, 90);
                                ImGui.TableSetupColumn("Table Column 2", ImGuiTableColumnFlags.WidthFixed, 100);
                                ImGui.TableHeadersRow();
                                for (var i = 0; i < 3; i++)
                                {
                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();
                                    ImGui.Text($"Cell{i * 2}");
                                    ImGui.TableNextColumn();
                                    ImGui.Text($"Cell{i * 2 + 1}");
                                }
                                ImGui.EndTable();
                            }
                            ImGui.SameLine();
                            ImGui.BeginGroup();
                            ImGui.Button("Button", new Vector2(120, 25));
                            ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.ButtonHovered));
                            ImGui.Button("Button (Hovered)", new Vector2(120, 25));
                            ImGui.PopStyleColor();
                            ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.ButtonActive));
                            ImGui.Button("Button (Active)", new Vector2(120, 25));
                            ImGui.PopStyleColor();
                            ImGui.EndGroup();

                            ImGui.SliderFloat("Slider", ref testSlider, 0, 100);
                            ImGui.EndGroup();

                        }
                        ImGui.SameLine();
                        ImGui.BeginGroup();
                        {
                            ImGui.EndGroup();
                        }
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Custom Widgets Tab"))
                    {
                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }
                ImGui.EndChild();
            }
        }

        unsafe void CreateThemeSelectors()
        {
            bool changed = false;
            ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY;
            Vector2 tableSize = new Vector2(ImGui.GetContentRegionAvail().X, 350);
            if (ImGui.BeginTable(str_id: "##SelectorsTable", column: 2, flags: tableFlags, outer_size: tableSize))
            {
                float halfWidth = ImGui.GetContentRegionAvail().X / 2;
                ImGui.TableSetupColumn("General Widget Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupColumn("Custom Widget Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableHeadersRow();

                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
                {
                    ImGuiCol stdCol = (ImGuiCol)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourImGui(stdCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(ImGuiCol), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        Themes.ThemeColoursStandard[stdCol] = new WritableRgbaFloat(colval).ToUint();
                    }

                }

                ImGui.TableSetColumnIndex(1);
                for (int colI = 0; colI < (int)(Themes.ThemeColoursCustom.Count); colI++)
                {
                    Themes.eThemeColour customCol = (Themes.eThemeColour)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourUINT(customCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(Themes.eThemeColour), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        Themes.ThemeColoursCustom[customCol] = new WritableRgbaFloat(colval).ToUint();
                    }

                }
                ImGui.EndTable();
            }

            if (ImGui.TreeNode("Dimensions"))
            {
                for (int dimI = 0; dimI < (int)(Themes.ThemeSizesCustom.Count); dimI++)
                {
                    Themes.eThemeSize sizeEnum = (Themes.eThemeSize)dimI;
                    int size = (int)Themes.GetThemeSize(sizeEnum);
                    Vector2 sizelimit = Themes.ThemeSizeLimits[sizeEnum];
                    if (ImGui.SliderInt(Enum.GetName(typeof(Themes.eThemeColour), dimI), ref size, (int)sizelimit.X, (int)sizelimit.Y))
                    {
                        changed = true;
                        Themes.ThemeSizesCustom[sizeEnum] = (float)size;
                    }

                }
                ImGui.TreePop();
            }

            if (ImGui.TreeNode("Metadata"))
            {
                Tuple<string, string>? changedVal = null;
                Dictionary<string, string> currentMetadata = new Dictionary<string, string>(Themes.ThemeMetadata);
                foreach (KeyValuePair<string, string> kvp in currentMetadata)
                {
                    string value = kvp.Value;
                    bool validValue = true;
                    if (badFields.Contains(kvp.Key))
                        validValue = false;

                    if (!validValue)
                    {
                        ImGui.PushStyleColor(ImGuiCol.FrameBg, INVALID_VALUE_TEXTBOX_COLOUR);
                    }
                    ImGuiInputTextCallbackData d = new ImGuiInputTextCallbackData();
                    ImGuiInputTextCallbackDataPtr dp = new ImGuiInputTextCallbackDataPtr();
                    IntPtr p = Marshal.StringToHGlobalUni(kvp.Key);

                    ImGuiInputTextFlags flags = ImGuiInputTextFlags.EnterReturnsTrue | ImGuiInputTextFlags.CallbackEdit;
                    ImGui.InputText(kvp.Key, ref value, 1024, flags, (ImGuiInputTextCallback)settingTextCheckValid, p);

                    if (!validValue)
                    {
                        ImGui.PopStyleColor();
                    }

                }
                if (changedVal != null)
                {
                    Themes.ThemeMetadata[changedVal.Item1] = changedVal.Item2;
                }
                ImGui.TreePop();
            }



            if (changed)
            {
                Themes.UnsavedTheme = true;
                RegenerateUIThemeJSON();
            }
        }

        static List<string> badFields = new List<string>();

        //this is terrible
        static unsafe int settingTextCheckValid(ImGuiInputTextCallbackData* p)
        {
            ImGuiInputTextCallbackData cb = *p;
            byte[] currentValue = new byte[cb.BufTextLen];
            Marshal.Copy((IntPtr)cb.Buf, currentValue, 0, p->BufTextLen);
            string actualCurrentValue = Encoding.ASCII.GetString(currentValue);

            string? keyname = Marshal.PtrToStringAuto((IntPtr)cb.UserData);
            if (keyname != null)
            {
                bool validValue = true;

                if (keyname == "Name" && Themes.BuiltinThemes.ContainsKey(actualCurrentValue)) validValue = false;
                if (actualCurrentValue.Contains('"')) validValue = true;

                if (badFields.Contains(keyname) && validValue)
                {
                    badFields.Remove(keyname);
                }
                else if (!badFields.Contains(keyname) && !validValue)
                {
                    badFields.Add(keyname);
                }
                if (validValue)
                {
                    Themes.SaveMetadataChange(keyname, actualCurrentValue);
                }
            }

            Marshal.FreeHGlobal((IntPtr)cb.UserData);
            return 0;
        }


        void RegenerateUIThemeJSON()
        {
            _theme_UI_JSON = Themes.RegenerateUIThemeJSON();
            _theme_UI_JSON_Text = _theme_UI_JSON;
            _UI_JSON_edited = false;
        }


        void ApplyNewThemeJSONToUI()
        {
            // read this into json
            //_theme_UI_JSON_Text

            //apply it to the config lists/arrays
            if (!Themes.ActivateThemeObject(_theme_UI_JSON_Text, out string error))
            {
                Console.WriteLine("Failed to load json");
                return;
            }

            RegenerateUIThemeJSON();

            _UI_JSON_edited = (_theme_UI_JSON != _theme_UI_JSON_Text);
        }


        void ActivateUIThemePreset(string name)
        {
            Themes.LoadTheme(name);
        }






        void CreateKeybindInput(string caption, eKeybind keyAction, int rowIndex)
        {
            uint bindFramecol = ((rowIndex % 2) == 0) ? 0xafcc3500 : 0xafdc4500;
            ImGui.PushStyleColor(ImGuiCol.FrameBg, bindFramecol);

            ImGui.TableNextRow();
            ImGui.TableNextColumn();

            ImGui.Text(caption);

            ImGui.TableNextColumn();



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

            ImGui.TableNextColumn();


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

            ImGui.PopStyleColor();
        }


        void DoClickToSetKeybind(string caption, eKeybind action, int bindIndex)
        {
            _pendingKeybind.active = true;
            _pendingKeybind.actionText = caption;
            _pendingKeybind.bindIndex = bindIndex;
            _pendingKeybind.action = action;

            _pendingKeybind.IsResponsive = GlobalConfig.ResponsiveHeldActions.Contains(action);

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
