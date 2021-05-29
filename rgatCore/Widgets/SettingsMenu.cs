using ImGuiNET;
using Newtonsoft.Json.Linq;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
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
                    selectedSetting = "PinTool32Path";
                }
                ImGui.PopStyleColor();
                ImGui.TableNextColumn();
                ImGui.Text($"{GlobalConfig.PinToolPath32}");

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
                    GlobalConfig.PinPath = path;
                    break;
                case "PinTool32Path":
                    GlobalConfig.PinToolPath32 = path;
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
        bool _expanded_theme_json = false;

        unsafe void CreateOptionsPane_UITheme()
        {

            if (ImGui.BeginCombo("Preset Themes", "Default"))
            {
                if (ImGui.Selectable("Default", true)) ActivateUIThemePreset("Default");
                if (ImGui.Selectable("Theme 2", false)) ActivateUIThemePreset("Theme 2");
                if (ImGui.Selectable("Theme 3", false)) ActivateUIThemePreset("Theme 3");
                if (ImGui.Selectable("Theme 4", false)) ActivateUIThemePreset("Theme 4");
                ImGui.EndCombo();
            }

            CreateJSONEditor();
           

            if (!ImGui.CollapsingHeader("Customise Theme"))
            {
                return;
            }

            CreateThemeSelectors();

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
            if (ImGui.Button("Restore"))
            {
                RegenerateUIThemeJSON();
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip("Regenerate JSON from the currently applied theme. The current JSON text will be lost.");

            if (disableRestore) { ImGui.PopStyleColor(3); }

            ImGui.SameLine();
            if (ImGui.Button("Save As Preset"))
            {
                Console.WriteLine("Todo save preset");
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip("Store the currently applied theme so it can be reloaded from the above dropdown.");
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

            ImGui.EndGroup();
        }


        void CreateThemeSelectors()
        {
            bool changed = false;
            if (ImGui.TreeNode("Base Widget Colours"))
            {
                for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
                {
                    ImGuiCol stdCol = (ImGuiCol)colI;
                    Vector4 colval = new WritableRgbaFloat(GlobalConfig.GetThemeColourImGui(stdCol)).ToVec4();
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
                    Vector4 colval = new WritableRgbaFloat(GlobalConfig.GetThemeColourUINT(customCol)).ToVec4();
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

            if (ImGui.TreeNode("Metadata"))
            {
                Tuple<string,string>? changedVal = null;
                foreach (KeyValuePair<string, string> kvp in GlobalConfig.ThemeMetadata)
                {
                    string valstr = kvp.Value;
                    if (ImGui.InputText(kvp.Key, ref valstr, 1024, ImGuiInputTextFlags.EnterReturnsTrue))
                    {
                        changed = true;
                        changedVal = new Tuple<string, string>(kvp.Key, valstr);
                    }

                }
                if (changedVal != null)
                {
                    GlobalConfig.ThemeMetadata[changedVal.Item1] = changedVal.Item2;
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

            JObject themeJsnObj = new JObject();

            JObject themeCustom = new JObject();
            foreach (var kvp in GlobalConfig.ThemeColoursCustom) themeCustom.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("CustomColours", themeCustom);

            JObject themeImgui = new JObject();
            foreach (var kvp in GlobalConfig.ThemeColoursStandard) themeImgui.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("StandardColours", themeImgui);

            JObject sizesObj = new JObject();
            foreach (var kvp in GlobalConfig.ThemeSizesCustom) sizesObj.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("Sizes", sizesObj);

            JObject sizeLimitsObj = new JObject();
            foreach (var kvp in GlobalConfig.ThemeSizeLimits) sizeLimitsObj.Add(kvp.Key.ToString(), new JArray(new List<float>() { kvp.Value.X, kvp.Value.Y }));
            themeJsnObj.Add("SizeLimits", sizeLimitsObj);

            JObject metadObj = new JObject();
            foreach (var kvp in GlobalConfig.ThemeMetadata) metadObj.Add(kvp.Key.ToString(), kvp.Value.ToString());
            themeJsnObj.Add("Metadata", metadObj);

            _theme_UI_JSON_Text = themeJsnObj.ToString();
            _theme_UI_JSON = themeJsnObj.ToString();
            _UI_JSON_edited = false;
        }


        void ApplyNewThemeJSONToUI()
        {
            // read this into json
            //_theme_UI_JSON_Text

            //apply it to the config lists/arrays

            _UI_JSON_edited = (_theme_UI_JSON != _theme_UI_JSON_Text);
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
