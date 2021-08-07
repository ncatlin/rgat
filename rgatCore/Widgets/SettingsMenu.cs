using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Veldrid;

namespace rgat.Widgets
{
    class SettingsMenu
    {
        static bool[] optionsSelectStates;
        static List<string> settingsNames = new List<string>();
        static ImGuiController _controller;
        static rgatState _rgatState;

        enum eSettingsCategory { eSignatures, eFiles, eText, eKeybinds, eUITheme, eMisc, eVideoEncode };

        public SettingsMenu(ImGuiController controller, rgatState rgatstate)
        {
            _controller = controller;
            _rgatState = rgatstate;
            InitSettings();

            settingTips["PinPath"] = "The path to pin.exe - the Intel Pin Dynamic Instrumentation program.";
            settingTips["PinToolPath32"] = "The path to the 32-bit pingat.dll rgat pin tool which is used by pin to instrument target programs";
            settingTips["PinToolPath64"] = "The path to the 64-bit pingat.dll rgat pin tool which is used by pin to instrument target programs";
            settingTips["FFmpegPath"] = "The path to the FFmpeg executable for recording video captures";

            settingTips["TraceSaveDirectory"] = "The directory where trace save files (.rgat) are stored";
            settingTips["TestsDirectory"] = "The directory where rgat development tests are stored. These can be downloaded from [todo]";
            settingTips["DiESigsPath"] = "The directory containing Detect It Easy signature scripts for file and memory scanning";
            settingTips["YaraRulesPath"] = "The directory containing YARA rules for file and memory scanning";
            settingTips["MediaCapturePath"] = "The directory where videos recordings and images are saved";
        }

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
            {
                //ImGui.BeginGroup();
                //ImGui.EndGroup();

                
                    ImGui.BeginGroup();
                {
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
                        if (ImGui.Button("Close1", new Vector2(65, 25)))
                        {
                            window_shown_flag = false;
                        }
                    
                ImGui.EndGroup();
                }
                
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
            if (hasError)
            {
                ImGui.PopStyleColor();
            }
        }

        void InitSettings()
        {
            RegenerateUIThemeJSON();

            settingsNames = new List<string>();
            settingsNames.Add("Files");
            settingsNames.Add("Signatures");
            settingsNames.Add("Text");
            settingsNames.Add("Keybinds");
            settingsNames.Add("Theme");
            settingsNames.Add("Video Encoder");
            settingsNames.Add("Miscellaneous");
            optionsSelectStates = new bool[settingsNames.Count];
            optionsSelectStates[(int)eSettingsCategory.eFiles] = false;
            optionsSelectStates[(int)eSettingsCategory.eText] = false;
            optionsSelectStates[(int)eSettingsCategory.eKeybinds] = false;
            optionsSelectStates[(int)eSettingsCategory.eSignatures] = false;
            optionsSelectStates[(int)eSettingsCategory.eUITheme] = true;
            optionsSelectStates[(int)eSettingsCategory.eVideoEncode] = false;
            optionsSelectStates[(int)eSettingsCategory.eMisc] = false;
        }

        void DeclareError(string msg, long MSDuration = 5500)
        {
            _errorExpiryTime = DateTime.Now.AddMilliseconds(MSDuration);
            _errorBanner = msg;
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
                case "Signatures":
                    CreateOptionsPane_Signatures();
                    break;
                case "Theme":
                    CreateOptionsPane_UITheme();
                    break;
                case "Video Encoder":
                    CreateOptionsPane_VideoEncode();
                    break;
                case "Miscellaneous":
                    CreateOptionsPane_Miscellaneous();
                    break;
                default:
                    Console.WriteLine($"Warning: Bad option category '{settingCategoryName}' selected");
                    break;
            }
        }





        void CreateOptionsPane_Signatures()
        {
            if (_rgatState.YARALib == null || _rgatState.DIELib == null) return; //loading

            //available/enabled/loaded signatures pane
            //scanning controls
            //download more btn
   
            Vector2 tabsize = ImGui.GetContentRegionAvail() - new Vector2(0, 100);
            if (ImGui.BeginChild("#SignaturesPane", tabsize, false, ImGuiWindowFlags.None))
            {
                ImGui.Text("Available Signatures");
                ImGui.SameLine();
                ImGui.Button("Get More");

                if (ImGui.BeginTabBar("#SigsAvailableTab", ImGuiTabBarFlags.None))
                {
                    if (ImGui.BeginTabItem("YARA Rules"))
                    {
                        if (ImGui.BeginChild("YaraSigsList", ImGui.GetContentRegionAvail(), true))
                        {
                            var ruleList = _rgatState.YARALib.GetRuleData();

                            ImGuiTableFlags flags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("#SettsYaraRuleList", 3, flags, ImGui.GetContentRegionAvail()))//))
                            {
                                ImGui.TableSetupColumn("Rule", ImGuiTableColumnFlags.WidthFixed, 160);
                                ImGui.TableSetupColumn("Collection", ImGuiTableColumnFlags.WidthFixed, 80);
                                ImGui.TableSetupColumn("Metadata");
                                ImGui.TableSetupScrollFreeze(0, 1);
                                ImGui.TableHeadersRow();

                                ImGui.Indent(5);
                                foreach (var rule in ruleList)
                                {
                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();
                                    ImGui.TextWrapped(rule.Identifier);

                                    ImGui.TableNextColumn();
                                    ImGui.TextWrapped("folder 1 2 3");

                                    ImGui.TableNextColumn();
                                    foreach (var kvp in rule.Metas)
                                    {
                                        ImGui.TextWrapped($"{kvp.Key}: \"{kvp.Value}\"");
                                    }
                                    if (rule.Tags.Any())
                                    {
                                        ImGui.TextWrapped($"Tags: {String.Join(", ", rule.Tags)}");
                                    }
                                }
                                ImGui.EndTable();
                            }
                            ImGui.EndChild();
                        }
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Detect It Easy Scripts"))
                    {
                        if (ImGui.BeginChild("DieSigsList", ImGui.GetContentRegionAvail(), true))
                        {
                            var ruleList = _rgatState.DIELib.GetSignatures;

                            ImGuiTableFlags flags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("#SettsDieRuleList", 2, flags, ImGui.GetContentRegionAvail()))//))
                            {
                                ImGui.TableSetupColumn("File Format", ImGuiTableColumnFlags.WidthFixed, 120);
                                ImGui.TableSetupColumn("Loaded Rule");
                                ImGui.TableSetupScrollFreeze(0, 1);
                                ImGui.TableHeadersRow();

                                ImGui.Indent(5);
                                foreach (var rule in ruleList)
                                {
                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();
                                    ImGui.TextWrapped(rule.fileType.ToString());

                                    ImGui.TableNextColumn();
                                    ImGui.TextWrapped(rule.name);
                                }
                                ImGui.EndTable();
                            }
                            ImGui.EndChild();
                        }
                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }
                ImGui.EndChild();
            }
            bool test = true;
            if (ImGui.BeginChild("#SignatureOptsPane", ImGui.GetContentRegionAvail(), true, ImGuiWindowFlags.None))
            {
                if (ImGui.BeginTable("#ScanConditionsTable", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX))
                {
                    ImGui.TableSetupColumn("Format", ImGuiTableColumnFlags.WidthFixed, 140);
                    ImGui.TableSetupColumn("Scan File On Load", ImGuiTableColumnFlags.WidthFixed, 130);
                    ImGui.TableSetupColumn("Scan Memory", ImGuiTableColumnFlags.WidthFixed, 90);

                    ImGui.TableHeadersRow();
                    uint formatCellColour = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg)).ToUint(0xd0);
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, formatCellColour);
                    uint yaraSigsCount = _rgatState.YARALib.LoadedRuleCount();
                    ImGui.Text($"YARA ({yaraSigsCount} rules)");
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##fycheck", ref GlobalConfig.ScanFilesYARA);
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##mycheck", ref GlobalConfig.ScanMemoryYARA);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, formatCellColour);
                    int dieFileSigsCount = _rgatState.DIELib.NumScriptsLoaded;
                    ImGui.Text($"DiE ({dieFileSigsCount} scripts)");
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##fdcheck", ref GlobalConfig.ScanFilesDiE);
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##mdcheck", ref GlobalConfig.ScanMemoryDiE);

                    ImGui.EndTable();
                }


                ImGui.EndChild();
            }

        }

        void CreateOptionsPane_Text()
        {

            ImGui.Text("todo");
        }

        string _errorBanner = "";
        DateTime _errorExpiryTime = DateTime.MinValue;
        string _pendingPathSetting;

        bool DrawPathMenuOption(string caption, string path, string tooltip, out bool clearFlag)
        {
            bool selected = false;
            bool hovered = false;
            bool hasPath = (path?.Length > 0);
            string pathTxt = hasPath ? path : "[Not Set]";
            string signerror = "";

            GlobalConfig.CheckSignatureError(path, out signerror, out bool signatureTimeWarning);

            ImGui.TableNextRow(); 
            ImGui.TableNextColumn();


            ImGui.PushStyleColor(ImGuiCol.Text, 0xeeeeeeee);
            bool notSelected = false;
            ImGui.Text(caption);
            hovered = hovered || ImGui.IsItemHovered();
            ImGui.PopStyleColor();
            ImGui.TableNextColumn();

            bool signatureError = signerror.Length > 0 && signerror != "No Error";

            if (signatureError)
            {
                if (signatureTimeWarning)
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.eWarnStateColour));
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                }
            }
            if (ImGui.Selectable(pathTxt + "##Sel" + caption, notSelected, ImGuiSelectableFlags.None))
            {
                selected = true;
            }

            if (signatureError) { ImGui.PopStyleColor();  }

            hovered = hovered || ImGui.IsItemHovered();

            ImGui.TableNextColumn();
            if (hasPath)
            {
                SmallWidgets.DrawClickableIcon(controller: _controller, "Cross", offset: new Vector2(0, -2));
                clearFlag = ImGui.IsItemClicked();
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("Clear the path");
                }
            }
            else
            {
                clearFlag = false;
            }

            if (hovered)
            {
                ImGui.BeginTooltip();
                ImGui.Text(tooltip);
                if (hasPath) ImGui.Text(path);
                if (signatureError)
                {
                    if (signatureTimeWarning)
                    {
                        ImGui.Text("-----Bad Signature Validity Date-----");
                    }
                    else
                    {
                        ImGui.Text("-----Signature Verification Failed-----");
                    }
                    ImGui.Text("\t" + signerror);
                }

                ImGui.EndTooltip();
            }

            return clearFlag || selected;
        }

        Dictionary<string, string> settingTips = new Dictionary<string, string>();

        void CreateOptionsPane_Files()
        {
            string choosePath = "";
            bool isFolder = false;
            bool doClear = false;

            if (ImGui.BeginTable("#PathsTable", 3, ImGuiTableFlags.RowBg))//, ImGuiTableFlags.PreciseWidths, ImGui.GetContentRegionAvail()))
            {
                ImGui.TableSetupColumn("Setting", ImGuiTableColumnFlags.WidthFixed, 180);
                ImGui.TableSetupColumn("Path");
                ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 35);

                ImGui.TableHeadersRow();


                if (DrawPathMenuOption("Pin Executable", GlobalConfig.PinPath, settingTips["PinPath"], out bool clearFlag))
                { choosePath = "PinPath"; doClear |= clearFlag; }

                if (DrawPathMenuOption("Pintool32 Library", GlobalConfig.PinToolPath32, settingTips["PinToolPath32"], out clearFlag))
                { choosePath = "PinToolPath32"; doClear |= clearFlag; }

                if (DrawPathMenuOption("Pintool64 Library", GlobalConfig.PinToolPath64, settingTips["PinToolPath64"], out clearFlag))
                { choosePath = "PinToolPath64"; doClear |= clearFlag; }

                if (DrawPathMenuOption("FFmpeg Executable", GlobalConfig.FFmpegPath, settingTips["FFmpegPath"], out clearFlag))
                { choosePath = "FFmpegPath"; doClear |= clearFlag; }

                if (choosePath.Length == 0) isFolder = true;

                if (DrawPathMenuOption("Saved Traces", GlobalConfig.TraceSaveDirectory, settingTips["TraceSaveDirectory"], out clearFlag))
                { choosePath = "TraceSaveDirectory"; doClear |= clearFlag; }

                if (DrawPathMenuOption("Tests", GlobalConfig.TestsDirectory, settingTips["TestsDirectory"], out clearFlag))
                { choosePath = "TestsDirectory"; doClear |= clearFlag; }

                if (DrawPathMenuOption("DiE Signatures", GlobalConfig.DiESigsPath, settingTips["DiESigsPath"], out clearFlag))
                { choosePath = "DiESigsPath"; doClear |= clearFlag; }

                if (DrawPathMenuOption("Yara Rules", GlobalConfig.YARARulesDir, settingTips["YaraRulesPath"], out clearFlag))
                { choosePath = "YaraRulesPath"; doClear |= clearFlag; }

                if (DrawPathMenuOption("Images/Videos", GlobalConfig.MediaCapturePath, settingTips["MediaCapturePath"], out clearFlag))
                { choosePath = "MediaCapturePath"; doClear |= clearFlag; }


                ImGui.EndTable();
            }

            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0099ff);
            if (ImGui.BeginChild("#FileSettsFrame", new Vector2(ImGui.GetContentRegionMax().X - 8, 150), true))
            {
                ImGui.BeginGroup();
                ImGui.AlignTextToFramePadding();
                ImGui.Text("Max Recent Paths"); ImGui.SameLine();
                ImGui.SetNextItemWidth(100);
                ImGui.InputInt("##MaxRecentPaths", ref GlobalConfig.MaxStoredRecentPaths);
                ImGui.EndGroup();
                SmallWidgets.MouseoverText("The number of recently opened samples/traces to store");
                ImGui.EndChildFrame();
            }
            //ImGui.PopStyleColor();

            if (choosePath.Length > 0)
            {
                if (doClear)
                {
                    if (isFolder)
                        GlobalConfig.SetDirectoryPath(choosePath, "");
                    else
                        GlobalConfig.SetBinaryPath(choosePath, "");
                }
                else
                {
                    if (isFolder)
                        LaunchFileSelectBox(choosePath, "##FoldersDLG");
                    else
                        LaunchFileSelectBox(choosePath, "##FilesDLG");
                }
            }


            DrawFolderSelectBox();
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
                case "VideoCodec":
                    GlobalConfig.SetBinaryPath("VideoCodec", path);
                    break;
                case "TestsDirectory":
                    GlobalConfig.SetDirectoryPath("TestsDirectory", path);
                    break;
                case "TraceSaveDirectory":
                    GlobalConfig.SetDirectoryPath("TraceSaveDirectory", path);
                    break;
                case "DiESigsPath":
                    GlobalConfig.SetDirectoryPath("DiESigsPath", path);
                    break;
                case "YaraRulesPath":
                    GlobalConfig.SetDirectoryPath("YaraRulesPath", path);
                    break;
                case "MediaCapturePath":
                    GlobalConfig.SetDirectoryPath("MediaCapturePath", path);
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

        bool _popupActive = true;
        private void DrawFileSelectBox()
        {
            if (ImGui.BeginPopupModal("##FilesDLG", ref _popupActive))
            {
                var picker = rgatFilePicker.FilePicker.GetFilePicker(_filePickHandle, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(_filePickHandle);
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
                        rgatFilePicker.FilePicker.RemoveFilePicker(_filePickHandle);
                    }

                }
                ImGui.EndPopup();
            }

        }

        object _filePickHandle = new object();
        object _dirPickHandle = new object();
        private void DrawFolderSelectBox()
        {
            if (ImGui.BeginPopupModal("##FoldersDLG", ref _popupActive))
            {
                var picker = rgatFilePicker.FilePicker.GetFilePicker(_dirPickHandle, Path.Combine(Environment.CurrentDirectory), onlyAllowFolders: true);
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(_dirPickHandle);
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                    {
                        if (Directory.Exists(picker.SelectedFile))
                        {
                            ChoseSettingPath(_pendingPathSetting, picker.SelectedFile);
                        }
                        else
                        {
                            DeclareError($"Error: Directory {picker.SelectedFile} does not exist");
                        }
                        rgatFilePicker.FilePicker.RemoveFilePicker(_dirPickHandle);
                    }

                }
                ImGui.EndPopup();
            }

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
            if (ImGui.BeginTable("KeybindSelectTable", 3, tableFlags, ImGui.GetContentRegionAvail() - new Vector2(0, 80)))
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
                CreateKeybindInput("Toggle Heatmap", eKeybind.ToggleHeatmap, index++, "Toggle heatmap mode, illustrating how busy different areas of the graph are");
                CreateKeybindInput("Toggle Conditionals", eKeybind.ToggleConditionals, index++, "Toggle conditional instruction mode, showing the status of conditional jumps");
                CreateKeybindInput("Force Direction Temperature +", eKeybind.RaiseForceTemperature, index++, "Increase the temperature of a force directed graph, increasing the rate of layout");
                CreateKeybindInput("Center Graph In View", eKeybind.CenterFrame, index++, "Move the camera so the entire graph centered in the visualiser pane");
                CreateKeybindInput("Lock Graph Centered", eKeybind.LockCenterFrame, index++, "Keep the entire graph centered in the visualiser pane");
                CreateKeybindInput("Toggle All Text", eKeybind.ToggleAllText, index++, "Toggle all text in the graph visualiser (eg: instructions, API calls)");
                CreateKeybindInput("Toggle Instruction Text", eKeybind.ToggleInsText, index++, "Toggle instruction text in the graph visualiser");
                CreateKeybindInput("Toggle Dynamic Text", eKeybind.ToggleLiveText, index++, "Toggle dynamic text in the graph visualiser (eg: API calls)");
                CreateKeybindInput("Graph QuickMenu", eKeybind.QuickMenu, index++, "Toggle the graph visualiser quickmenu");
                CreateKeybindInput("Capture Window", eKeybind.CaptureWindowImage, index++, "Save an image of the window contents to the media directory");
                CreateKeybindInput("Capture Graph", eKeybind.CaptureGraphImage, index++, "Save an image of the visualiser graph to the media directory");
                CreateKeybindInput("Capture Graph & Previews", eKeybind.CaptureGraphPreviewImage, index++, "Save an image of the visualiser graph and preview graphs to the media directory");
                CreateKeybindInput("Toggle Video Capture", eKeybind.ToggleVideo, index++, "Begin recording a new video, or finish recording the current one");
                CreateKeybindInput("Pause Video Capture", eKeybind.PauseVideo, index++, "Stop sending frames to be recorded");
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
            Themes.GetMetadataValue("Name", out string activeThemeName);
            if (Themes.UnsavedTheme)
            {
                ImGui.Text($"Current Theme: {activeThemeName} [Modified - Unsaved]. Save as a preset to keep changes.");
            }
            else
            {
                ImGui.Text($"Current Theme: {activeThemeName}");
            }

            ImGui.SameLine();
            if (ImGui.Button("Save As Preset"))
            {
                saveThemeboxIsOpen = true;
                pendingPresetName = activeThemeName;
                ImGui.OpenPopup("##SavePreset");
                ImGui.SetNextWindowSize(new Vector2(270, 130));
            }
            else
            {
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Store the currently applied theme so it can be reloaded from the above dropdown.");
            }

            DrawSavePresetPopUp();

            if (Themes.DefaultTheme == activeThemeName)
                activeThemeName += " [Default]";

            if (ImGui.BeginCombo("Preset Themes", activeThemeName))
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
                        if (Themes.GetMetadataValue("Description", out string themeDescription)) tipDescription += $"Description: {themeDescription}\r\n";
                        if (Themes.GetMetadataValue("Author", out string auth1)) tipDescription += $"Source: {auth1}";
                        if (Themes.GetMetadataValue("Author2", out string auth2)) tipDescription += $" ({auth2})";

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



        bool doSetThemeDefaultOnSave = true;
        bool saveThemeboxIsOpen = false;
        void DrawSavePresetPopUp()
        {
            if (ImGui.BeginPopupModal("##SavePreset", ref saveThemeboxIsOpen))
            {
                bool validName = !Themes.BuiltinThemes.ContainsKey(pendingPresetName) && !pendingPresetName.Contains('"');

                if (!validName)
                {
                    ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xff333333);
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0xff333333);
                    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0xff333333);
                }
                ImGui.Text("Theme Name");
                if (ImGui.InputText("", ref pendingPresetName, 255, ImGuiInputTextFlags.EnterReturnsTrue) && validName)
                {
                    Themes.SavePresetTheme(pendingPresetName, doSetThemeDefaultOnSave);
                    ImGui.CloseCurrentPopup();
                }
                ImGui.SameLine();
                if (validName && ImGui.Button("Save"))
                {
                    Themes.SavePresetTheme(pendingPresetName, doSetThemeDefaultOnSave);
                    ImGui.CloseCurrentPopup();
                }
                if (!validName)
                {
                    ImGui.Text("Invalid name");
                    ImGui.PopStyleColor(4);
                }
                ImGui.Checkbox("Set As Default", ref doSetThemeDefaultOnSave);
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("This theme will be set as the startup theme");
                }
                ImGui.EndPopup();
            }

        }


        void CreateOptionsPane_VideoEncode()
        {
            _rgatState.VideoRecorder?.DrawSettingsPane();
        }


        void CreateOptionsPane_Miscellaneous()
        {
            bool debglog = GlobalConfig.BulkLogging;
            if (ImGui.Checkbox("Bulk Debug Logging", ref debglog))
            {
                GlobalConfig.BulkLogging = debglog;
                GlobalConfig.AddUpdateAppSettings("BulkLogging", debglog ? "True" : "False");
            }

            float minGraphAlpha = GlobalConfig.MinimumAlpha;
            ImGui.SetNextItemWidth(80);
            if (ImGui.DragFloat("Minimum Animation Alpha", ref minGraphAlpha, 0.01f, 0, 1))
            {
                GlobalConfig.MinimumAlpha = minGraphAlpha;
                GlobalConfig.AddUpdateAppSettings("MinimumGraphAlpha", minGraphAlpha.ToString());
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
            {
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

                Themes.GetMetadataValue("Name", out string activeThemeName);
                if (activeThemeName != Themes.DefaultTheme)
                {
                    ImGui.SameLine();
                    if (ImGui.Button("Set As Default"))
                    {
                        Themes.DefaultTheme = activeThemeName;
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
            }


            ImGui.EndGroup();
        }

        void DeleteCurrentTheme()
        {
            Themes.GetMetadataValue("Name", out string oldTheme);
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
                            {
                                ImGui.Button("Button", new Vector2(120, 25));
                                ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.ButtonHovered));
                                ImGui.Button("Button (Hovered)", new Vector2(120, 25));
                                ImGui.PopStyleColor();
                                ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.ButtonActive));
                                ImGui.Button("Button (Active)", new Vector2(120, 25));
                                ImGui.PopStyleColor();
                                ImGui.EndGroup();
                            }

                            ImGui.SliderFloat("Slider", ref testSlider, 0, 100);
                            ImGui.EndGroup();
                        }

                        ImGui.SameLine();
                        ImGui.BeginGroup();
                        {
                            ImGui.EndGroup();
                        }
                    }
                    ImGui.EndTabItem();
                    
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
            bool changed = Themes.DrawColourSelectors();
            if (changed)
            {
                Themes.UnsavedTheme = true;
                RegenerateUIThemeJSON();
            }
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






        void CreateKeybindInput(string caption, eKeybind keyAction, int rowIndex, string tooltip=null)
        {
            uint bindFramecol = ((rowIndex % 2) == 0) ? 0xafcc3500 : 0xafdc4500;
            ImGui.PushStyleColor(ImGuiCol.FrameBg, bindFramecol);

            ImGui.TableNextRow();
            ImGui.TableNextColumn();

            ImGui.Text(caption);
            if (tooltip != null)
            {
                SmallWidgets.MouseoverText(tooltip);
                ImGui.SameLine();
                ImGui.TextDisabled("(?)");
                SmallWidgets.MouseoverText(tooltip);
            }


            ImGui.TableNextColumn();
            string kstring = "";
            {
                if (GlobalConfig.PrimaryKeybinds.TryGetValue(keyAction, out var kmval))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.Button));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                    if (kmval.Item2 != ModifierKeys.None)
                        kstring += kmval.Item2.ToString() + "+";
                    kstring += kmval.Item1;
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xffbb9999);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xff000000);
                    kstring = $"[Click To Set]##{rowIndex}1";
                }
                if (ImGui.Button($"[{kstring}]"))
                    DoClickToSetKeybind(caption, action: keyAction, 1);
                ImGui.PopStyleColor(2);
            }

            ImGui.TableNextColumn();

            {
                kstring = "";
                if (GlobalConfig.AlternateKeybinds.TryGetValue(keyAction, out var kmval))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.Button));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                    if (kmval.Item2 != ModifierKeys.None)
                        kstring += kmval.Item2.ToString() + "+";
                    kstring += kmval.Item1;
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xffbb9999);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xff000000);
                    kstring = $"[Click To Set]##{rowIndex}2";
                }
                if (ImGui.Button($"[{kstring}]")) 
                    DoClickToSetKeybind(caption, action: keyAction, 2);

                ImGui.PopStyleColor(2);
            }

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
