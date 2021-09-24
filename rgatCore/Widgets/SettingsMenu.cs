using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading;
using Veldrid;
using static rgat.CONSTANTS;

namespace rgat.Widgets
{
    internal class SettingsMenu
    {
        private bool[] optionsSelectStates = new bool[0];
        private List<string> settingsNames = new List<string>();
        private readonly ImGuiController _controller;

        private enum eSettingsCategory { eSignatures, eFiles, eText, eKeybinds, eUITheme, eMisc, eVideoEncode };

        /// <summary>
        /// Init a settings menu
        /// </summary>
        /// <param name="controller">imgui controller</param>
        public SettingsMenu(ImGuiController controller)
        {
            _controller = controller;
            InitSettings();

            settingTips[CONSTANTS.PathKey.PinPath] = "The path to pin.exe - the Intel Pin Dynamic Instrumentation program.";
            settingTips[CONSTANTS.PathKey.PinToolPath32] = "The path to the 32-bit pingat.dll rgat pin tool which is used by pin to instrument target programs";
            settingTips[CONSTANTS.PathKey.PinToolPath64] = "The path to the 64-bit pingat.dll rgat pin tool which is used by pin to instrument target programs";
            settingTips[CONSTANTS.PathKey.FFmpegPath] = "The path to the FFmpeg executable for recording video captures";

            settingTips[CONSTANTS.PathKey.TraceSaveDirectory] = "The directory where trace save files (.rgat) are stored";
            settingTips[CONSTANTS.PathKey.TestsDirectory] = "The directory where rgat development tests are stored. These can be downloaded from [todo]";
            settingTips[CONSTANTS.PathKey.DiESigsDirectory] = "The directory containing Detect It Easy signature scripts for file and memory scanning";
            settingTips[CONSTANTS.PathKey.YaraRulesDirectory] = "The directory containing YARA rules for file and memory scanning";
            settingTips[CONSTANTS.PathKey.MediaCapturePath] = "The directory where videos recordings and images are saved";
        }


        ~SettingsMenu()
        {
            if (_cancelTokens != null && !_cancelTokens.IsCancellationRequested)
            {
                _cancelTokens.Cancel();
            }
        }

        private class PendingKeybind
        {
            public PendingKeybind() { }
            public bool active;
            public string actionText = "";
            public eKeybind action;
            public int bindIndex;
            public string currentKey = "";
            public bool IsResponsive;
        }

        private readonly PendingKeybind _pendingKeybind = new PendingKeybind();
        public bool HasPendingKeybind
        {
            get => _pendingKeybind.active;
            set => _pendingKeybind.active = value;
        }

        public void AssignPendingKeybind(Tuple<Veldrid.Key, Veldrid.ModifierKeys> keybind)
        {
            GlobalConfig.Settings.Keybinds.SetKeybind(_pendingKeybind.action, _pendingKeybind.bindIndex, keybind.Item1, keybind.Item2, true);
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

        private void InitSettings()
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

        private void DeclareError(string msg, long MSDuration = 5500)
        {
            _errorExpiryTime = DateTime.Now.AddMilliseconds(MSDuration);
            _errorBanner = msg;
        }

        private void CreateSettingsContentPane(string settingCategoryName)
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
                    Logging.WriteConsole($"Warning: Bad option category '{settingCategoryName}' selected");
                    break;
            }
        }

        private static List<string> _selectedRepos = new List<string>();

        private void CreateOptionsPane_Signatures()
        {
            if (rgatState.YARALib == null || rgatState.DIELib == null)
            {
                return; //loading
            }

            //available/enabled/loaded signatures pane
            //scanning controls
            //download more btn

            Vector2 tabsize = ImGui.GetContentRegionAvail() - new Vector2(0, 100);
            int tabType = -1;
            if (ImGui.BeginChild("#SignaturesPane", tabsize, false, ImGuiWindowFlags.None))
            {
                ImGui.Text("Available Signatures");

                if (ImGui.BeginTabBar("#SigsAvailableTab", ImGuiTabBarFlags.None))
                {
                    if (ImGui.BeginTabItem("YARA Rules"))
                    {
                        tabType = 1;
                        if (ImGui.BeginChild("YaraSigsList", ImGui.GetContentRegionAvail(), true))
                        {
                            var ruleList = rgatState.YARALib.GetRuleData();

                            ImGuiTableFlags flags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("#SettsYaraRuleList", 3, flags, ImGui.GetContentRegionAvail()))//))
                            {
                                ImGui.TableSetupColumn("Rule", ImGuiTableColumnFlags.WidthFixed, 160);
                                ImGui.TableSetupColumn("Collection", ImGuiTableColumnFlags.WidthFixed, 80);
                                ImGui.TableSetupColumn("Metadata");
                                ImGui.TableSetupScrollFreeze(0, 1);
                                ImGui.TableHeadersRow();

                                ImGui.Indent(5);
                                if (ruleList is not null)
                                {
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
                                            ImGui.TextWrapped($"Tags: {string.Join(", ", rule.Tags)}");
                                        }
                                    }
                                }
                                ImGui.EndTable();
                            }
                            ImGui.EndChild();
                        }
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("DIE Scripts"))
                    {
                        tabType = 1;
                        if (ImGui.BeginChild("DieSigsList", ImGui.GetContentRegionAvail(), true))
                        {
                            var ruleList = rgatState.DIELib.GetSignatures;

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

                    if (ImGui.BeginTabItem("Download Signatures"))
                    {
                        tabType = 2;
                        if (ImGui.BeginChild("DownloadSigs", ImGui.GetContentRegionAvail(), true))
                        {

                            ImGuiTableFlags flags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg;
                            if (ImGui.BeginTable("#SettsDownloadSigRules", 5, flags, ImGui.GetContentRegionAvail() - new Vector2(0, 25)))
                            {

                                ImGui.TableSetupColumn("###SigChk", ImGuiTableColumnFlags.WidthFixed, 26);
                                ImGui.TableSetupColumn("Source");
                                ImGui.TableSetupColumn("# Rules", ImGuiTableColumnFlags.WidthFixed, 60);
                                ImGui.TableSetupColumn("Last Updated", ImGuiTableColumnFlags.WidthFixed, 140);
                                ImGui.TableSetupColumn("Last Downloaded", ImGuiTableColumnFlags.WidthFixed, 140);
                                ImGui.TableSetupScrollFreeze(0, 1);

                                ImGui.TableNextRow(ImGuiTableRowFlags.Headers);

                                GlobalConfig.SignatureSource[] sources = GlobalConfig.Settings.Signatures.GetSignatureSources();
                                bool[] selectedStates = sources.Select(source => _selectedRepos.Contains(source.FetchPath)).ToArray();
                                bool allSigsSelected = !Array.Exists<bool>(selectedStates, x => x == false);

                                for (int column = 0; column < 5; column++)
                                {
                                    ImGui.TableSetColumnIndex(column);
                                    string column_name = ImGui.TableGetColumnName(column); // Retrieve name passed to TableSetupColumn()
                                    ImGui.PushID(column);
                                    if (column == 0)
                                    {
                                        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
                                        if (ImGui.Checkbox("##checkall", ref allSigsSelected))
                                        {
                                            if (allSigsSelected)
                                            {
                                                _selectedRepos = sources.Select(x => x.FetchPath).ToList();
                                            }
                                            else
                                            {
                                                _selectedRepos.Clear();
                                            }

                                            selectedStates = Enumerable.Repeat(allSigsSelected, selectedStates.Length).ToArray();
                                        }
                                        ImGui.PopStyleVar();
                                        ImGui.SameLine(0.0f, ImGui.GetStyle().ItemInnerSpacing.X);
                                    }
                                    ImGui.TableHeader(column_name);
                                    ImGui.PopID();
                                }

                                string activeRepoOperation = _githubSigDownloader.TaskType;
                                List<string> activeRepoTasks = _githubSigDownloader.GetActive();
                                for (var seti = 0; seti < sources.Length; seti++)
                                {
                                    GlobalConfig.SignatureSource sigset = sources[seti];
                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();

                                    bool isSelected = selectedStates[seti];
                                    if (ImGui.Checkbox("##SigChkSrc" + seti, ref isSelected))
                                    {
                                        if (isSelected)
                                        {
                                            _selectedRepos.Add(sigset.FetchPath);
                                        }
                                        else
                                        {
                                            _selectedRepos.RemoveAll(x => x == sigset.FetchPath);
                                        }

                                        selectedStates[seti] = isSelected;
                                    }
                                    ImGui.TableNextColumn();
                                    ImGui.Text($"{sigset.OrgName}/{sigset.RepoName}{(sigset.SubDir.Any() ? ("/" + sigset.SubDir) : "")}");
                                    SmallWidgets.MouseoverText(sigset.FetchPath);
                                    ImGui.TableNextColumn();
                                    ImguiUtils.DrawHorizCenteredText(sigset.RuleCount == -1 ? "-" : sigset.RuleCount.ToString());
                                    ImGui.TableNextColumn();
                                    bool newAvailable = sigset.LastFetch < sigset.LastUpdate;


                                    if (_githubSigDownloader.Running && _githubSigDownloader.TaskType == "Refresh" && activeRepoTasks.Contains(sigset.FetchPath))
                                    {
                                        ImguiUtils.DrawHorizCenteredText("Updating");
                                    }
                                    else
                                    {
                                        string? refreshError = sigset.LastRefreshError is null ? null : new string(sigset.LastRefreshError);

                                        if (refreshError != null)
                                        {
                                            ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff000030);
                                            if (refreshError.Length > 22)
                                            {
                                                ImguiUtils.DrawHorizCenteredText(refreshError.Substring(0, 22) + "..");
                                                SmallWidgets.MouseoverText("Error checking for update: " + refreshError);
                                            }
                                            else
                                            {
                                                ImguiUtils.DrawHorizCenteredText(refreshError);
                                            }
                                        }
                                        else
                                        {
                                            if (newAvailable)
                                            {
                                                ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff004000);
                                            }
                                            ImguiUtils.DrawHorizCenteredText(sigset.LastUpdate == DateTime.MinValue ? "Never Checked" :
                                                Humanizer.TimeSpanHumanizeExtensions.Humanize(DateTime.Now - sigset.LastUpdate) + " ago");
                                            string mouseoverText = "";
                                            if (sigset.LastUpdate == DateTime.MinValue)
                                            {
                                                mouseoverText += "Select this source and press \"Refresh\" to check for signature updates\n";
                                            }
                                            else
                                            {

                                                if (sigset.LastCheck != DateTime.MinValue)
                                                {
                                                    mouseoverText += $"Last checked: {sigset.LastCheck}\n";
                                                }

                                                mouseoverText += $"Last updated: {sigset.LastUpdate}\n";
                                            }

                                            if (newAvailable)
                                            {
                                                mouseoverText += "Updates are available for these signatures";
                                            }

                                            SmallWidgets.MouseoverText(mouseoverText);
                                        }

                                    }


                                    ImGui.TableNextColumn();

                                    string? downloadError = sigset.LastDownloadError == null ? null : new string(sigset.LastDownloadError);
                                    if (downloadError != null)
                                    {
                                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff000030);
                                        if (downloadError.Length > 22)
                                        {
                                            ImguiUtils.DrawHorizCenteredText(downloadError.Substring(0, 22) + "..");
                                            SmallWidgets.MouseoverText("Error downloading signatures: " + downloadError);
                                        }
                                        else
                                        {
                                            ImguiUtils.DrawHorizCenteredText(downloadError);
                                        }
                                    }
                                    else
                                    {
                                        if (_githubSigDownloader.Running &&
                                            _githubSigDownloader.TaskType == "Download" &&
                                            activeRepoTasks.Contains(sigset.FetchPath))
                                        {
                                            ImguiUtils.DrawHorizCenteredText("Downloading");
                                        }
                                        else
                                        {
                                            ImguiUtils.DrawHorizCenteredText(sigset.LastFetch == DateTime.MinValue ? "Never Downloaded" :
                                                Humanizer.TimeSpanHumanizeExtensions.Humanize(DateTime.Now - sigset.LastFetch) + " ago");

                                            if (sigset.LastFetch != DateTime.MinValue)
                                            {
                                                SmallWidgets.MouseoverText($"Last Successful Download: {sigset.LastFetch.ToString()}");
                                            }
                                        }
                                    }

                                }


                                ImGui.EndTable();
                                Vector2 btnSizes = new Vector2(150, 24);
                                if (ImGui.Button("Add Signature Source", btnSizes))
                                {
                                    _repoChangeState = _repoChangeState == eRepoChangeState.Add ? eRepoChangeState.Inactive : eRepoChangeState.Add;
                                }
                                ImGui.SameLine();
                                bool someSelected = _selectedRepos.Any();
                                if (someSelected)
                                {
                                    ImGui.PushStyleColor(ImGuiCol.Button, 0xff000040);
                                }

                                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + ImGui.GetContentRegionAvail().X - btnSizes.X);
                                if (SmallWidgets.DisableableButton("Delete Selected", enabled: someSelected, size: btnSizes))
                                {
                                    _repoChangeState = _repoChangeState == eRepoChangeState.Delete ? eRepoChangeState.Inactive : eRepoChangeState.Delete;
                                }
                                if (someSelected)
                                {
                                    ImGui.PopStyleColor();
                                }
                            }
                            ImGui.EndChild();
                        }
                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }
                ImGui.EndChild();
            }

            if (ImGui.BeginChild("#SignatureOptsPane", ImGui.GetContentRegionAvail(), true, ImGuiWindowFlags.None))
            {
                if (tabType == 1 && ImGui.BeginTable("#ScanConditionsTable", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX))
                {
                    ImGui.TableSetupColumn("Format", ImGuiTableColumnFlags.WidthFixed, 140);
                    ImGui.TableSetupColumn("Scan File On Load", ImGuiTableColumnFlags.WidthFixed, 130);
                    ImGui.TableSetupColumn("Scan Memory", ImGuiTableColumnFlags.WidthFixed, 90);

                    ImGui.TableHeadersRow();
                    uint formatCellColour = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg)).ToUint(0xd0);
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, formatCellColour);
                    uint yaraSigsCount = rgatState.YARALib.LoadedRuleCount();
                    ImGui.Text($"YARA ({yaraSigsCount} rules)");
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##fycheck", ref GlobalConfig.ScanFilesYARA);
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##mycheck", ref GlobalConfig.ScanMemoryYARA);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, formatCellColour);
                    int dieFileSigsCount = rgatState.DIELib.NumScriptsLoaded;
                    ImGui.Text($"DiE ({dieFileSigsCount} scripts)");
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##fdcheck", ref GlobalConfig.ScanFilesDiE);
                    ImGui.TableNextColumn();
                    ImGui.Checkbox($"##mdcheck", ref GlobalConfig.ScanMemoryDiE);

                    ImGui.EndTable();
                }

                if (tabType == 2 && ImGui.BeginTable("#SigDownloadControls", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.NoHostExtendX))
                {
                    ImGui.TableSetupColumn("SigDLBtns", ImGuiTableColumnFlags.WidthFixed, 85);
                    ImGui.TableSetupColumn("SigDLProgressBar", ImGuiTableColumnFlags.WidthFixed, 85);
                    ImGui.TableSetupColumn("SigDLProgressTxt");

                    uint formatCellColour = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiCol.TableHeaderBg)).ToUint(0xd0);

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    float progress = 0;
                    if (_githubSigDownloader.Running)
                    {
                        progress = _githubSigDownloader.CompletedTaskCount / (float)_githubSigDownloader.InitialTaskCount;
                        progress = Math.Max(0, progress);
                    }


                    Vector2 btnSize = new Vector2(80, 25);
                    if (_githubSigDownloader == null || !_githubSigDownloader.Running)
                    {
                        if (SmallWidgets.DisableableButton("Refresh", size: btnSize, enabled: _selectedRepos.Any()))
                        {
                            RefreshSelectedSignatureSources();
                        }

                        SmallWidgets.MouseoverText("Check for new updates to the selected signature repositories");

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        if (SmallWidgets.DisableableButton("Download", size: btnSize, enabled: _selectedRepos.Any()))
                        {
                            DownloadSelectedSignatureSources();
                        }

                        SmallWidgets.MouseoverText("Download signatures from the selected signature repositories");
                        ImGui.TableNextColumn();
                        ImGui.TableNextColumn();
                    }
                    else
                    {
                        if (_githubSigDownloader.TaskType == "Refresh")
                        {
                            if (SmallWidgets.DisableableButton("Cancel", size: btnSize, enabled: true))
                            {
                                _cancelTokens?.Cancel();
                            }

                            SmallWidgets.MouseoverText("Cancel signature refresh");

                            ImGui.TableNextColumn();
                            ImGui.ProgressBar(progress, btnSize);
                            ImGui.TableNextColumn();
                            ImGui.Text($"Refreshing");
                        }
                        else
                        {
                            SmallWidgets.DisableableButton("Refresh", size: btnSize, enabled: false);
                            SmallWidgets.MouseoverText("Signature download is currently in progress");
                        }


                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();

                        if (_githubSigDownloader.TaskType == "Download")
                        {
                            if (SmallWidgets.DisableableButton("Cancel", size: btnSize, enabled: true))
                            {
                                _cancelTokens?.Cancel();
                            }

                            SmallWidgets.MouseoverText("Cancel signature download");

                            ImGui.TableNextColumn();
                            ImGui.ProgressBar(progress, btnSize);
                            ImGui.TableNextColumn();
                            ImGui.Text($"Downloading");
                        }
                        else
                        {
                            SmallWidgets.DisableableButton("Download", size: btnSize, enabled: false);
                            SmallWidgets.MouseoverText("Signature Refresh is currently in progress");
                        }

                    }


                    ImGui.EndTable();
                }

                ImGui.EndChild();
            }

            bool popupOpen = false;
            switch (_repoChangeState)
            {
                case eRepoChangeState.Add:
                    ImGui.OpenPopup("Add Signature Source");
                    popupOpen = true;
                    break;
                case eRepoChangeState.Delete:
                    ImGui.OpenPopup("SigRepoDeleteConfirm");
                    popupOpen = true;
                    break;
                default:
                    break;
            }


            if (ImGui.BeginPopupModal("Add YARA Rule Source", ref popupOpen))
            {
                ImGui.Text("Add a new Github repo containing YARA rules");
                ImGui.Text("This can be any Github repository containing rules in the master branch");
                ImGui.Indent(15);
                ImGui.Text("Specify a repo, eg: https://github.com/Neo23x0/signature-base");
                ImGui.Text("Or a repo directory, eg: https://github.com/h3x2b/yara-rules/tree/master/malware");
                ImGui.Text("You can also add a comma seperated list of sources");
                ImGui.Indent(-15);

                if (ImGui.BeginChild("#RepoAddControls", new Vector2(500, 200), true))
                {
                    if (ImGui.InputTextMultiline("##RepoPathinput", ref currentRepoTextEntry, 1024 * 1024, ImGui.GetContentRegionAvail() - new Vector2(0, 28)))
                    {
                        _validInputRepos.Clear();
                        string joinedTextEntry = currentRepoTextEntry.Replace(" ", "").Replace("\r", "").Replace("\n", "");
                        string[] repoSplit = joinedTextEntry.Split(',');
                        foreach (string currentRepoPath in repoSplit)
                        {
                            bool validRepo = false;
                            string currentOrg = "";
                            string currentRepo = "";
                            string currentDirectory = "";
                            string[] slashSplit = currentRepoPath.ToLower().Split('/');
                            if (slashSplit.Length > 0)
                            {
                                int slashIndex = 0;
                                if (slashSplit[slashIndex] == "http:" || slashSplit[slashIndex] == "https:")
                                {
                                    slashIndex += 1;
                                }

                                while (slashIndex < slashSplit.Length && slashSplit[slashIndex].Length == 0)
                                {
                                    slashIndex += 1;
                                }

                                if (slashIndex < slashSplit.Length && slashSplit[slashIndex] == "github.com")
                                {
                                    slashIndex += 1;
                                }

                                if (slashIndex < slashSplit.Length && slashSplit[slashIndex].Length > 0)
                                {
                                    currentOrg = slashSplit[slashIndex];
                                    slashIndex += 1;
                                }
                                if (slashIndex < slashSplit.Length && slashSplit[slashIndex].Length > 0)
                                {
                                    validRepo = true;
                                    currentRepo = slashSplit[slashIndex];
                                    slashIndex += 1;
                                }
                                if (slashIndex < slashSplit.Length && slashSplit[slashIndex] == "tree")
                                {
                                    validRepo = false;
                                    slashIndex += 1;
                                    if (slashIndex < slashSplit.Length && slashSplit[slashIndex] == "master")
                                    {
                                        slashIndex += 1;
                                        if (slashIndex < slashSplit.Length && slashSplit[slashIndex].Length > 0)
                                        {
                                            validRepo = true;
                                            currentDirectory = string.Join("/", slashSplit.Skip(slashIndex).Take(slashSplit.Length - slashIndex).ToArray());
                                        }
                                    }
                                }
                            }

                            string githubPath = GlobalConfig.SignatureSource.RepoComponentsToPath(currentOrg, currentRepo, currentDirectory);
                            validRepo = validRepo && !GlobalConfig.Settings.Signatures.RepoExists(githubPath);
                            if (validRepo)
                            {
                                GlobalConfig.SignatureSource src = new GlobalConfig.SignatureSource()
                                {
                                    OrgName = currentOrg,
                                    RepoName = currentRepo,
                                    SubDir = currentDirectory,
                                    LastCheck = DateTime.MinValue,
                                    LastUpdate = DateTime.MinValue,
                                    LastFetch = DateTime.MinValue,
                                    SignatureType = eSignatureType.YARA
                                };
                                _validInputRepos.Add(src);
                            }
                        }

                    }

                    if (SmallWidgets.DisableableButton($"Add {_validInputRepos.Count} new valid sources", enabled: _validInputRepos.Count > 0))
                    {
                        AddInputSources(_validInputRepos);
                        _validInputRepos.Clear();
                        popupOpen = false;
                    }
                    if (ImGui.IsItemHovered() && _validInputRepos.Any())
                    {
                        int printCount = Math.Min(_validInputRepos.Count, 10);
                        ImGui.BeginTooltip();
                        for (var i = 0; i < printCount; i++)
                        {
                            ImGui.Text(_validInputRepos[i].FetchPath);
                        }
                        if (printCount < _validInputRepos.Count)
                        {
                            ImGui.Text($"...And {(_validInputRepos.Count - printCount)} more sources");
                        }

                        ImGui.EndTooltip();
                    }
                    ImGui.EndChild();
                }
                ImGui.EndPopup();
            }

            if (ImGui.BeginPopupModal("SigRepoDeleteConfirm", ref popupOpen, flags: ImGuiWindowFlags.AlwaysAutoResize))
            {
                if (ImGui.BeginChild("#RepoDeleteConfirmFrame", new Vector2(350, 105)))
                {
                    ImGui.Text($"Delete {_selectedRepos.Count} signature source{(_selectedRepos.Count == 1 ? "" : "s")}?");
                    ImGui.Checkbox("Also delete downloaded signatures", ref alsoEraseFiles);
                    ImGui.SetCursorPos(ImGui.GetCursorPos() + ImGui.GetContentRegionAvail() - new Vector2(50, 25));
                    if (ImGui.Button("Confirm"))
                    {
                        DeleteSources(_selectedRepos, alsoEraseFiles);
                        _selectedRepos.Clear();
                        popupOpen = false;
                    }
                    ImGui.EndChild();
                }
                ImGui.EndPopup();
            }
            if (!popupOpen)
            {
                ImGui.CloseCurrentPopup();
                _repoChangeState = eRepoChangeState.Inactive;
            }
        }

        private bool alsoEraseFiles = false;
        private string currentRepoTextEntry = "";
        private readonly List<GlobalConfig.SignatureSource> _validInputRepos = new List<GlobalConfig.SignatureSource>();

        private enum eRepoChangeState { Inactive, Delete, Add };

        private eRepoChangeState _repoChangeState = eRepoChangeState.Inactive;

        private static void DeleteSources(List<string> sources, bool eraseFiles)
        {
            foreach (string path in sources)
            {
                GlobalConfig.SignatureSource? source = GlobalConfig.Settings.Signatures.GetSignatureRepo(path);
                if (source == null)
                {
                    continue;
                }

                if (source.SignatureType == eSignatureType.DIE)
                {
                    Logging.RecordError("The DetectItEasy repo cannot be deleted from the UI because there is no way of re-adding it from the UI");
                }
                else
                {
                    GithubSignatureManager.PurgeRepoFiles(source);
                    GlobalConfig.Settings.Signatures.DeleteSignatureSource(path);
                }
            }
        }

        private static void AddInputSources(List<GlobalConfig.SignatureSource> repoPaths)
        {
            for (var i = 0; i < repoPaths.Count; i++)
            {
                GlobalConfig.SignatureSource source = repoPaths[i];
                GlobalConfig.Settings.Signatures.AddSignatureSource(source);
            }
        }

        private CancellationTokenSource? _cancelTokens = null;
        private readonly GithubSignatureManager _githubSigDownloader = new GithubSignatureManager();

        private void RefreshSelectedSignatureSources()
        {
            if (_githubSigDownloader.Running)
            {
                return;
            }

            _cancelTokens = new CancellationTokenSource();
            var allSources = GlobalConfig.Settings.Signatures.GetSignatureSources();
            var repos = allSources.Where(x => _selectedRepos.Contains(x.FetchPath)).ToList();
            _githubSigDownloader.StartRefresh(repos, 3, _cancelTokens.Token);
        }

        private void DownloadSelectedSignatureSources()
        {
            if (_githubSigDownloader.Running)
            {
                return;
            }

            _cancelTokens = new CancellationTokenSource();
            var allSources = GlobalConfig.Settings.Signatures.GetSignatureSources();
            var repos = allSources.Where(x => _selectedRepos.Contains(x.FetchPath)).ToList();
            _githubSigDownloader.StartDownloads(repos, 3, _cancelTokens.Token);
        }

        private void CreateOptionsPane_Text()
        {

            ImGuiIOPtr io = ImGui.GetIO();
            ImFontAtlasPtr atlas = io.Fonts;

            ImGui.ShowFontSelector("fs");

            _controller.PushUnicodeFont();

            int ct = 0;
            string s = "";
            for (var i = 0xe000; i < 0xffff; i += 1)
            {
                if (_controller.GlyphExists((ushort)(i)))
                {
                    ct += 1;
                    s += $"{i:X}:{char.ConvertFromUtf32(i)},";
                }

                if (ct % 16 == 0)
                {
                    ImGui.Text(s);
                    s = "";
                    ct += 1;
                }
            }
            ImGui.PopFont();

            Vector4 tint_col = new Vector4(1.0f, 1.0f, 1.0f, 1.0f);
            Vector4 border_col = new Vector4(1.0f, 1.0f, 1.0f, 0.5f);
            ImGui.Image(atlas.TexID, new Vector2(atlas.TexWidth, atlas.TexHeight), new Vector2(0.0f, 0.0f), new Vector2(1.0f, 1.0f), tint_col, border_col);


        }

        private string _errorBanner = "";
        private DateTime _errorExpiryTime = DateTime.MinValue;
        private CONSTANTS.PathKey _pendingPathSetting;

        private bool DrawPathMenuOption(string caption, string? path, string tooltip, out bool clearFlag)
        {
            bool selected = false;
            bool hovered = false;
            bool hasPath = (path?.Length > 0);
            string? pathTxt = hasPath ? path : "[Not Set]";
            string? signerror = "";
            bool signatureTimeWarning = false;

            if (path is not null)
            {
                GlobalConfig.PreviousSignatureCheckPassed(path, out signerror, out signatureTimeWarning);
            }

            ImGui.TableNextRow();
            ImGui.TableNextColumn();


            ImGui.PushStyleColor(ImGuiCol.Text, 0xeeeeeeee);
            bool notSelected = false;
            ImGui.Text(caption);
            hovered = hovered || ImGui.IsItemHovered();
            ImGui.PopStyleColor();
            ImGui.TableNextColumn();

            bool signatureError = signerror?.Length > 0 && signerror != "No Error";

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

            if (signatureError) { ImGui.PopStyleColor(); }

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
                if (hasPath)
                {
                    ImGui.Text(path);
                }

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

        private readonly Dictionary<CONSTANTS.PathKey, string> settingTips = new Dictionary<CONSTANTS.PathKey, string>();

        private void CreateOptionsPane_Files()
        {
            CONSTANTS.PathKey? choosePath = null;
            bool isFolder = false;
            bool doClear = false;

            if (ImGui.BeginTable("#PathsTable", 3, ImGuiTableFlags.RowBg))//, ImGuiTableFlags.PreciseWidths, ImGui.GetContentRegionAvail()))
            {
                ImGui.TableSetupColumn("Setting", ImGuiTableColumnFlags.WidthFixed, 180);
                ImGui.TableSetupColumn("Path");
                ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 35);

                ImGui.TableHeadersRow();


                if (DrawPathMenuOption("Pin Executable", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinPath), settingTips[CONSTANTS.PathKey.PinPath], out bool clearFlag))
                { choosePath = CONSTANTS.PathKey.PinPath; doClear |= clearFlag; }

                if (DrawPathMenuOption("Pintool32 Library", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath32), settingTips[CONSTANTS.PathKey.PinToolPath32], out clearFlag))
                { choosePath = CONSTANTS.PathKey.PinToolPath32; doClear |= clearFlag; }

                if (DrawPathMenuOption("Pintool64 Library", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath64), settingTips[CONSTANTS.PathKey.PinToolPath64], out clearFlag))
                { choosePath = CONSTANTS.PathKey.PinToolPath64; doClear |= clearFlag; }

                if (DrawPathMenuOption("FFmpeg Executable", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.FFmpegPath), settingTips[CONSTANTS.PathKey.FFmpegPath], out clearFlag))
                { choosePath = CONSTANTS.PathKey.FFmpegPath; doClear |= clearFlag; }

                if (choosePath == null)
                {
                    isFolder = true;
                }

                if (DrawPathMenuOption("Saved Traces", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TraceSaveDirectory), settingTips[CONSTANTS.PathKey.TraceSaveDirectory], out clearFlag))
                { choosePath = CONSTANTS.PathKey.TraceSaveDirectory; doClear |= clearFlag; }

                if (DrawPathMenuOption("Tests", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TestsDirectory), settingTips[CONSTANTS.PathKey.TestsDirectory], out clearFlag))
                { choosePath = CONSTANTS.PathKey.TestsDirectory; doClear |= clearFlag; }

                if (DrawPathMenuOption("DiE Signatures", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory), settingTips[CONSTANTS.PathKey.DiESigsDirectory], out clearFlag))
                { choosePath = CONSTANTS.PathKey.DiESigsDirectory; doClear |= clearFlag; }

                if (DrawPathMenuOption("Yara Rules", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory), settingTips[CONSTANTS.PathKey.YaraRulesDirectory], out clearFlag))
                { choosePath = CONSTANTS.PathKey.YaraRulesDirectory; doClear |= clearFlag; }

                if (DrawPathMenuOption("Images/Videos", GlobalConfig.GetSettingPath(CONSTANTS.PathKey.MediaCapturePath), settingTips[CONSTANTS.PathKey.MediaCapturePath], out clearFlag))
                { choosePath = CONSTANTS.PathKey.MediaCapturePath; doClear |= clearFlag; }


                ImGui.EndTable();
            }

            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0099ff);
            if (ImGui.BeginChild("#FileSettsFrame", new Vector2(ImGui.GetContentRegionMax().X - 8, 150), true))
            {
                ImGui.BeginGroup();
                ImGui.AlignTextToFramePadding();
                ImGui.Text("Max Recent Paths"); ImGui.SameLine();
                ImGui.SetNextItemWidth(100);
                int pathsLimit = GlobalConfig.Settings.UI.MaxStoredRecentPaths;
                if (ImGui.InputInt("##MaxRecentPaths", ref pathsLimit))
                {
                    GlobalConfig.Settings.UI.MaxStoredRecentPaths = pathsLimit;
                }
                ImGui.EndGroup();
                SmallWidgets.MouseoverText("The number of recently opened samples/traces to store");
                ImGui.EndChildFrame();
            }
            //ImGui.PopStyleColor();

            if (choosePath.HasValue)
            {
                if (doClear)
                {
                    if (isFolder)
                    {
                        GlobalConfig.SetDirectoryPath(choosePath.Value, "");
                    }
                    else
                    {
                        GlobalConfig.SetBinaryPath(choosePath.Value, "");
                    }
                }
                else
                {
                    if (isFolder)
                    {
                        LaunchFileSelectBox(choosePath.Value, "##FoldersDLG");
                    }
                    else
                    {
                        LaunchFileSelectBox(choosePath.Value, "##FilesDLG");
                    }
                }
            }


            ImGui.SetNextWindowSize(new Vector2(600, 600), ImGuiCond.FirstUseEver);
            DrawFolderSelectBox();
            ImGui.SetNextWindowSize(new Vector2(600, 600), ImGuiCond.FirstUseEver);
            DrawFileSelectBox();
        }

        private static void ChoseSettingPath(CONSTANTS.PathKey setting, string path)
        {
            switch (setting)
            {
                case CONSTANTS.PathKey.PinPath:
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.PinPath, path);
                    break;
                case CONSTANTS.PathKey.PinToolPath32:
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.PinToolPath32, path);
                    break;
                case CONSTANTS.PathKey.PinToolPath64:
                    GlobalConfig.SetBinaryPath(CONSTANTS.PathKey.PinToolPath64, path);
                    break;
                case CONSTANTS.PathKey.TestsDirectory:
                    GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.TestsDirectory, path);
                    break;
                case CONSTANTS.PathKey.TraceSaveDirectory:
                    GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.TraceSaveDirectory, path);
                    break;
                case CONSTANTS.PathKey.DiESigsDirectory:
                    GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.DiESigsDirectory, path);
                    break;
                case CONSTANTS.PathKey.YaraRulesDirectory:
                    GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.YaraRulesDirectory, path);
                    break;
                case CONSTANTS.PathKey.MediaCapturePath:
                    GlobalConfig.SetDirectoryPath(CONSTANTS.PathKey.MediaCapturePath, path);
                    break;
                default:
                    Logging.RecordLogEvent("Bad path setting " + setting, Logging.LogFilterType.TextAlert);
                    break;
            }
        }

        private void LaunchFileSelectBox(CONSTANTS.PathKey setting, string popupID)
        {
            ImGui.SetNextWindowSize(new Vector2(800, 820), ImGuiCond.Appearing);
            ImGui.OpenPopup(popupID);
            _pendingPathSetting = setting;
        }

        private bool _popupActive = true;
        private void DrawFileSelectBox()
        {
            if (ImGui.BeginPopupModal("##FilesDLG", ref _popupActive))
            {
                var picker = rgatFilePicker.FilePicker.GetFilePicker(_filePickHandle, Path.Combine(Environment.CurrentDirectory));
                rgatFilePicker.FilePicker.PickerResult result = picker.Draw(_filePickHandle);

                if (result == rgatFilePicker.FilePicker.PickerResult.eTrue)
                {
                    if (picker.SelectedFile is not null && File.Exists(picker.SelectedFile))
                    {
                        ChoseSettingPath(_pendingPathSetting, picker.SelectedFile);
                    }
                    else
                    {
                        DeclareError($"Error: Path {picker.SelectedFile} does not exist");
                    }
                }
                if (result != rgatFilePicker.FilePicker.PickerResult.eNoAction)
                {
                    rgatFilePicker.FilePicker.RemoveFilePicker(_filePickHandle);
                }

                ImGui.EndPopup();
            }

        }

        private readonly object _filePickHandle = new object();
        private readonly object _dirPickHandle = new object();
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
                        if (picker.SelectedFile is not null && Directory.Exists(picker.SelectedFile))
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

        private void CreateOptionsPane_Keybinds()
        {
            if (_pendingKeybind.active)
            {
                ImGui.OpenPopup("Activate New Keybind");
            }

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
                GlobalConfig.Settings.Keybinds.ResetKeybinds();
            }


        }

        private void ApplyUIJSON()
        {
            Logging.WriteConsole("Apply UI JSON");
        }

        private string _theme_UI_JSON = "fffffffffff";
        private string _theme_UI_JSON_Text = "fffffffffff";
        private bool _UI_JSON_edited = false;
        private bool _expanded_theme_json = false;
        private string pendingPresetName = "";

        private unsafe void CreateOptionsPane_UITheme()
        {
            Themes.GetMetadataValue("Name", out string? activeThemeName);
            if (Themes.UnsavedTheme)
            {
                ImGui.Text($"Current Theme: {activeThemeName} [Modified - Unsaved]. Save as a preset to keep changes.");
            }
            else
            {
                ImGui.Text($"Current Theme: {activeThemeName}");
            }

            ImGui.SameLine();
            if (ImGui.Button("Save As Preset") && activeThemeName is not null)
            {
                saveThemeboxIsOpen = true;
                pendingPresetName = activeThemeName;
                ImGui.OpenPopup("##SavePreset");
                ImGui.SetNextWindowSize(new Vector2(270, 130));
            }
            else
            {
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("Store the currently applied theme so it can be reloaded from the above dropdown.");
                }
            }

            DrawSavePresetPopUp();

            string defaultTheme = GlobalConfig.Settings.Themes.DefaultTheme;
            if (defaultTheme == activeThemeName)
            {
                activeThemeName += " [Default]";
            }

            if (ImGui.BeginCombo("Preset Themes", activeThemeName))
            {
                foreach (string themeName in Themes.ThemesMetadataCatalogue.Keys)
                {
                    string themeLabel = themeName;
                    if (defaultTheme == themeName)
                    {
                        themeLabel += "  [Default]";
                    }

                    if (ImGui.Selectable(themeName, true))
                    {
                        ActivateUIThemePreset(themeName);
                    }

                    if (ImGui.IsItemHovered())
                    {
                        string tipDescription = $"Name: {themeName}\r\n";
                        if (Themes.GetMetadataValue("Description", out string? themeDescription))
                        {
                            tipDescription += $"Description: {themeDescription}\r\n";
                        }

                        if (Themes.GetMetadataValue("Author", out string? auth1))
                        {
                            tipDescription += $"Source: {auth1}";
                        }

                        if (Themes.GetMetadataValue("Author2", out string? auth2))
                        {
                            tipDescription += $" ({auth2})";
                        }

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

        private bool doSetThemeDefaultOnSave = true;
        private bool saveThemeboxIsOpen = false;

        private void DrawSavePresetPopUp()
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


        private static void CreateOptionsPane_VideoEncode()
        {
            rgatState.VideoRecorder?.DrawSettingsPane();
        }

        private static void CreateOptionsPane_Miscellaneous()
        {
            bool debglog = GlobalConfig.Settings.Logs.BulkLogging;
            if (ImGui.Checkbox("Bulk Debug Logging", ref debglog))
            {
                GlobalConfig.Settings.Logs.BulkLogging = debglog;
            }

            float minGraphAlpha = GlobalConfig.AnimatedFadeMinimumAlpha;
            ImGui.SetNextItemWidth(80);
            if (ImGui.DragFloat("Graph Minimum Animation Alpha", ref minGraphAlpha, 0.01f, 0, 1))
            {
                GlobalConfig.AnimatedFadeMinimumAlpha = minGraphAlpha;
            }

            bool screencapAnim = GlobalConfig.Settings.UI.ScreencapAnimation;
            if (ImGui.Checkbox("Enable Screen Capture Animation", ref screencapAnim))
            {
                GlobalConfig.Settings.UI.ScreencapAnimation = screencapAnim;
            }
            SmallWidgets.MouseoverText("Display an animated rectangle to give feedback for screen captures");

            bool alertAnim = GlobalConfig.Settings.UI.AlertAnimation;
            if (ImGui.Checkbox("Enable Alert Animation", ref alertAnim))
            {
                GlobalConfig.Settings.UI.AlertAnimation = alertAnim;
            }
            SmallWidgets.MouseoverText("Display a shrinking circle to draw the eye to new alert messages");

            bool updateCheckEnable = GlobalConfig.Settings.Updates.DoUpdateCheck;
            if (ImGui.Checkbox("Check for new releases", ref updateCheckEnable))
            {
                GlobalConfig.Settings.Updates.DoUpdateCheck = alertAnim;
            }
            SmallWidgets.MouseoverText("Check for new rgat releases");

            int previewWorkers = GlobalConfig.Settings.UI.PreviewWorkers;
            ImGui.SetNextItemWidth(60);
            if (ImGui.InputInt("Preview Workers", ref previewWorkers, 1, 1))
            {
                if (previewWorkers > 0 && previewWorkers < 32)
                    GlobalConfig.Settings.UI.PreviewWorkers = previewWorkers;
            }
            SmallWidgets.MouseoverText("How many preview workers to run. Increasing this makes rendering many previews snappier, but too may cause contention issues.");

        }

        private void CreateJSONEditor()
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
                    if (_UI_JSON_edited)
                    {
                        ApplyNewThemeJSONToUI();
                    }
                }
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("Apply the theme from the JSON editor to the UI. Any settings not specified will be unchanged.");
                }

                ImGui.SameLine();
                if (ImGui.Button("Cancel"))
                {
                    RegenerateUIThemeJSON();
                }
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("Restore export text from the currently applied theme. The changes will be lost.");
                }

                if (disableRestore) { ImGui.PopStyleColor(3); }


                ImGui.SameLine();
                if (ImGui.Button("Copy"))
                {
                    ImGui.LogToClipboard();
                    int blockSize = 255; //LogText won't copy more than this at once
                    for (var written = 0; written < _theme_UI_JSON_Text.Length; written += blockSize)
                    {
                        if (written < _theme_UI_JSON_Text.Length)
                        {
                            ImGui.LogText(_theme_UI_JSON_Text.Substring(written, Math.Min(blockSize, _theme_UI_JSON_Text.Length - written)));
                        }
                    }

                    ImGui.LogFinish();
                }
                ImGui.SameLine();
                string expandBtnText = _expanded_theme_json ? "Collapse" : "Expand";
                string expandBtnTip = _expanded_theme_json ? "Collapse the JSON editor" : "Expand the JSON editor";
                if (ImGui.Button(expandBtnText))
                {
                    _expanded_theme_json = !_expanded_theme_json;
                }
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip(expandBtnTip);
                }

                Themes.GetMetadataValue("Name", out string? activeThemeName);
                if (activeThemeName is not null &&
                    activeThemeName != GlobalConfig.Settings.Themes.DefaultTheme)
                {
                    ImGui.SameLine();
                    if (ImGui.Button("Set As Default"))
                    {
                        GlobalConfig.Settings.Themes.DefaultTheme = activeThemeName;
                    }
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Cause this theme to be activated when rgat is launched");
                    }
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


        private static void DeleteCurrentTheme()
        {
            Themes.GetMetadataValue("Name", out string? oldTheme);
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

            if (oldTheme is not null)
            {
                Themes.DeleteTheme(oldTheme);
            }
        }


        private void CreateThemeTester()
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

        private bool testCheck = true;
        private float testSlider = 25f;


        private void DrawThemeTestFrame()
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


        private unsafe void CreateThemeSelectors()
        {
            bool changed = Themes.DrawColourSelectors();
            if (changed)
            {
                Themes.UnsavedTheme = true;
                RegenerateUIThemeJSON();
            }
        }


        private void RegenerateUIThemeJSON()
        {
            _theme_UI_JSON = Themes.RegenerateUIThemeJSON();
            _theme_UI_JSON_Text = _theme_UI_JSON;
            _UI_JSON_edited = false;
        }


        private void ApplyNewThemeJSONToUI()
        {
            // read this into json
            //_theme_UI_JSON_Text

            //apply it to the config lists/arrays
            if (!Themes.ActivateThemeObject(_theme_UI_JSON_Text, out string? error))
            {
                Logging.WriteConsole("Failed to load json");
                return;
            }

            RegenerateUIThemeJSON();

            _UI_JSON_edited = (_theme_UI_JSON != _theme_UI_JSON_Text);
        }


        private static void ActivateUIThemePreset(string name) => Themes.LoadTheme(name);


        private void CreateKeybindInput(string caption, eKeybind keyAction, int rowIndex, string? tooltip = null)
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
                if (GlobalConfig.Settings.Keybinds.PrimaryKeybinds.TryGetValue(keyAction, out var kmval))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.Button));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                    if (kmval.Item2 != ModifierKeys.None)
                    {
                        kstring += kmval.Item2.ToString() + "+";
                    }

                    kstring += kmval.Item1;
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xffbb9999);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xff000000);
                    kstring = $"[Click To Set]##{rowIndex}1";
                }
                if (ImGui.Button($"[{kstring}]"))
                {
                    DoClickToSetKeybind(caption, action: keyAction, 1);
                }

                ImGui.PopStyleColor(2);
            }

            ImGui.TableNextColumn();

            {
                kstring = "";
                if (GlobalConfig.Settings.Keybinds.AlternateKeybinds.TryGetValue(keyAction, out var kmval))
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.Button));
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                    if (kmval.Item2 != ModifierKeys.None)
                    {
                        kstring += kmval.Item2.ToString() + "+";
                    }

                    kstring += kmval.Item1;
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xffbb9999);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xff000000);
                    kstring = $"[Click To Set]##{rowIndex}2";
                }
                if (ImGui.Button($"[{kstring}]"))
                {
                    DoClickToSetKeybind(caption, action: keyAction, 2);
                }

                ImGui.PopStyleColor(2);
            }

            ImGui.PopStyleColor();
        }


        private void DoClickToSetKeybind(string caption, eKeybind action, int bindIndex)
        {
            _pendingKeybind.active = true;
            _pendingKeybind.actionText = caption;
            _pendingKeybind.bindIndex = bindIndex;
            _pendingKeybind.action = action;

            _pendingKeybind.IsResponsive = GlobalConfig.ResponsiveHeldActions.Contains(action);

            _pendingKeybind.currentKey = "";
            if (GlobalConfig.Settings.Keybinds.PrimaryKeybinds.TryGetValue(action, out var kmval))
            {
                if (kmval.Item2 != ModifierKeys.None)
                {
                    _pendingKeybind.currentKey += kmval.Item2.ToString() + "+";
                }

                _pendingKeybind.currentKey += kmval.Item1;
            }

        }

    }
}
