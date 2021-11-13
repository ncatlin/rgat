using ImGuiNET;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;

namespace rgat
{
    internal partial class rgatUI
    {
        private void DrawStartSplash()
        {

            var recenttraces = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Trace, false);
            var recentbins = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.PathType.Binary);
            DrawSplash(recentbins, recenttraces);

        }


        private void DrawSplash(rgatSettings.PathRecord[] recentBins, rgatSettings.PathRecord[] recentTraces)
        {

            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, Vector2.Zero);

            float regionHeight = ImGui.GetContentRegionAvail().Y;
            float regionWidth = ImGui.GetContentRegionAvail().X;
            float buttonBlockWidth = Math.Min(400f, regionWidth / 2.1f);
            float headerHeight = ImGui.GetWindowSize().Y / 3;
            float blockHeight = (regionHeight * 0.95f) - headerHeight;
            float blockStart = headerHeight + 40f;

            ImFontPtr titleFont = Controller.rgatLargeFont ?? Controller._originalFont!.Value;
            ImGui.PushFont(titleFont);
            Vector2 titleSize = ImGui.CalcTextSize("rgat");
            ImGui.SetCursorScreenPos(new Vector2((ImGui.GetWindowContentRegionMax().X / 2) - (titleSize.X / 2), (ImGui.GetWindowContentRegionMax().Y / 5) - (titleSize.Y / 2)));
            ImGui.Text("rgat");
            ImGui.PopFont();


            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0000ff);
            //ImGui.PushStyleColor(ImGuiCol.ChildBg, new WritableRgbaFloat(0, 0, 0, 255).ToUint());

            bool boxBorders = false;

            //ImGui.PushStyleColor(ImGuiCol.HeaderHovered, 0x45ffffff);

            _splashHeaderHover = ImGui.GetMousePos().Y < (ImGui.GetWindowSize().Y / 3f);
            //ImGui.PopStyleColor();

            //Run group
            float voidspace = Math.Max(0, (regionWidth - (2 * buttonBlockWidth)) / 3);
            float runGrpX = voidspace;
            float iconTableYSep = 18;
            float iconTitleYSep = 10;

            ImGuiTableFlags tblflags = ImGuiTableFlags.NoHostExtendX;
            if (boxBorders)
            {
                tblflags |= ImGuiTableFlags.Borders;
            }

            ImGui.SetCursorPos(new Vector2(runGrpX, blockStart));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowBackground));
            if (ImGui.BeginChild("##RunGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                ImGui.PushFont(Controller.SplashLargeFont ?? Controller._originalFont!.Value);
                float captionHeight = ImGui.CalcTextSize("Load Binary").Y;
                if (ImGui.BeginTable("##LoadBinBtnBox", 3, tblflags))
                {
                    Vector2 LargeIconSize = Controller.LargeIconSize;
                    float iconColumnWidth = 200;
                    float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                    ImGui.TableSetupColumn("##BBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                    ImGui.TableSetupColumn("##LoadBinBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                    ImGui.TableSetupColumn("##BBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(1);

                    Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + LargeIconSize.Y + iconTitleYSep + 12);

                    if (ImGui.Selectable("##Load Binary", false, ImGuiSelectableFlags.None, selectableSize))
                    {
                        ToggleLoadExeWindow();
                    }
                    Controller.PushUnicodeFont();
                    Widgets.SmallWidgets.MouseoverText("Load an executable or DLL for examination. It will not be executed at this stage.");
                    ImGui.PopFont();
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                    ImGuiUtils.DrawHorizCenteredText("Load Binary");
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (LargeIconSize.X / 2));
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTitleYSep);

                    Controller.PushBigIconFont();
                    ImGui.Text($"{ImGuiController.FA_ICON_SAMPLE}"); //If you change this be sure to update ImGuiController.BuildFonts
                    ImGui.PopFont();

                    ImGui.EndTable();
                }
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);
                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                if (ImGui.BeginTable("#RecentBinTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                {
                    ImGui.Indent(5);
                    ImGui.TableSetupColumn("Recent Binaries" + $"{(rgatState.ConnectedToRemote ? " (Remote Files)" : "")}");
                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableHeadersRow();
                    if (recentBins?.Length > 0)
                    {
                        int bincount = Math.Min(GlobalConfig.Settings.UI.MaxStoredRecentPaths, recentBins.Length);
                        for (var bini = 0; bini < bincount; bini++)
                        {
                            var entry = recentBins[bini];
                            ImGui.TableNextRow();
                            if (ImGui.TableNextColumn())
                            {
                                if (DrawRecentPathEntry(entry, false))
                                {
                                    if (File.Exists(entry.Path))
                                    {
                                        if (!LoadSelectedBinary(entry.Path, rgatState.ConnectedToRemote) && !_badPaths.Contains(entry.Path))
                                        {
                                            _badPaths.Add(entry.Path);
                                        }
                                    }
                                    else if (!_missingPaths.Contains(entry.Path) && rgatState.ConnectedToRemote is false)
                                    {
                                        _scheduleMissingPathCheck = true;
                                        _missingPaths.Add(entry.Path);
                                    }
                                }
                            }
                        }
                    }
                    ImGui.EndTable();
                }
                ImGui.PopStyleVar();

                ImGui.EndChild();
            }

            ImGui.SetCursorPosY(blockStart);
            ImGui.SetCursorPosX(runGrpX + buttonBlockWidth + voidspace);
            if (ImGui.BeginChild("##LoadGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                ImGui.PushFont(Controller.SplashLargeFont ?? Controller._originalFont!.Value);
                float captionHeight = ImGui.CalcTextSize("Load Trace").Y;
                if (ImGui.BeginTable("##LoadBtnBox", 3, tblflags))
                {
                    Vector2 LargeIconSize = Controller.LargeIconSize;
                    float iconColumnWidth = 200;
                    float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                    ImGui.TableSetupColumn("##LBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                    ImGui.TableSetupColumn("##LoadBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                    ImGui.TableSetupColumn("##LBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(1);
                    Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + LargeIconSize.Y + iconTitleYSep + 12);
                    if (ImGui.Selectable("##Load Trace", false, ImGuiSelectableFlags.None, selectableSize))
                    {
                        ToggleLoadTraceWindow();
                    }
                    Controller.PushUnicodeFont();
                    Widgets.SmallWidgets.MouseoverText("Load a previously generated trace");
                    ImGui.PopFont();
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                    ImGuiUtils.DrawHorizCenteredText("Load Trace");
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (LargeIconSize.X / 2) + 8); //shift a bit to the right to balance it 
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTitleYSep);

                    Controller.PushBigIconFont();
                    ImGui.Text($"{ImGuiController.FA_ICON_LOADFILE}");//If you change this be sure to update ImGuiController.BuildFonts
                    ImGui.PopFont();

                    ImGui.EndTable();
                }
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);

                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);


                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                if (ImGui.BeginTable("#RecentTraceTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                {
                    ImGui.Indent(5);
                    ImGui.TableSetupColumn("Recent Traces");
                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableHeadersRow();
                    if (recentTraces?.Length > 0)
                    {
                        int traceCount = Math.Min(GlobalConfig.Settings.UI.MaxStoredRecentPaths, recentTraces.Length);
                        for (var traceI = 0; traceI < traceCount; traceI++)
                        {
                            var entry = recentTraces[traceI];
                            ImGui.TableNextRow();
                            if (ImGui.TableNextColumn())
                            {
                                if (DrawRecentPathEntry(entry, false))
                                {
                                    if (File.Exists(entry.Path))
                                    {
                                        System.Threading.Tasks.Task.Run(() => LoadTraceByPath(entry.Path));
                                        /*
                                        if (!LoadTraceByPath(entry.Path) && !_badPaths.Contains(entry.Path))
                                        {
                                            _badPaths.Add(entry.Path);
                                        }*/
                                    }
                                    else if (!_missingPaths.Contains(entry.Path))
                                    {
                                        _scheduleMissingPathCheck = true;
                                        _missingPaths.Add(entry.Path);
                                    }
                                }
                            }
                        }
                    }
                    ImGui.EndTable();
                }
                ImGui.PopStyleVar();

                ImGui.EndChild();
            }

            ImGui.PopStyleVar(5);

            ImGui.BeginGroup();
            string versionString = $"rgat {CONSTANTS.PROGRAMVERSION.RGAT_VERSION}";
            float width = ImGui.CalcTextSize(versionString).X;
            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(width + 25, 40));
            ImGui.Text(versionString);


            if (GlobalConfig.NewVersionAvailable)
            {
                Version currentVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
                Version newVersion = GlobalConfig.Settings.Updates.UpdateLastCheckVersion;
                string updateString;
                if (newVersion.Major > currentVersion.Major ||
                    (newVersion.Major == currentVersion.Major && newVersion.Minor > currentVersion.Minor))
                {
                    updateString = "New version available ";
                }
                else
                {
                    updateString = "Updates available ";
                }
                updateString += $"({newVersion})";

                Vector2 textSize = ImGui.CalcTextSize(updateString);
                ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(textSize.X + 25, 55));

                if (ImGui.Selectable(updateString, false, flags: ImGuiSelectableFlags.None, size: new Vector2(textSize.X, textSize.Y)))
                {
                    ImGui.OpenPopup("New Version Available");
                }
                if (ImGui.IsItemHovered())
                {
                    Updates.ChangesCounts(out int changes, out int versions);
                    if (changes > 0)
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text($"Click to see {changes} changes in {versions} newer rgat versions");
                        ImGui.EndTooltip();
                    }
                }
            }
            ImGui.EndGroup();

            ImGui.PopStyleColor();
            if (GlobalConfig.Settings.UI.EnableTortoise)
            {
                _splashRenderer?.Draw();
            }

            if (StartupProgress < 1)
            {
                float originalY = ImGui.GetCursorPosY();
                float ypos = ImGui.GetWindowSize().Y - 12;
                ImGui.SetCursorPosY(ypos);
                ImGui.ProgressBar((float)StartupProgress, new Vector2(-1, 4f));
                ImGui.SetCursorPosY(originalY);
            }

            if (ImGui.IsPopupOpen("New Version Available"))
            {
                ImGui.SetNextWindowSize(new Vector2(600, 500), ImGuiCond.FirstUseEver);
                ImGui.SetNextWindowPos((ImGui.GetWindowSize() / 2) - new Vector2(600f / 2f, 500f / 2f), ImGuiCond.Appearing);
                bool isopen = true;
                if (ImGui.BeginPopupModal("New Version Available", ref isopen, flags: ImGuiWindowFlags.Modal))
                {
                    Updates.DrawChangesDialog();
                    isopen = isopen && !ImGui.IsKeyDown(ImGui.GetKeyIndex(ImGuiKey.Escape));
                    if (!isopen) { ImGui.CloseCurrentPopup(); }
                    ImGui.EndPopup();
                }
            }
        }

        private readonly List<string> _missingPaths = new List<string>();
        private readonly List<string> _badPaths = new List<string>();
    }
}
