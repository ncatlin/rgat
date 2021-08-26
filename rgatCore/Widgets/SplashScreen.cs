using ImGuiNET;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgat
{
    partial class rgatUI
    {

        void DrawStartSplash()
        {
            if (rgatState.NetworkBridge != null && rgatState.ConnectedToRemote)
            {
                DrawSplash(RemoteDataMirror.GetRecentBins(), GlobalConfig.RecentTraces);
            }
            else
            {
                DrawSplash(GlobalConfig.RecentBinaries, GlobalConfig.RecentTraces);
            }
        }


        void DrawSplash(GlobalConfig.CachedPathData[] recentBins, GlobalConfig.CachedPathData[] recentTraces)
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

            //ImGui.PushFont(_controller.f)
            ImGui.PushFont(_controller.rgatLargeFont);
            Vector2 titleSize = ImGui.CalcTextSize("rgat");
            ImGui.SetCursorScreenPos(new Vector2((ImGui.GetWindowContentRegionMax().X / 2) - (titleSize.X/2), (ImGui.GetWindowContentRegionMax().Y / 5) - (titleSize.Y/2)));
            ImGui.Text("rgat");
            ImGui.PopFont();


            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0000ff);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new WritableRgbaFloat(0, 0, 0, 255).ToUint());

            bool boxBorders = false;

            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, 0x45ffffff);

            _splashHeaderHover = ImGui.GetMousePos().Y < (ImGui.GetWindowSize().Y / 3f);
            ImGui.PopStyleColor();

            //Run group
            float voidspace = Math.Max(0, (regionWidth - (2 * buttonBlockWidth)) / 3);
            float runGrpX = voidspace;
            float iconTableYSep = 18;
            float iconTitleYSep = 10;

            ImGuiTableFlags tblflags = ImGuiTableFlags.NoHostExtendX;
            if (boxBorders) tblflags |= ImGuiTableFlags.Borders;

            ImGui.SetCursorPos(new Vector2(runGrpX, blockStart));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0);
            if (ImGui.BeginChild("##RunGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                ImGui.PushFont(_controller.SplashLargeFont);
                float captionHeight = ImGui.CalcTextSize("Load Binary").Y;
                if (ImGui.BeginTable("##LoadBinBtnBox", 3, tblflags))
                {
                    Vector2 LargeIconSize = _controller.LargeIconSize;
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
                        _show_select_exe_window = true;
                    }
                    _controller.PushUnicodeFont();
                    Widgets.SmallWidgets.MouseoverText("Load an executable or DLL for examination. It will not be executed at this stage.");
                    ImGui.PopFont();
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                    ImguiUtils.DrawHorizCenteredText("Load Binary");
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (LargeIconSize.X / 2));
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTitleYSep);

                    _controller.PushBigIconFont();
                    ImGui.Text($"{ImGuiController.FA_ICON_SAMPLE}");
                    ImGui.PopFont();

                    ImGui.EndTable();
                }
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);
                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                if (recentBins?.Length > 0)
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                    if (ImGui.BeginTable("#RecentBinTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                    {
                        ImGui.Indent(5);
                        ImGui.TableSetupColumn("Recent Binaries" + $"{(rgatState.ConnectedToRemote ? " (Remote Files)" : "")}");
                        ImGui.TableSetupScrollFreeze(0, 1);
                        ImGui.TableHeadersRow();
                        int bincount = recentBins.Length;
                        for (var bini = 0; bini < bincount; bini++)
                        {
                            var entry = recentBins[bini];
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            if (DrawRecentPathEntry(entry, false))
                            {
                                if (File.Exists(entry.path))
                                {
                                    if (!LoadSelectedBinary(entry.path, rgatState.ConnectedToRemote) && !_badPaths.Contains(entry.path))
                                    {
                                        _badPaths.Add(entry.path);
                                    }
                                }
                                else if (!_missingPaths.Contains(entry.path))
                                {
                                    _scheduleMissingPathCheck = true;
                                    _missingPaths.Add(entry.path);
                                }
                            }
                        }
                        ImGui.EndTable();
                    }
                    ImGui.PopStyleVar();
                }
                else
                {
                    if (GlobalConfig.LoadProgress < 1)
                    {
                        ImGui.ProgressBar((float)GlobalConfig.LoadProgress, new Vector2(300, 3));
                    }
                }
                ImGui.EndChild();
            }

            ImGui.SetCursorPosY(blockStart);
            ImGui.SetCursorPosX(runGrpX + buttonBlockWidth + voidspace);
            if (ImGui.BeginChild("##LoadGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                ImGui.PushFont(_controller.SplashLargeFont);
                float captionHeight = ImGui.CalcTextSize("Load Trace").Y;
                if (ImGui.BeginTable("##LoadBtnBox", 3, tblflags))
                {
                    Vector2 LargeIconSize = _controller.LargeIconSize;
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
                        _show_load_trace_window = true;
                    }
                    _controller.PushUnicodeFont();
                    Widgets.SmallWidgets.MouseoverText("Load a previously generated trace");
                    ImGui.PopFont();
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                    ImguiUtils.DrawHorizCenteredText("Load Trace");
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (LargeIconSize.X / 2) + 8); //shift a bit to the right to balance it 
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTitleYSep); 

                    _controller.PushBigIconFont();
                    ImGui.Text($"{ImGuiController.FA_ICON_LOADFILE}");
                    ImGui.PopFont();

                    ImGui.EndTable();
                }
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);

                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                if (recentTraces?.Length > 0)
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                    if (ImGui.BeginTable("#RecentTraceTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                    {
                        ImGui.Indent(5);
                        ImGui.TableSetupColumn("Recent Traces");
                        ImGui.TableSetupScrollFreeze(0, 1);
                        ImGui.TableHeadersRow();

                        foreach (var entry in recentTraces)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableNextColumn();
                            if (DrawRecentPathEntry(entry, false))
                            {
                                if (File.Exists(entry.path))
                                {
                                    if (!LoadTraceByPath(entry.path) && !_badPaths.Contains(entry.path))
                                    {
                                        _badPaths.Add(entry.path);
                                    }
                                }
                                else if (!_missingPaths.Contains(entry.path))
                                {
                                    _scheduleMissingPathCheck = true;
                                    _missingPaths.Add(entry.path);
                                }
                            }
                        }
                        ImGui.EndTable();
                    }
                    ImGui.PopStyleVar();
                }
                else
                {
                    if (GlobalConfig.LoadProgress < 1)
                    {
                        ImGui.ProgressBar((float)GlobalConfig.LoadProgress, new Vector2(300, 3));
                    }
                }
                ImGui.EndChild();
            }

            ImGui.PopStyleVar(5);


            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(100, 50));
            if (ImGui.BeginChild("##SplashCorner", new Vector2(80, 35)))
            {



                if (ImGui.Selectable("rgat v0.6.0"))
                {
                    ToggleTestHarness();
                }

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();

            if (StartupProgress < 1)
            {
                float ypos = ImGui.GetWindowSize().Y - 12;
                ImGui.SetCursorPosY(ypos);
                ImGui.ProgressBar((float)StartupProgress, new Vector2(-1, 4f));
            }
            //String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁ф";
            //ImguiUtils.DrawRegionCenteredText(msg);
        }


        List<string> _missingPaths = new List<string>();
        List<string> _badPaths = new List<string>();
    }
}
