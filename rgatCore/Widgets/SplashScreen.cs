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


        void DrawSplash(List<GlobalConfig.CachedPathData> recentBins, List<GlobalConfig.CachedPathData> recentTraces)
        {
            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, Vector2.Zero);
            ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, Vector2.Zero);

            float regionHeight = ImGui.GetContentRegionAvail().Y;
            float regionWidth = ImGui.GetContentRegionAvail().X;
            float buttonBlockWidth = Math.Min(400f, regionWidth / 2.1f);
            float headerHeight = regionHeight / 3;
            float blockHeight = (regionHeight * 0.95f) - headerHeight;
            float blockStart = headerHeight + 40f;

            if (StartupProgress < 1)
            {
                float ypos = ImGui.GetCursorPosY();
                ImGui.ProgressBar((float)StartupProgress, new Vector2(-1, 4f));
                ImGui.SetCursorPosY(ypos);
            }

            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff0000ff);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new WritableRgbaFloat(0, 0, 0, 255).ToUint());

            bool boxBorders = false;

            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, 0x45ffffff);
            if (ImGui.BeginChild("header", new Vector2(ImGui.GetContentRegionAvail().X, headerHeight), boxBorders))
            {
                Texture settingsIcon = _controller.GetImage("Menu");
                GraphicsDevice gd = _controller.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(gd.ResourceFactory, settingsIcon, "SettingsIcon");

                int groupSep = 100;

                ImGui.BeginGroup();
                {
                    float headerBtnsY = 65;
                    float btnSize = 50;
                    ImGui.BeginGroup();
                    {
                        float btnX = (regionWidth / 2) - (btnSize + groupSep / 2);
                        ImGui.SetCursorPos(new Vector2(btnX, headerBtnsY));
                        ImGui.Image(CPUframeBufferTextureId, new Vector2(btnSize, btnSize), Vector2.Zero, Vector2.One, Vector4.One);

                        ImGui.SetCursorPos(new Vector2(btnX - 35, headerBtnsY - 35));

                        if (ImGui.Selectable("##SettingsDlg", false, ImGuiSelectableFlags.None, new Vector2(120, 120)))
                        {
                            if (_SettingsMenu != null)
                            {
                                _settings_window_shown = true;
                            }
                        }
                        if (ImGui.IsItemHovered(ImGuiHoveredFlags.None))
                        {
                            ImGui.SetTooltip("Open Settings Menu");
                        }
                        if (_splashHeaderHover)
                        {
                            ImGui.PushFont(_controller.SplashButtonFont);
                            Vector2 textsz = ImGui.CalcTextSize("Settings");
                            ImGui.SetCursorPosX(btnX - (textsz.X + 35));
                            ImGui.SetCursorPosY(headerBtnsY + btnSize / 2 - textsz.Y / 2);
                            ImGui.Text("Settings");
                            ImGui.PopFont();
                        }
                        ImGui.EndGroup();
                    }
                    ImGui.BeginGroup();
                    {
                        float btnX = (regionWidth / 2) + groupSep / 2;
                        ImGui.SetCursorPos(new Vector2(btnX, headerBtnsY));
                        ImGui.Image(CPUframeBufferTextureId, new Vector2(btnSize, btnSize), Vector2.Zero, Vector2.One, Vector4.One);

                        ImGui.SetCursorPos(new Vector2(btnX - 35, headerBtnsY - 35));
                        if (ImGui.Selectable("##NetworkDlg", false, ImGuiSelectableFlags.None, new Vector2(120, 120)))
                        {
                            ToggleRemoteDialog();
                        }
                        if (ImGui.IsItemHovered(ImGuiHoveredFlags.None))
                        {
                            ImGui.SetTooltip("Setup Remote Tracing");
                        }
                        if (_splashHeaderHover)
                        {
                            ImGui.PushFont(_controller.SplashButtonFont);
                            Vector2 textsz = ImGui.CalcTextSize("Settings");
                            ImGui.SetCursorPosX(btnX + btnSize + 35);
                            ImGui.SetCursorPosY(headerBtnsY + btnSize / 2 - textsz.Y / 2);
                            ImGui.TextWrapped("Remote Tracing");
                            ImGui.PopFont();
                        }

                        ImGui.EndGroup();
                    }

                    ImGui.EndGroup();
                }
                ImGui.EndChild();
            }
            _splashHeaderHover = ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenBlockedByActiveItem | ImGuiHoveredFlags.AllowWhenBlockedByPopup);
            ImGui.PopStyleColor();

            //Run group
            float voidspace = Math.Max(0, (regionWidth - (2 * buttonBlockWidth)) / 3);
            float runGrpX = voidspace;
            float iconTableYSep = 18;

            ImGuiTableFlags tblflags = ImGuiTableFlags.NoHostExtendX;
            if (boxBorders) tblflags |= ImGuiTableFlags.Borders;

            ImGui.SetCursorPos(new Vector2(runGrpX, blockStart));
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0);
            if (ImGui.BeginChild("##RunGroup", new Vector2(buttonBlockWidth, blockHeight), boxBorders))
            {
                Texture btnIcon = _controller.GetImage("Crosshair");
                GraphicsDevice gd = _controller.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(gd.ResourceFactory, btnIcon, "CrossHairIcon");

                ImGui.PushFont(_controller.SplashButtonFont);
                float captionHeight = ImGui.CalcTextSize("Load Binary").Y;
                Vector2 iconsize = new Vector2(80, 80);
                ImGui.BeginTable("##LoadBinBtnBox", 3, tblflags);
                float iconColumnWidth = 200;
                float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                ImGui.TableSetupColumn("##BBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableSetupColumn("##LoadBinBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                ImGui.TableSetupColumn("##BBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(1);
                Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + iconsize.Y);
                if (ImGui.Selectable("##Load Binary", false, ImGuiSelectableFlags.None, selectableSize))
                {
                    _show_select_exe_window = true;
                }
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                ImguiUtils.DrawHorizCenteredText("Load Binary");
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (iconsize.X / 2));
                ImGui.Image(CPUframeBufferTextureId, iconsize, Vector2.Zero, Vector2.One, Vector4.One);
                ImGui.EndTable();
                ImGui.PopFont();
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);
                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                if (recentBins?.Count > 0)
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 2));
                    if (ImGui.BeginTable("#RecentBinTableList", 1, ImGuiTableFlags.ScrollY, tableSz))
                    {
                        ImGui.Indent(5);
                        ImGui.TableSetupColumn("Recent Binaries" + $"{(rgatState.ConnectedToRemote ? " (Remote Files)" : "")}");
                        ImGui.TableSetupScrollFreeze(0, 1);
                        ImGui.TableHeadersRow();
                        int bincount = recentBins.Count;
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
                Texture btnIcon = _controller.GetImage("Crosshair");
                GraphicsDevice gd = _controller.graphicsDevice;
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(gd.ResourceFactory, btnIcon, "LoadGrpIcon");

                ImGui.PushFont(_controller.SplashButtonFont);
                float captionHeight = ImGui.CalcTextSize("Load Trace").Y;
                Vector2 iconsize = new Vector2(80, 80);
                ImGui.BeginTable("##LoadBtnBox", 3, tblflags);
                float iconColumnWidth = 200;
                float paddingX = (buttonBlockWidth - iconColumnWidth) / 2;
                ImGui.TableSetupColumn("##LBSPadL", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableSetupColumn("##LoadBtnIcn", ImGuiTableColumnFlags.WidthFixed, iconColumnWidth);
                ImGui.TableSetupColumn("##LBSPadR", ImGuiTableColumnFlags.WidthFixed, paddingX);
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(1);
                Vector2 selectableSize = new Vector2(iconColumnWidth, captionHeight + iconsize.Y);
                if (ImGui.Selectable("##Load Trace", false, ImGuiSelectableFlags.None, selectableSize))
                {
                    _show_load_trace_window = true;
                }
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - ImGui.GetItemRectSize().Y);
                ImguiUtils.DrawHorizCenteredText("Load Trace");
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (iconColumnWidth / 2) - (iconsize.X / 2));
                ImGui.Image(CPUframeBufferTextureId, iconsize, Vector2.Zero, Vector2.One, Vector4.One);
                ImGui.EndTable();
                ImGui.PopFont();

                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + iconTableYSep);

                Vector2 tableSz = new Vector2(buttonBlockWidth, ImGui.GetContentRegionAvail().Y - 25);

                if (recentTraces?.Count > 0)
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


            ImGui.SetCursorPos(ImGui.GetContentRegionMax() - new Vector2(100, 40));
            if (ImGui.BeginChild("##SplashCorner", new Vector2(80, 35)))
            {



                if (ImGui.Selectable("rgat v0.6.0"))
                {
                    ToggleTestHarness();
                }

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
            //String msg = "No target binary is selected\nOpen a binary or saved trace from the target menu фä洁ф";
            //ImguiUtils.DrawRegionCenteredText(msg);
        }


        List<string> _missingPaths = new List<string>();
        List<string> _badPaths = new List<string>();
    }
}
