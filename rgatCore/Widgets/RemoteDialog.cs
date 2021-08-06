using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace rgat.Widgets
{
    class RemoteDialog
    {
        public bool ListenMode = false;
        public bool Active = false;
        public bool Connected = false;

        public RemoteDialog()
        {
            if (GlobalConfig.StartOptions.NetworkKey == null || GlobalConfig.StartOptions.NetworkKey.Length == 0)
            {
                if (GlobalConfig.DefaultNetworkKey != null && GlobalConfig.DefaultNetworkKey.Length > 0)
                {
                    GlobalConfig.StartOptions.NetworkKey = GlobalConfig.DefaultNetworkKey;
                }
                else
                {
                    RegenerateKey();
                }
            }

            if (GlobalConfig.StartOptions.ConnectModeAddress == null || GlobalConfig.StartOptions.ConnectModeAddress.Length == 0)
            {
                if (GlobalConfig.DefaultHeadlessAddress != null && GlobalConfig.DefaultHeadlessAddress.Length > 0)
                {
                    GlobalConfig.StartOptions.ConnectModeAddress = GlobalConfig.DefaultHeadlessAddress;
                    ListenMode = false;
                }
            }
            else
            {
                ListenMode = false;
            }

            if (GlobalConfig.StartOptions.ListenPort == -1)
            {
                if (GlobalConfig.DefaultListenPort != -1)
                {
                    GlobalConfig.StartOptions.ListenPort = GlobalConfig.DefaultListenPort;
                    ListenMode = true;
                }
            }
            else
            {
                ListenMode = true;
            }


        }

        void RegenerateKey()
        {
            Regex matchSimilar = new Regex(@"[\.1IO0]");
            string newkey = "";
            while (newkey.Length != NETWORK_CONSTANTS.DefaultKeyLength) //avoid hard to distinguish characters
            {
                newkey = System.IO.Path.GetRandomFileName().ToUpper();
                newkey = matchSimilar.Replace(newkey, "");
                if (newkey.Length < NETWORK_CONSTANTS.DefaultKeyLength) continue;
                newkey = newkey.Substring(0, NETWORK_CONSTANTS.DefaultKeyLength);
                break;
            }
            GlobalConfig.DefaultNetworkKey = newkey;
            GlobalConfig.StartOptions.NetworkKey = newkey;
            GlobalConfig.AddUpdateAppSettings("DefaultNetworkKey", newkey);
        }

        public void Draw(ref bool window_shown_flag)
        {
            ImGui.SetNextWindowSize(new Vector2(330, 400), ImGuiCond.Appearing);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.NoResize;

            string title = "Remote Tracing Connection Settings";
            float itemsw = 300;


            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(15, 15));
            ImGui.Begin(title + "###Settings", ref window_shown_flag, window_flags);
            {
                if (ImGui.BeginChild("#ConStatFrame1", new Vector2(ImGui.GetContentRegionAvail().X, 35)))
                {
                    if (Active)
                    {
                        if (Connected)
                        {
                            ImguiUtils.DrawHorizCenteredText($"Connected");
                        }
                        else
                        {
                            if (ListenMode)
                            {
                                ImguiUtils.DrawHorizCenteredText($"Listening for connections");
                            }
                            else
                            {
                                ImguiUtils.DrawHorizCenteredText($"Attempting to connect");
                            }
                        }
                    }
                    else
                    {
                        ImguiUtils.DrawHorizCenteredText($"Remote Tracing Disabled");
                    }
                    ImGui.EndChild();
                }

                Vector2 togStart = ImGui.GetCursorScreenPos();
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X/2) - ( ImGui.CalcTextSize("Listen Mode").X + 24));
                {
                    if (ListenMode)
                        ImGui.Text("Listen Mode");
                    else
                        ImGui.TextDisabled("Listen Mode");
                }
                ImGui.SameLine();
                if (SmallWidgets.ToggleButton("NwkListenModeTog", !ListenMode, "Toggle remote tracing mode"))
                {
                    ListenMode = !ListenMode;
                }
                ImGui.SameLine();
                {
                    if (!ListenMode)
                        ImGui.Text("Connect Mode");
                    else
                        ImGui.TextDisabled("Connect Mode");
                }
                if (ImGui.IsMouseHoveringRect(togStart, new Vector2(ImGui.GetCursorScreenPos().X + ImGui.GetContentRegionAvail().X - 10, ImGui.GetCursorScreenPos().Y)))
                {
                    ImGui.BeginTooltip();
                    ImGui.Text("rgat supports two methods of connecting rgat instances to support different network environments");
                    string listenTip = "Listen Mode: The GUI instance of rgat will listen for connections from the headless instance";
                    string connectTip = "Connect Mode: The GUI instance of rgat will connect to the headless instance.";
                    if (ListenMode)
                    {
                        ImGui.Text(listenTip);
                        ImGui.TextDisabled(connectTip);
                    }
                    else
                    {
                        ImGui.TextDisabled(listenTip);
                        ImGui.Text(connectTip);
                    }
                    ImGui.EndTooltip();

                }

                if (ImGui.BeginChildFrame(ImGui.GetID("NetworkContent"), new Vector2(itemsw, 180)))
                {
                    if (ImGui.BeginTable("#LoptsTab", 2))
                    {
                        ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 90);
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("Network Key");
                        ImGui.TableNextColumn();
                        string keystring = GlobalConfig.StartOptions.NetworkKey;
                        if (ImGui.InputText("##nwkKeytxt", ref keystring, 64))
                        {
                            GlobalConfig.StartOptions.NetworkKey = keystring;
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.BeginTooltip();
                            ImGui.Text("Remote tracing is intended for use between a Host/Guest VM or machines on a LAN.");
                            ImGui.Text("While traffic is encrypted and connections attempts are heavily rate-limited, exposing this port to the internet is discouraged.");
                            ImGui.Text("This key should be the value passed to the headless rgat instance on the other machine with the 'key' or -k option.");
                            ImGui.EndTooltip();
                        }
                        ImGui.SameLine();
                        if (ImGui.Button("O##rkeybtn"))
                        {
                            RegenerateKey();
                        }
                        SmallWidgets.MouseoverText("Generate new key");

                        if (ListenMode)
                        {
                            DrawListenOptsFrame();
                        }
                        else
                        {
                            DrawConnectOptsFrame();
                        }
                        ImGui.EndTable();
                    }
                    ImGui.EndChildFrame();
                }


                if (ImGui.BeginChild("##RemoteStatFrame", new Vector2(itemsw, 80)))
                {
                    
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X / 2) - (ImGui.CalcTextSize("Active").X + 39));
                    {
                        if (!Active)
                            ImGui.Text("Disabled");
                        else
                            ImGui.TextDisabled("Disabled");
                    }
                    ImGui.SameLine();
                    if (SmallWidgets.ToggleButton("NwkListenActive", Active, "Toggle remote tracing mode"))
                    {
                        Active = !Active;
                    }
                    ImGui.SameLine();
                    {
                        if (Active)
                            ImGui.Text("Active");
                        else
                            ImGui.TextDisabled("Active");
                    }


                    ImGui.EndChildFrame();
                }

                ImGui.End();
            }
            ImGui.PopStyleVar();
        }

        int listenPort = -1;

        void DrawListenOptsFrame()
        {
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.Text("Local Port");
            ImGui.TableNextColumn();
            string portstr = GlobalConfig.StartOptions.ListenPort.ToString();
            if(ImGui.InputText("##InPort1", ref portstr, 6))
            {
                if(int.TryParse(portstr, out int outport))
                {
                    GlobalConfig.StartOptions.ListenPort = outport;
                    GlobalConfig.DefaultListenPort = outport;
                    GlobalConfig.AddUpdateAppSettings("DefaultListenPort", portstr);
                }
            }
            ImGui.SameLine();
            if (ImGui.Button("O##rportbtn"))
            {
                //todo
            }
            SmallWidgets.MouseoverText("Select random available port");

            ImGui.TableNextRow();
            ImGui.Text("Interface");
            ImGui.TableNextColumn();
            ImGui.Text("IfSelectorhere");

        }


        void DrawConnectOptsFrame()
        { 
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.Text("Remote Address");
            ImGui.TableNextColumn(); 
            string addr = GlobalConfig.StartOptions.ConnectModeAddress ?? "";
            if (ImGui.InputText("##nwkConAddr", ref addr, 512))
            {
                GlobalConfig.StartOptions.ConnectModeAddress = addr;
                GlobalConfig.DefaultHeadlessAddress = addr;
                GlobalConfig.AddUpdateAppSettings("DefaultHeadlessAddress", addr);
            }
            if (ImGui.IsItemHovered())
            {
                ImGui.BeginTooltip();
                ImGui.Text("This should be the [interface address]:[port] of a computer with rgat running in listen mode (-p)");
                ImGui.Text("Eg:");
                ImGui.Indent();
                ImGui.Text("192.168.0.141:6381");
                ImGui.Text("analysis-server-3:7525");
                ImGui.Text("ignored://infectedhost:11951");
                ImGui.EndTooltip();
            }

            ImGui.TableNextRow();
            ImGui.Text("Interface");
            ImGui.TableNextColumn();
            ImGui.Text("IfSelectorhere2");

        }
    }
}

