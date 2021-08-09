using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace rgat.Widgets
{
    class RemoteDialog
    {
        public bool ListenMode = false;
        List<NetworkInterface> _netIFList = new List<NetworkInterface>();
        string _listenIFID = "";
        string _connectIFID = "";
        string activeInterfaceID;
        System.Timers.Timer _refreshTimer = new System.Timers.Timer(NETWORK_CONSTANTS.InterfaceRefreshIntervalMS);
        bool _refreshTimerFired = false;
        int listenPort = -1;
        OperationModes.BridgedRunner runner;
        rgatState _rgatState;

        public RemoteDialog(rgatState state)
        {
            _rgatState = state;
            InitSettings();
            if (_rgatState.NetworkBridge == null)
            {
                _rgatState.NetworkBridge = new BridgeConnection(isgui: true);
            }
            runner = new OperationModes.BridgedRunner(state);

            _refreshTimer.Elapsed += FireTimer;
            _refreshTimer.AutoReset = true;
            _refreshTimerFired = true;


        }

        void InitSettings()
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

            if (GlobalConfig.StartOptions.ListenPort == null || GlobalConfig.StartOptions.ListenPort == -1)
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

            if (GlobalConfig.StartOptions.Interface == null || GlobalConfig.StartOptions.Interface.Length == 0)
            {
                if (GlobalConfig.DefaultListenModeIF != null && GlobalConfig.DefaultListenModeIF.Length > 0)
                {
                    _listenIFID = GlobalConfig.DefaultListenModeIF;
                }
                if (GlobalConfig.DefaultConnectModeIF != null && GlobalConfig.DefaultConnectModeIF.Length > 0)
                {
                    _connectIFID = GlobalConfig.DefaultConnectModeIF;
                }
            }
            else
            {
                if (GlobalConfig.DefaultListenModeIF == null || GlobalConfig.DefaultListenModeIF.Length == 0)
                {
                    GlobalConfig.DefaultListenModeIF = GlobalConfig.StartOptions.Interface;
                    GlobalConfig.AddUpdateAppSettings("DefaultListenModeIF", GlobalConfig.DefaultListenModeIF);
                    _listenIFID = GlobalConfig.DefaultListenModeIF;
                }
                if (GlobalConfig.DefaultConnectModeIF == null || GlobalConfig.DefaultConnectModeIF.Length == 0)
                {
                    GlobalConfig.DefaultConnectModeIF = GlobalConfig.StartOptions.Interface;
                    GlobalConfig.AddUpdateAppSettings("DefaultConnectModeIF", GlobalConfig.DefaultConnectModeIF);
                    _connectIFID = GlobalConfig.DefaultConnectModeIF;
                }
            }

        }

        public void Close()
        {
            _refreshTimer.Stop();
        }

        private void FireTimer(object sender, System.Timers.ElapsedEventArgs e)
        {
            _refreshTimerFired = true;
        }

        void RefreshInterfaces()
        {
            var latestInterfaces = RemoteTracing.GetInterfaces();
            //remove interfaces that are no longer around
            _netIFList.RemoveAll(existingIF => !latestInterfaces.Any(latestIF => latestIF.Id == existingIF.Id));
            //add newly usable interfaces
            var newInterfaces = latestInterfaces.Where(newIF => !_netIFList.Any(existingIF => existingIF.Id == newIF.Id));
            _netIFList.AddRange(newInterfaces);
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
            if (window_shown_flag && !_refreshTimer.Enabled)
            {
                _refreshTimerFired = true;
                _refreshTimer.Start();
            }
            float itemsWidth = 350;
            ImGui.SetNextWindowSize(new Vector2(itemsWidth + 30, 410), ImGuiCond.Appearing);

            ImGuiWindowFlags window_flags = ImGuiWindowFlags.NoResize;

            string title = "Remote Tracing Setup";

            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(5, 5));
            ImGui.Begin(title + "###Settings", ref window_shown_flag, window_flags);
            {

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 10);
                if (ImGui.BeginChild("#RemoteFrameMain", new Vector2(itemsWidth, 375)))
                {
                    DrawStatusBanner();
                    DrawActivationToggle(itemsWidth);
                    DrawOptionsFrame(itemsWidth);
                    DrawModeToggle();
                    DrawMessagesList(itemsWidth);

                    ImGui.EndChild();
                }
                ImGui.End();
            }
            ImGui.PopStyleVar();
        }


        void DrawStatusBanner()
        {
            if (ImGui.BeginChild("#ConStatFrame1", new Vector2(ImGui.GetContentRegionAvail().X, 35)))
            {
                if (_rgatState.NetworkBridge.ActiveNetworking)
                {
                    IPEndPoint endpoint = _rgatState.NetworkBridge.RemoteEndPoint;
                    if (_rgatState.NetworkBridge.Connected)
                    {
                        ImguiUtils.DrawRegionCenteredText($"Connected to {endpoint}");
                    }
                    else
                    {
                        if (ListenMode)
                        {
                            ImguiUtils.DrawRegionCenteredText($"Listening for connections");
                        }
                        else
                        {
                            ImguiUtils.DrawRegionCenteredText($"Attempting to connect to {GlobalConfig.StartOptions.ConnectModeAddress}");
                        }
                    }
                }
                else
                {
                    ImguiUtils.DrawRegionCenteredText($"Remote Tracing Inactive");
                }
                ImGui.EndChild();
            }
        }


        void DrawActivationToggle(float itemsWidth)
        {
            Vector2 togStart = ImGui.GetCursorScreenPos();
            if (ImGui.BeginChild("##RemoteActiveTogFrame", new Vector2(itemsWidth, 30), true, flags: ImGuiWindowFlags.NoScrollbar))
            {
                bool activeNetworking = _rgatState.NetworkBridge.ActiveNetworking;
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X / 2) - (ImGui.CalcTextSize("Active").X + 39));
                {
                    if (!activeNetworking)
                    {
                        ImGui.Text("Disabled");
                    }
                    else
                    {
                        if (_rgatState.NetworkBridge.Connected)
                            ImGui.TextDisabled("Disconnect");
                        else
                            ImGui.TextDisabled("Disable");
                    }
                }
                ImGui.SameLine();
                if (SmallWidgets.ToggleButton("NwkListenActive", activeNetworking, null))
                {
                    if (activeNetworking)
                    {
                        _rgatState.NetworkBridge.Teardown();
                    }
                    else
                    {
                        if (ListenMode)
                        {
                            GlobalConfig.StartOptions.Interface = _listenIFID;
                            System.Threading.Tasks.Task.Run(() => runner.StartGUIListen(_rgatState.NetworkBridge, () => { _rgatState.NetworkBridge.SendCommand("RefreshCaches"); }));
                        }
                        else
                        {
                            GlobalConfig.StartOptions.Interface = _connectIFID;
                            System.Threading.Tasks.Task.Run(() => runner.StartGUIConnect(_rgatState.NetworkBridge, () => { _rgatState.NetworkBridge.SendCommand("RefreshCaches"); }));
                        }
                    }
                }
                ImGui.SameLine();
                {
                    if (activeNetworking)
                    {
                        if (_rgatState.NetworkBridge.Connected)
                        {
                            ImGui.Text("Connected");
                        }
                        else if (ListenMode)
                        {
                            ImGui.Text("Listening");
                        }
                        else
                        {
                            ImGui.Text("Connecting");
                        }
                    }
                    else
                    {
                        if (ListenMode)
                        {
                            ImGui.TextDisabled("Start Listening");
                        }
                        else
                        {
                            ImGui.TextDisabled("Connect");
                        }
                    }
                }
                ImGui.EndChildFrame();
            }

            if (ImGui.IsMouseHoveringRect(togStart, new Vector2(ImGui.GetCursorScreenPos().X + ImGui.GetContentRegionAvail().X - 10, ImGui.GetCursorScreenPos().Y)))
            {
                ImGui.BeginTooltip();
                const string ListenActive = "Listening for connections from a commandline rgat instance on the specified interface+port";
                const string ListenActiveConnected = "A commandline rgat instance is connected to the specified interface+port";
                const string ListenInactive = "Start listening for connections from a commandline rgat instance on the specified interface+port";
                const string ListenInactivate = "Stop listening for connections";
                const string ListenInactivateConnected = "Disconnect from the remote rgat instance and stop listening for connections";
                const string ConnectInactivateConnected = "Disconnect from the remote rgat instance";
                const string ConnectInactivate = "Disable connection attempts";
                const string ConnectInactive = "Establish a connection to a commandline rgat instance with the specified settings";
                const string ConnectActive = "Trying to connect to the specified commandline rgat instance";
                const string ConnectActiveConnected = "Connected to the specified commandline rgat instance";
                const string Inactive = "Remote tracing disabled";

                if (!_rgatState.NetworkBridge.ActiveNetworking)
                {
                    ImGui.Text(Inactive);
                    if (ListenMode)
                        ImGui.TextDisabled(ListenInactive);
                    else
                        ImGui.TextDisabled(ConnectInactive);
                }
                else
                {
                    //what happens when we toggle to disabled
                    if (ListenMode)
                    {
                        if (_rgatState.NetworkBridge.Connected)
                            ImGui.TextDisabled(ListenInactivateConnected);
                        else
                            ImGui.TextDisabled(ListenInactivate);
                    }
                    else
                    {
                        if (_rgatState.NetworkBridge.Connected)
                            ImGui.TextDisabled(ConnectInactivateConnected);
                        else
                            ImGui.TextDisabled(ConnectInactivate);
                    }

                    //current enabled state
                    if (ListenMode)
                    {
                        if (_rgatState.NetworkBridge.Connected)
                            ImGui.Text(ListenActiveConnected);
                        else
                            ImGui.Text(ListenActive);
                    }
                    else
                    {
                        if (_rgatState.NetworkBridge.Connected)
                            ImGui.Text(ConnectActiveConnected);
                        else
                            ImGui.Text(ConnectActive);
                    }
                }

                ImGui.EndTooltip();
            }
        }

        void DrawOptionsFrame(float itemsWidth)
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("NetworkContent"), new Vector2(itemsWidth, 180), flags: ImGuiWindowFlags.NoScrollbar))
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
        }

        void DrawListenOptsFrame()
        {
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.Text("Local Port");
            ImGui.TableNextColumn();
            string portstr = GlobalConfig.StartOptions.ListenPort.ToString();
            if (ImGui.InputText("##InPort1", ref portstr, 6))
            {
                if (int.TryParse(portstr, out int outport))
                {
                    GlobalConfig.StartOptions.ListenPort = outport;
                    GlobalConfig.DefaultListenPort = outport;
                    GlobalConfig.AddUpdateAppSettings("DefaultListenPort", portstr);
                }
            }
            SmallWidgets.MouseoverText("The TCP port to listen on, or 0 to choose a random port");

            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.Text("Interface");
            ImGui.TableNextColumn();
            DrawInterfaceSelector();

        }

        void DrawInterfaceSelector()
        {
            if (_refreshTimerFired)
            {
                RefreshInterfaces();
                _refreshTimerFired = false;
            }


            if (ImGui.BeginTable("#IFListtable", 1, ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
            {
                int i = 0;
                foreach (var iface in _netIFList)
                {
                    i++;
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    bool selected = (ListenMode && iface.Id == _listenIFID) || (!ListenMode && iface.Id == _connectIFID);
                    if (ImGui.Selectable(iface.Name + "##" + iface.Id + i.ToString(), selected))
                    {
                        if (selected)
                        {
                            GlobalConfig.StartOptions.Interface = "0.0.0.0";
                            if (ListenMode)
                            {
                                _listenIFID = "";
                                GlobalConfig.AddUpdateAppSettings("DefaultListenModeIF", _listenIFID);
                                GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(_listenIFID);
                            }
                            else
                            {

                                _connectIFID = "";
                                GlobalConfig.AddUpdateAppSettings("DefaultConnectModeIF", _connectIFID);
                                GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(_connectIFID);
                            }
                        }
                        else
                        {
                            if (ListenMode)
                            {
                                _listenIFID = iface.Id;
                                GlobalConfig.AddUpdateAppSettings("DefaultListenModeIF", _listenIFID);
                                GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(_listenIFID);
                            }
                            else
                            {
                                _connectIFID = iface.Id;
                                GlobalConfig.AddUpdateAppSettings("DefaultConnectModeIF", _connectIFID);
                                GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(_connectIFID);
                            }
                        }
                    }
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.BeginTooltip();
                        ImGui.Text($"{iface.Name}: {iface.Description}");
                        var addresses = iface.GetIPProperties().UnicastAddresses;
                        if (addresses.Count > 0)
                        {
                            ImGui.Text($"\t\tAddresses:");
                            foreach (var addr in addresses.Reverse())
                                ImGui.Text($"\t\t\t{addr.Address}");
                        }
                        else
                        {
                            ImGui.Text("\t\tInterface has no addresses");
                        }
                        string MAC = RemoteTracing.hexMAC(iface.GetPhysicalAddress());
                        if (MAC.Length > 0)
                            ImGui.Text($"\t\tMAC: {MAC}");
                        ImGui.Text($"\t\tType: {iface.NetworkInterfaceType}");
                        ImGui.Text($"\t\tID: {iface.Id}");
                        ImGui.EndTooltip();
                    }
                }
                ImGui.EndTable();
            }
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
            ImGui.TableNextColumn();
            ImGui.Text("Interface");
            ImGui.TableNextColumn();
            DrawInterfaceSelector();

        }


        void DrawModeToggle()
        {
            Vector2 togStart = ImGui.GetCursorScreenPos();
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
        }

        void DrawMessagesList(float itemsWidth)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.FrameBg));
            if (ImGui.BeginChild("##MsgsFrame1", new Vector2(itemsWidth, ImGui.GetContentRegionAvail().Y)))
            {
                var messages = _rgatState.NetworkBridge.GetRecentConnectEvents().TakeLast(5);
                if (messages.Any())
                {
                    ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(4, 0));
                    ImGui.Indent(6);
                    foreach (var evt in messages)
                    {
                        if (evt.Item2 == null)
                        {
                            ImGui.Text(evt.Item1);
                        }
                        else
                        {
                            ImGui.TextColored(Themes.GetThemeColourWRF(evt.Item2.Value).ToVec4(), evt.Item1);
                        }
                    }
                    ImGui.Indent(0);
                    ImGui.PopStyleVar();
                }
                ImGui.EndChildFrame();
            }
            ImGui.PopStyleColor();
        }
    }
}

