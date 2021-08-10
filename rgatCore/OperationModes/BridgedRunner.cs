using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static rgat.BridgeConnection;

namespace rgat.OperationModes

{    /// <summary>
     /// Runs rgat as a headless proxy which allows an rgat instance on a remote machine to control tracing and receive raw trace data
     /// This does not require access to a GPU
     /// </summary>
    class BridgedRunner
    {
        rgatState _rgatState;
        public BridgedRunner(rgatState state)
        {
            _rgatState = state;
        }

        Queue<Tuple<emsgType, string>> _incomingData = new Queue<Tuple<emsgType, string>>();
        readonly object _lock = new object();

        ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);


        public void StartGUIConnect(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback onConnected)
        {
            if (GlobalConfig.StartOptions.ConnectModeAddress != null)
            {
                Logging.RecordLogEvent("Starting GUI connect mode", Logging.LogFilterType.TextDebug);
                ConnectToListener(connection, onConnected);
            }
        }

        public void StartGUIListen(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback onConnected)
        {
            if (GlobalConfig.StartOptions.ListenPort != null)
            {
                Logging.RecordLogEvent("Starting GUI listen mode", Logging.LogFilterType.TextDebug);
                StartListenerMode(connection, onConnected);
            }

        }

        public void RunHeadless(BridgeConnection connection)
        {
            GlobalConfig.LoadConfig(); //todo a lightweight headless config

            if (GlobalConfig.StartOptions.ListenPort != null)
            {
                Logging.RecordLogEvent($"Starting headless listen mode => {GlobalConfig.StartOptions.ListenPort}", Logging.LogFilterType.TextDebug);
                StartListenerMode(connection, () => RunConnection(connection));
            }

            if (GlobalConfig.StartOptions.ConnectModeAddress != null)
            {
                Logging.RecordLogEvent($"Starting headless connect mode => {GlobalConfig.StartOptions.ConnectModeAddress}", Logging.LogFilterType.TextDebug);
                ConnectToListener(connection, () => RunConnection(connection));
            }

            while (connection.ActiveNetworking)
            {
                Thread.Sleep(500); //todo on disconnected callback
            }

            Console.WriteLine("Headless mode complete");
        }

        void RunConnection(BridgeConnection connection)
        {
            while (!_rgatState.rgatIsExiting && !connection.Connected && connection.ActiveNetworking)
            {
                Console.WriteLine($"Waiting for connection: {connection.BridgeState}");
                System.Threading.Thread.Sleep(500);
            }
            List<Tuple<emsgType, string>> incoming = new List<Tuple<emsgType, string>>();
            while (!_rgatState.rgatIsExiting && connection.Connected)
            {
                Console.WriteLine($"Headless bridge running while connected {connection.BridgeState}");
                NewDataEvent.Wait();
                lock (_lock)
                {
                    if (_incomingData.Any())
                    {
                        incoming = _incomingData.ToList();
                        _incomingData.Clear();
                    }
                    NewDataEvent.Reset();
                }

                foreach (Tuple<emsgType, string> item in incoming)
                {
                    Console.WriteLine($"Processing indata: {item}");
                    if (item.Item2.Length > 0)
                    {
                        ProcessData(item);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"RunConnection Error: null data");
                        connection.Teardown();
                        break;
                    }
                }
            }

        }


        void ProcessData(Tuple<emsgType, string> item)
        {

            switch (item.Item1)
            {
                case emsgType.Command:
                    ProcessCommand(item.Item2);
                    break;
                default:
                    Console.WriteLine($"Unhandled message typer {item.Item1} => {item.Item2}");
                    break;
            }
        }


        void ProcessCommand(string cmd)
        {
            if (_rgatState.NetworkBridge.GUIMode)
            {
                Logging.RecordLogEvent("Error: GUI sent a command", Logging.LogFilterType.TextError);
                _rgatState.NetworkBridge.Teardown();
                return;
            }




            Console.WriteLine("Processing command " + cmd);
            switch (cmd)
            {
                case "RefreshCaches":
                    Console.WriteLine($"Sending {GlobalConfig.RecentBinaries.Count} recent");
                    _rgatState.NetworkBridge.SendResponse("RefreshCaches", GlobalConfig.RecentBinaries);
                    break;
            }

        }

   

        public void GotData(Tuple<emsgType, string> data)
        {
            Console.WriteLine("BridgedRunner got new data: " + data.Item2);
            lock (_lock)
            {
                _incomingData.Enqueue(data);
                NewDataEvent.Set();
            }
        }


        void ConnectToListener(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback onConnected)
        {

            IPAddress localBinding = GetLocalAddress();
            if (localBinding == null) return;

            Console.WriteLine($"Initialising Connection to {GlobalConfig.StartOptions.ConnectModeAddress}");
            if (!GetRemoteAddress(GlobalConfig.StartOptions.ConnectModeAddress, out string address, out int port))
            {
                Console.WriteLine($"Failed to parse address/port from param {GlobalConfig.StartOptions.ConnectModeAddress}");
                return;
            }

            connection.Start(localBinding, address, port, GotData, onConnected);
        }





        bool GetRemoteAddress(string param, out string address, out int port)
        {
            address = "";
            port = -1;

            if (param == null) return false;
            int slashindex = param.IndexOf("://");
            if (slashindex != -1)
            {
                param = param.Substring(slashindex);
            }
            string[] parts = param.Split(':', options: StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && int.TryParse(parts[1], out port))
            {
                address = parts[0];
                return port <= 65535;
            }
            return false;
        }

        IPAddress GetLocalAddress()
        {
            IPAddress result = null;
            if (GlobalConfig.StartOptions.ActiveNetworkInterface == null && GlobalConfig.StartOptions.Interface != null)
            {
                GlobalConfig.StartOptions.ActiveNetworkInterface = RemoteTracing.ValidateNetworkInterface(GlobalConfig.StartOptions.Interface);
            }

            if (GlobalConfig.StartOptions.ActiveNetworkInterface == null) //user didn't pass a param, or 
            {
                if (IPAddress.TryParse(GlobalConfig.StartOptions.Interface, out IPAddress address))
                {
                    result = address;
                }
                else
                {
                    result = IPAddress.Parse("0.0.0.0");
                }
            }
            else
            {

                //int index = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().GetIPv4Properties().Index;
                try
                {
                    if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.ToString() == GlobalConfig.StartOptions.Interface))
                    {
                        result = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.ToString() == GlobalConfig.StartOptions.Interface).Address;
                    }
                    else if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork))
                    {
                        result = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.AddressFamily == AddressFamily.InterNetwork).Address;
                    }
                    else if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6))
                    {
                        result = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6).Address;
                    }
                    else
                    {
                        Console.WriteLine($"Error: Failed to find any ipv4 or ipv6 addresses for the specified interface");
                        return null;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: Exception '{e.Message}' trying to find any ipv4 or ipv6 addresses for the specified interface");
                }
            }
            return result;
        }


        void StartListenerMode(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback connectCallback)
        {

            IPAddress localAddr = GetLocalAddress();
            if (localAddr == null)
            {
                Console.WriteLine("Error: no local address to connect from");
                return;
            }

            Int32 port;
            if (GlobalConfig.StartOptions.ListenPort != null && GlobalConfig.StartOptions.ListenPort.Value > 0)
            {
                port = GlobalConfig.StartOptions.ListenPort.Value;
                Console.WriteLine($"Starting TCP server on {localAddr}:{port}");
            }
            else
            {
                Console.WriteLine($"Starting TCP server on {localAddr}:[next free port]");
                port = 0;
            }

            Task connect = connection.Start(localAddr, port, GotData, connectCallback);
            connect.Wait();
        }


        /// Downloaded State

        static readonly object _cacheLock = new object();
        static List<GlobalConfig.CachedPathData> _pathsRecentBinaries = new List<GlobalConfig.CachedPathData>();
        static List<GlobalConfig.CachedPathData> _pathsRecentTraces = new List<GlobalConfig.CachedPathData>();

        public static void GetRecentWorkLists(out List<GlobalConfig.CachedPathData> binaries, out List<GlobalConfig.CachedPathData> traces)
        {
            lock (_cacheLock)
            {
                binaries = _pathsRecentBinaries.ToList();
                traces = _pathsRecentTraces.ToList();
            }

        }

        ////




    }
}
