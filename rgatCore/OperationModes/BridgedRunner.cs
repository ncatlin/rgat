using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
        public BridgedRunner()
        {
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
            while (!rgatState.RgatIsExiting && !connection.Connected && connection.ActiveNetworking)
            {
                Console.WriteLine($"Waiting for connection: {connection.BridgeState}");
                System.Threading.Thread.Sleep(500);
            }
            List<Tuple<emsgType, string>> incoming = new List<Tuple<emsgType, string>>();
            while (!rgatState.RgatIsExiting && connection.Connected)
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
                        connection.Teardown("Null indata");
                        break;
                    }
                }
            }

        }


        void ProcessData(Tuple<emsgType, string> item)
        {

            switch (item.Item1)
            {
                case emsgType.Meta:
                    if(item.Item2 != null && item.Item2.StartsWith("Teardown:"))
                    {
                        var split = item.Item2.Split(':');
                        string reason = "";
                        if (split.Length > 1 && split[1].Length > 0)
                            reason += ": " +split[1];
                        Logging.RecordLogEvent($"Disconnected - Remote party tore down the connection{((reason.Length > 0) ? reason : "")}", Logging.LogFilterType.TextError);
                        rgatState.NetworkBridge.Teardown();
                        return;
                    }

                    Console.WriteLine($"Unhandled meta message: {item.Item2}");
                    break;
                case emsgType.TracerCommand:
                    try
                    {
                        ProcessCommand(item.Item2);
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine($"Exception processing command  {item.Item1} {item.Item2}: {e}");
                        rgatState.NetworkBridge.Teardown($"Command Exception ({item.Item2})");
                    }
                    
                    break;
                case emsgType.CommandResponse:

                    if (!ParseResponse(item.Item2, out int commandID, out JToken response))
                    {
                        rgatState.NetworkBridge.Teardown($"Bad command ({commandID}) response");
                        break;
                    }
                    Console.WriteLine($"Delivering response {response}");
                    RemoteDataMirror.DeliverResponse(commandID, response);
                    break;

                case emsgType.Log:
                    {
                        int typeEnd = item.Item2.IndexOf(',');
                        string msgTypeStr = item.Item2.Substring(0, typeEnd);
                        if (!Enum.TryParse(typeof(Logging.LogFilterType), msgTypeStr, out object logtype))
                        {
                            rgatState.NetworkBridge.Teardown($"Bad Log Format");
                            return;
                        }
                        Console.WriteLine($"Logging { (Logging.LogFilterType)logtype} from remote: {item.Item2}");
                        Logging.RecordLogEvent(item.Item2.Substring(typeEnd + 1), filter: (Logging.LogFilterType)logtype);
                        break;
                    }
                default:
                    rgatState.NetworkBridge.Teardown($"Bad message type ({item.Item1})");
                    Logging.RecordLogEvent($"Unhandled message type {item.Item1} => {item.Item2}", filter: Logging.LogFilterType.TextError );
                    break;
            }
        }

        bool ParseCommandFields(string cmd, out string actualCmd, out int cmdID, out string paramfield)
        {
            actualCmd = "";
            paramfield = null;
            cmdID = -1;

            int cmdEndIDx = cmd.IndexOf('&');
            if (cmdEndIDx == -1)
            {
                Logging.RecordLogEvent("Error: No command seperator in command.", Logging.LogFilterType.TextError);
                return false;
            }
            int idEndIDx = cmd.IndexOf('&', cmdEndIDx + 1);
            if (idEndIDx == -1)
            {
                Logging.RecordLogEvent("Error: No command ID seperator in command.", Logging.LogFilterType.TextError);
                return false;
            }

            actualCmd = cmd.Substring(0, cmdEndIDx);

            if (cmd.Length > (idEndIDx + 1))
            {
                int paramLen = cmd.Length - idEndIDx - 2;
                paramfield = cmd.Substring(idEndIDx + 1, paramLen);
            }

            int.TryParse(cmd.Substring(cmdEndIDx + 1, idEndIDx - cmdEndIDx - 1), out cmdID);
            if (cmdID == -1)
            {
                Logging.RecordLogEvent("Error: No command ID in command.", Logging.LogFilterType.TextError);
                return false;
            }
            return true;
        }

        void ProcessCommand(string cmd)
        {
            if (rgatState.NetworkBridge.GUIMode)
            {
                Logging.RecordLogEvent("Error: The GUI sent a tracer-only command.", Logging.LogFilterType.TextError);
                rgatState.NetworkBridge.Teardown("GUI only command");
                return;
            }

            if(!ParseCommandFields(cmd, out string actualCmd, out int cmdID, out string paramfield))
            {
                rgatState.NetworkBridge.Teardown("Command parse failure");
                return;
            }


            Console.WriteLine("Processing command " + cmd);
            switch (actualCmd)
            {
                case "GetRecentBinaries":
                    Console.WriteLine($"Sending {GlobalConfig.RecentBinaries.Count} recent");
                    rgatState.NetworkBridge.SendResponseObject(cmdID, GlobalConfig.RecentBinaries);
                    break;
                case "DirectoryInfo":
                    rgatState.NetworkBridge.SendResponseJSON(cmdID, GetDirectoryInfo(paramfield));
                    break;
                case "GetDrives":
                    rgatState.NetworkBridge.SendResponseObject(cmdID, rgatFilePicker.FilePicker.GetLocalDriveStrings());
                    break;
                case "LoadTarget":
                    rgatState.NetworkBridge.SendResponseObject(cmdID, GatherTargetInitData(paramfield));
                    break;
                case "StartTrace":
                    StartTrace(paramfield);
                    break;
                default:
                    Logging.RecordLogEvent($"Unknown command: {actualCmd} ({cmd})", Logging.LogFilterType.TextError);
                    rgatState.NetworkBridge.Teardown("Bad Command");
                    break;
            }

        }

        void StartTrace(string paramfield)
        {
            int testIdIdx = paramfield.LastIndexOf(',');
            string path = paramfield.Substring(0, testIdIdx);
            long testID = long.Parse(paramfield.Substring(testIdIdx + 1));
            BinaryTarget target = rgatState.targets.AddTargetByPath(path);

            Process p = ProcessLaunching.StartLocalTrace(target.BitWidth == 32 ? GlobalConfig.PinToolPath32 : GlobalConfig.PinToolPath64, path, testID);
            rgatState.NetworkBridge.SendLog($"Trace of {path} launched as remote process ID {p.Id}", Logging.LogFilterType.TextAlert);
        }

        JsonLoadSettings _JSONLoadSettings = new JsonLoadSettings() { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error };

 

        JObject GetDirectoryInfo(string dir)
        {
            JObject data = new JObject();
            if (dir == null || dir.Length == 0)
                dir = Environment.CurrentDirectory;
            DirectoryInfo dirinfo = new DirectoryInfo(dir);
            data.Add("Current", dir);
            data.Add("CurrentExists", Directory.Exists(dir));
            data.Add("Parent", (dirinfo.Parent != null) ? dirinfo.Parent.FullName : "");
            data.Add("ParentExists", dirinfo.Parent != null && Directory.Exists(dirinfo.Parent.FullName));
            data.Add("Contents", GetDirectoryListing(dir, out string error));
            data.Add("Error", error);
            return data;
            //rootfolder
        }

        JObject GetDirectoryListing(string param, out string error)
        {
            JArray files = new JArray();
            JArray dirs = new JArray();
            error = "";
            Console.WriteLine("listing " + param);
            try
            {
                if (Directory.Exists(param))
                {
                    string[] listing = Directory.GetFileSystemEntries(param);
                    foreach (string item in listing)
                    {
                        FileInfo info = new FileInfo(item);
                        if (File.Exists(item)) files.Add(new JArray() { Path.GetFileName(item), false, info.Length, info.LastWriteTime });
                        else if (Directory.Exists(item)) dirs.Add(new JArray() { Path.GetFileName(item), true, -1, info.LastWriteTime });
                    }
                }
            }
            catch (Exception e)
            {
                if (e.GetType() != typeof(System.UnauthorizedAccessException))
                {
                    Console.WriteLine(e);
                }
                error = e.Message;
            }

            JObject result = new JObject();
            result.Add("Files", files);
            result.Add("Dirs", dirs);
            return result;
        }


        JToken GatherTargetInitData(string path)
        {
            BinaryTarget target = rgatState.targets.AddTargetByPath(path);          

            return (JToken)target.GetRemoteLoadInitData();
        }



        bool ParseResponse(string messageJson, out int commandID, out JToken responseData)
        {
            commandID = -1; responseData = null;
            try
            {
                JObject responseJsn = JObject.Parse(messageJson, _JSONLoadSettings);
                if (!responseJsn.TryGetValue("CommandID", out JToken cID) || cID == null || cID.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent($"Missing valid command ID in response JSON: [snippet: {messageJson.Substring(0, Math.Min(messageJson.Length, 128))}]");
                    return false;
                }
                if (!responseJsn.TryGetValue("Response", out responseData) || responseData == null)
                {
                    Logging.RecordLogEvent($"Missing valid response data: [snippet: {messageJson.Substring(0, Math.Min(messageJson.Length, 128))}]");
                    return false;
                }
                commandID = cID.ToObject<int>();
                return true;
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error parsing incoming response JSON: {e.Message} [snippet: {messageJson.Substring(0, Math.Min(messageJson.Length, 128))}]");
                return false;
            }
        }




        public void GotData(Tuple<emsgType, string> data)
        {
            //Console.WriteLine($"BridgedRunner ({(rgatState.NetworkBridge.GUIMode ? "GUI mode" : "Headless mode")}) got new {data.Item1} data: {data.Item2}");
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


        public void CompleteGUIConnection()
        {
            Thread dataProcessor = new Thread(new ParameterizedThreadStart(ResponseHandlerThread));
            dataProcessor.Start(rgatState.NetworkBridge.CancelToken);
            rgatState.NetworkBridge.SendCommand("GetRecentBinaries", recipientID:"GUI",  callback: RemoteDataMirror.HandleRecentBinariesList);
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




        public void ResponseHandlerThread(object cancelToken)
        {
            Debug.Assert(cancelToken.GetType() == typeof(CancellationToken));
            lock (_lock)
            {
                _incomingData.Clear();
            }
            Tuple<emsgType, string>[] incoming = null;
            while (!rgatState.RgatIsExiting)
            {
                try
                {
                    NewDataEvent.Wait((CancellationToken)cancelToken);
                }
                catch (Exception e)
                {
                    if (((CancellationToken)cancelToken).IsCancellationRequested) return;
                }
                lock (_lock)
                {
                    if (_incomingData.Any())
                    {
                        incoming = _incomingData.ToArray();
                        _incomingData.Clear();
                    }
                }
                if (incoming != null)
                {
                    foreach (var item in incoming)
                    {
                        ProcessData(item);
                    }
                    incoming = null;
                }
            }
        }




    }
}
