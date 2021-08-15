using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgat.Config;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
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

        Queue<NETWORK_MSG> _incomingData = new Queue<NETWORK_MSG>();
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

            rgatState.processCoordinatorThreadObj = new ProcessCoordinatorThread();
            rgatState.processCoordinatorThreadObj.Begin();

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
            rgatState.Shutdown();
        }

        void RunConnection(BridgeConnection connection)
        {
            while (!rgatState.RgatIsExiting && !connection.Connected && connection.ActiveNetworking)
            {
                Console.WriteLine($"Waiting for connection: {connection.BridgeState}");
                System.Threading.Thread.Sleep(500);
            }
            List<NETWORK_MSG> incoming = new List<NETWORK_MSG>();
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

                foreach (NETWORK_MSG item in incoming)
                {
                    //Console.WriteLine($"RunConnection Processing indata {item.msgType}: {GetString(item.data)}");
                    if (item.data.Length > 0)
                    {
                        try
                        {
                            ProcessData(item);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"RunConnection Error: ProcessData exception {e.Message} <{item.msgType}>, data:{GetString(item.data)}", Logging.LogFilterType.TextError);
                            connection.Teardown("RunConnection ProcessData Exception");
                            return;
                        }
                    }
                    else
                    {
                        Logging.RecordLogEvent($"RunConnection Error: null data", Logging.LogFilterType.TextError);
                        connection.Teardown("Null indata");
                        return;
                    }
                }
            }

        }


        void ProcessData(NETWORK_MSG item)
        {

            switch (item.msgType)
            {
                case emsgType.Meta:
                    string metaparam = GetString(item.data); 
                    if (metaparam != null && metaparam.StartsWith("Teardown:"))
                    {
                        var split = metaparam.Split(':');
                        string reason = "";
                        if (split.Length > 1 && split[1].Length > 0)
                            reason = split[1];
                        Logging.RecordLogEvent($"Disconnected - Remote party tore down the connection{((reason.Length > 0) ? $": {reason}" : "")}", Logging.LogFilterType.TextError);
                        rgatState.NetworkBridge.Teardown(reason);
                        return;
                    }

                    Console.WriteLine($"Unhandled meta message: {metaparam}");
                    break;

                case emsgType.Command:
                    try
                    {
                        ProcessCommand(GetString(item.data));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception processing command  {item.msgType} {GetString(item.data)}: {e}");
                        rgatState.NetworkBridge.Teardown($"Command Exception ({GetString(item.data)})");
                    }

                    break;

                case emsgType.CommandResponse:
                    try
                    {
                        string responseStr = GetString(item.data);
                        if (!ParseResponse(responseStr, out int commandID, out JToken response))
                        {
                            rgatState.NetworkBridge.Teardown($"Bad command ({commandID}) response");
                            break;
                        }
                        Console.WriteLine($"Delivering response {response}");
                        RemoteDataMirror.DeliverResponse(commandID, response);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception processing command response {item.msgType} {GetString(item.data)}: {e}");
                        rgatState.NetworkBridge.Teardown($"Command Reponse Exception ({GetString(item.data)})");
                    }

                    break;

                case emsgType.TraceMeta:
                    
                    if (!ParseTraceMeta(item.data, out TraceRecord trace, out string[] items))
                    {
                        rgatState.NetworkBridge.Teardown($"Bad Trace Metadata");
                        break;
                    }
                    Console.WriteLine($"Processing trace meta {GetString(item.data)}");
                    if (!HandleTraceMeta(trace, items))
                    {
                        Logging.RecordLogEvent($"Failed processing trace meta {GetString(item.data)}", Logging.LogFilterType.TextError);
                        rgatState.NetworkBridge.Teardown($"Trace Meta processing failed");
                    }
                    break;

                case emsgType.TraceData:
                    {

                        //Console.WriteLine("handletracedata to ui: " + System.Text.ASCIIEncoding.ASCII.GetString(item.data, 0, item.data.Length));
                        if (RemoteDataMirror.GetPipeInterface(item.destinationID, out RemoteDataMirror.ProcessIncomingWorkerData dataFunc))
                        {
                            dataFunc(item.data, 0);
                        }
                        else
                        {
                            Logging.RecordLogEvent($"Trace data sent to bad pipe {item.destinationID}", Logging.LogFilterType.TextError);
                            rgatState.NetworkBridge.Teardown($"Trace Data processing failed");
                        }

                        break;
                    }

                case emsgType.TraceCommand: 
                    {
                        Console.WriteLine("Incoming trace command:" + GetString(item.data));
                        if (rgatState.NetworkBridge.HeadlessMode &&
                            RemoteDataMirror.GetPipeWorker(item.destinationID, out TraceProcessorWorker moduleHandler) &&
                            moduleHandler.GetType() == typeof(ModuleHandlerThread))
                        {
                            ((ModuleHandlerThread)moduleHandler).ProcessIncomingTraceCommand(item.data, 0);
                        }
                        else
                        {
                            Logging.RecordLogEvent($"Invalid tracecommand addressing {item.destinationID}", Logging.LogFilterType.TextError);
                            rgatState.NetworkBridge.Teardown($"TraceCommand addressing failure");
                        }

                        break;
                    }

                case emsgType.Log:
                    {
                        byte[] data = item.data;

                        Logging.LogFilterType filter = (Logging.LogFilterType)item.destinationID;
                        if (!Enum.IsDefined(typeof(Logging.LogFilterType), filter))
                        {
                            Logging.RecordLogEvent("Bad log filter for " + GetString(item.data));
                            return;
                        }
                        Console.WriteLine($"Logging { filter} from remote: {GetString(item.data)}");
                        Logging.RecordLogEvent(GetString(item.data), filter: filter);
                        break;
                    }
                default:
                    rgatState.NetworkBridge.Teardown($"Bad message type ({item.data})");
                    Logging.RecordLogEvent($"Unhandled message type {item.msgType} => {GetString(item.data)}", filter: Logging.LogFilterType.TextError);
                    break;
            }
        }


        bool ParseTraceMeta(byte[] infoBytes, out TraceRecord trace, out string[] metaparams)
        {
            trace = null;
            metaparams = null;
            string info;
            if (infoBytes == null) return false;
            try
            {
                info = Encoding.ASCII.GetString(infoBytes);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exeption {e} decoding tracemeta", Logging.LogFilterType.TextError);
                return false;
            }


            string[] splitmain = info.Split(',');
            if (splitmain.Length < 4)
            {
                Logging.RecordLogEvent($"Insufficient fields in tracemeta message", Logging.LogFilterType.TextError);
                return false;
            }

            string sha1 = splitmain[0];
            string pidstr = splitmain[1];
            string idstr = splitmain[2];
            string infostr = splitmain[3];

            if (!uint.TryParse(pidstr, out uint pid) || !long.TryParse(idstr, out long id)) return false;

            if (sha1 != null && sha1.Length > 0 && rgatState.targets.GetTargetBySHA1(sha1, out BinaryTarget target))
            {
                target.GetTraceByIDs(pid, id, out trace);
                if (trace == null)
                {
                    target.CreateNewTrace(DateTime.Now, pid, id, out trace);
                }
            }

            metaparams = infostr.Split('@');
            return true;
        }

        bool HandleTraceMeta(TraceRecord trace, string[] inparams)
        {
            Debug.Assert(trace != null);


            if (inparams.Length == 7 && inparams[0] == "InitialPipes")
            {
                //start block handler
                if (inparams[1] == "C" && uint.TryParse(inparams[2], out uint cmdPipeID) &&
                    inparams[3] == "E" && uint.TryParse(inparams[4], out uint eventPipeID) &&
                    inparams[5] == "B" && uint.TryParse(inparams[6], out uint blockPipeID))
                {

                    ModuleHandlerThread moduleHandler = new ModuleHandlerThread(trace.binaryTarg, trace, blockPipeID);
                    trace.ProcessThreads.Register(moduleHandler);
                    moduleHandler.RemoteCommandPipeID = cmdPipeID;
                    RemoteDataMirror.RegisterRemotePipe(cmdPipeID, moduleHandler, null);
                    RemoteDataMirror.RegisterRemotePipe(eventPipeID, moduleHandler, moduleHandler.AddRemoteEventData);
                    moduleHandler.Begin();


                    BlockHandlerThread blockHandler = new BlockHandlerThread(trace.binaryTarg, trace, eventPipeID);
                    trace.ProcessThreads.Register(blockHandler);
                    RemoteDataMirror.RegisterRemotePipe(blockPipeID, blockHandler, blockHandler.AddRemoteBlockData);
                    blockHandler.Begin();

                }



                //start cmd handler

                return true;
            }

            Logging.RecordLogEvent($"Error unhandled cmd {String.Join("", inparams)}");
            return false;

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

            if (!ParseCommandFields(cmd, out string actualCmd, out int cmdID, out string paramfield))
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
                    StartHeadlessTrace(paramfield);
                    break;
                case "ThreadIngest":
                    if (!StartThreadIngestWorker(cmdID, paramfield))
                    {
                        rgatState.NetworkBridge.Teardown("Failed ThreadIngest Command");
                    }
                    break;
                default:
                    Logging.RecordLogEvent($"Unknown command: {actualCmd} ({cmd})", Logging.LogFilterType.TextError);
                    rgatState.NetworkBridge.Teardown("Bad Command");
                    break;
            }

        }

        void StartHeadlessTrace(string paramfield)
        {
            int testIdIdx = paramfield.LastIndexOf(',');
            string path = paramfield.Substring(0, testIdIdx);
            long testID = long.Parse(paramfield.Substring(testIdIdx + 1));
            BinaryTarget target = rgatState.targets.AddTargetByPath(path);

            Process p = ProcessLaunching.StartLocalTrace(target.BitWidth == 32 ? GlobalConfig.PinToolPath32 : GlobalConfig.PinToolPath64, path, testID);
            rgatState.NetworkBridge.SendLog($"Trace of {path} launched as remote process ID {p.Id}", Logging.LogFilterType.TextAlert);
        }



        bool StartThreadIngestWorker(int cmdID, string paramfield)
        {
            JObject paramObj;
            try
            {
                paramObj = JObject.Parse(paramfield);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("Failed to parse StartThreadIngestWorker params", Logging.LogFilterType.TextError);
                return false;
            }

            if (paramObj.TryGetValue("TID", out JToken tidTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("PID", out JToken pidTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("RID", out JToken ridTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("ref", out JToken refTok) && tidTok.Type == JTokenType.Integer)
            {
                string pipename = ModuleHandlerThread.GetTracePipeName(pidTok.ToObject<uint>(), ridTok.ToObject<long>(), tidTok.ToObject<ulong>());
                Console.WriteLine("Opening pipe " + pipename);
                uint pipeID = RemoteDataMirror.RegisterPipe(pipename);
                NamedPipeServerStream threadListener = new NamedPipeServerStream(pipename, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.None);

                JObject response = new JObject();
                response.Add("Thread#", refTok);
                response.Add("Pipe#", pipeID);


                rgatState.NetworkBridge.SendResponseJSON(cmdID, response);
                Console.WriteLine("Waiting for thread connection... ");
                threadListener.WaitForConnection();

                PipeTraceIngestThread worker = new PipeTraceIngestThread(null, threadListener, tidTok.ToObject<uint>(), pipeID);

                RemoteDataMirror.RegisterRemotePipe(pipeID, worker, null);
                worker.Begin();

                return true;
            }

            Logging.RecordLogEvent("Bad StartThreadIngestWorker params", Logging.LogFilterType.TextError);
            return false;
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




        public void GotData(NETWORK_MSG data)
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
            rgatState.NetworkBridge.SendCommand("GetRecentBinaries", recipientID: "GUI", callback: RemoteDataMirror.HandleRecentBinariesList);
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
            NETWORK_MSG[] incoming = null;
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
                       // try
                        {
                            ProcessData(item);
                        }
                        /*
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"ResponseHandlerThread Error: ProcessData exception {e.Message} <{item.msgType}>, data:{GetString(item.data)}", Logging.LogFilterType.TextError);
                            rgatState.NetworkBridge.Teardown("Processing response exception");
                            return;
                        }*/
                    }
                    incoming = null;
                }
            }
        }

        static string GetString(byte[] bytes)
        {
            try
            {
               return Encoding.ASCII.GetString(bytes);
            }
            catch
            {
                return "<DecodeError>";
            };
        }


    }
}
