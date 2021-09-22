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

{
    /// <summary>
    /// Runs rgat as a headless proxy which allows an rgat instance on a remote machine to control tracing and receive raw trace data
    /// This does not require access to a GPU
    /// </summary>
    class BridgedRunner
    {
        public BridgedRunner()
        {
        }

        readonly Queue<NETWORK_MSG> _incomingData = new Queue<NETWORK_MSG>();
        readonly object _lock = new object();
        readonly ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);


        public void StartGUIConnect(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback onConnected)
        {
            if (GlobalConfig.StartOptions.ConnectModeAddress != null)
            {
                Logging.RecordLogEvent("Starting GUI connect mode", Logging.LogFilterType.TextDebug);
                try
                {
                    ConnectToListener(connection, onConnected);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Exception in ConnectToListener: {e.Message}");
                    rgatState.NetworkBridge.Teardown("Connection Failure");
                    return;
                }
            }
        }

        public void StartGUIListen(BridgeConnection connection, BridgeConnection.OnConnectSuccessCallback onConnected)
        {
            if (GlobalConfig.StartOptions.ListenPort != null)
            {
                Logging.RecordLogEvent("Starting GUI listen mode", Logging.LogFilterType.TextDebug);
                try
                {
                    StartListenerMode(connection, onConnected);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Exception in StartListenerMode: {e.Message}");
                    rgatState.NetworkBridge.Teardown("Connection Failure");
                    return;
                }
            }

        }

        public static void SendSigDates()
        {
            JObject sigDates = new JObject();
            sigDates.Add("YARA", rgatState.YARALib.NewestSignature);
            sigDates.Add("DIE", rgatState.DIELib.NewestSignature);
            rgatState.NetworkBridge.SendAsyncData("SignatureTimes", sigDates);
        }

        /// <summary>
        /// Runs in headless mode which either connects to (command line -r) or waits for connections
        /// from (command line -p) a controlling UI mode rgat instance
        /// This does not use the GPU
        /// </summary>
        public void RunHeadless(BridgeConnection connection)
        {
            GlobalConfig.LoadConfig(GUI: false, progress: null);
            InitStartOptions();

            Task sigsTask = Task.Run(() => rgatState.LoadSignatures(completionCallback: SendSigDates));

            if (GlobalConfig.NewVersionAvailable)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"A new version of rgat is available! ({CONSTANTS.RGAT_VERSION} -> {GlobalConfig.Settings.Updates.UpdateLastCheckVersion})");
                Console.ForegroundColor = ConsoleColor.White;
            }

            rgatState.processCoordinatorThreadObj = new ProcessCoordinatorThread();
            rgatState.processCoordinatorThreadObj.Begin();

            if (GlobalConfig.StartOptions.NetworkKey == null || GlobalConfig.StartOptions.NetworkKey.Length == 0)
            {
                Logging.RecordError("A network key (-k) is required");
                return;
            }

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

            WaitHandle.WaitAny(new[] { rgatState.NetworkBridge.CancelToken.WaitHandle });

            Console.WriteLine("Headless mode complete");
            rgatState.Shutdown();
        }

        void InitStartOptions()
        {
            string defaultKey = GlobalConfig.Settings.Network.DefaultNetworkKey;
            if (defaultKey?.Length > 0)
            {
                GlobalConfig.StartOptions.NetworkKey = defaultKey;
            }

        }


        void RunConnection(BridgeConnection connection)
        {
            while (!rgatState.rgatIsExiting && !connection.Connected && connection.ActiveNetworking)
            {
                Console.WriteLine($"Waiting for connection: {connection.BridgeState}");
                System.Threading.Thread.Sleep(500);
            }
            List<NETWORK_MSG> incoming = new List<NETWORK_MSG>();
            while (!rgatState.rgatIsExiting && connection.Connected)
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
                        JObject cmdObj = JObject.Parse(GetString(item.data));
                        ProcessCommand(cmdObj);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception processing command  {item.msgType}: {e}");
                        rgatState.NetworkBridge.Teardown($"Command Exception ({item.msgType})");
                    }

                    break;

                case emsgType.CommandResponse:
                    try
                    {
                        string responseStr = GetString(item.data);
                        if (!ParseResponse(responseStr, out int commandID, out JToken? response))
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
                            dataFunc(item.data);
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
                            ((ModuleHandlerThread)moduleHandler).ProcessIncomingTraceCommand(item.data);
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
                        Logging.LogFilterType filter = (Logging.LogFilterType)item.destinationID;
                        if (!Enum.IsDefined(typeof(Logging.LogFilterType), filter))
                        {
                            Logging.RecordError("Bad log filter for " + GetString(item.data));
                            return;
                        }
                        Logging.RecordLogEvent("[Remote Log] " + GetString(item.data), filter: filter);
                        break;
                    }

                case emsgType.AsyncData:
                    {
                        try
                        {
                            string asyncStr = GetString(item.data);
                            if (!ParseAsync(asyncStr, out string? name, out JToken? data))
                            {
                                rgatState.NetworkBridge.Teardown($"Bad async data ({name})");
                                break;
                            }
                            Console.WriteLine($"Delivering async {name}");
                            ProcessAsync(name, data);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Exception processing command response {item.msgType} {GetString(item.data)}: {e}");
                            rgatState.NetworkBridge.Teardown($"Command Reponse Exception ({GetString(item.data)})");
                        }
                    }

                    break;

                default:
                    rgatState.NetworkBridge.Teardown($"Bad message type ({item.data})");
                    Logging.RecordError($"Unhandled message type {item.msgType} => {GetString(item.data)}");
                    break;
            }
        }


        bool ParseAsync(string injson, out string? name, out JToken? data)
        {
            name = null; data = null;
            try
            {
                JObject msgObj = JObject.Parse(injson);

                if (!msgObj.TryGetValue("Name", out JToken? nameTok) || nameTok.Type != JTokenType.String) return false;
                name = nameTok.ToString();
                if (msgObj.TryGetValue("Data", out data)) return true;

            }
            catch (Exception e)
            {
                Logging.RecordError($"Error parsing async data: {e.Message}");
            }
            return false;
        }

        public void ProcessAsync(string name, JToken data)
        {
            bool success = false;
            try
            {
                switch (name)
                {
                    case "SignatureTimes":
                        success = ProcessSignatureTimes(data);
                        break;

                    case "SigHit":
                        success = ProcessSignatureHit(data);
                        break;
                    default:
                        Logging.RecordError("Bad async data: " + name);
                        return;
                }
            }
            catch (Exception e)
            {
                Logging.RecordError("Error processing async data: " + e.Message);
            }

            if (!success)
            {
                rgatState.NetworkBridge.Teardown($"Bad Async Data ({name})");
            }

        }


        bool ProcessSignatureTimes(JToken data)
        {
            if (data.Type is not JTokenType.Object) return false;

            JObject? values = data.ToObject<JObject>();
            if (values is null) return false;
            if (values.TryGetValue("YARA", out JToken? yaraTok) && yaraTok.Type is JTokenType.Date)
                rgatState.YARALib.EndpointNewestSignature = yaraTok.ToObject<DateTime>();
            if (values.TryGetValue("DIE", out JToken? dieTok) && dieTok.Type is JTokenType.Date)
                rgatState.DIELib.EndpointNewestSignature = dieTok.ToObject<DateTime>();

            return true;
        }

        bool ProcessSignatureHit(JToken data)
        {
            if (data.Type is not JTokenType.Object) return false;

            JObject? values = data.ToObject<JObject>();
            if (values is null || !values.TryGetValue("Obj", out JToken? sigObjTok)) return false;
            if (!values.TryGetValue("TargetSHA", out JToken? shaTok)) return false;
            if (values.TryGetValue("Type", out JToken? typeTok) && typeTok.Type is JTokenType.String)
            {
                if (!rgatState.targets.GetTargetBySHA1(shaTok.ToString(), out BinaryTarget? target) || target is null) return false;
                string sigType = typeTok.ToString();
                switch (sigType)
                {
                    case "YARA":
                        YARAScan.YARAHit? yarahit = sigObjTok.ToObject<YARAScan.YARAHit>();
                        target.AddYaraSignatureHit(yarahit);
                        break;

                    case "DIE":
                        string dieHit = sigObjTok.ToString();
                        target.AddDiESignatureHit(dieHit);
                        break;

                    default:
                        Logging.RecordError("ProcessSignatureHit processing bad signature type:" + sigType.Substring(0, Math.Min(50, sigType.Length)));
                        return false;
                }
            }
            return true;
        }


        /// <summary>
        /// Parse internal control information used to setup/manage remote tracing
        /// </summary>
        /// <param name="infoBytes">The raw bytes of the data</param>
        /// <param name="trace">The trace the metadata applies to</param>
        /// <param name="metaparams">The metadata string items produced</param>
        /// <returns></returns>
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
                Logging.RecordError($"Exeption {e} decoding tracemeta");
                return false;
            }


            string[] splitmain = info.Split(',');
            if (splitmain.Length < 4)
            {
                Logging.RecordError($"Insufficient fields in tracemeta message");
                return false;
            }

            string sha1 = splitmain[0];
            string pidstr = splitmain[1];
            string idstr = splitmain[2];
            string infostr = splitmain[3];

            if (!uint.TryParse(pidstr, out uint pid) || !long.TryParse(idstr, out long id)) return false;

            if (sha1 != null && sha1.Length > 0 && rgatState.targets.GetTargetBySHA1(sha1, out BinaryTarget? target) && target is not null)
            {
                target.GetTraceByIDs(pid, id, out trace);
                if (trace == null)
                {
                    target.CreateNewTrace(DateTime.Now, pid, id, out trace);
                }
            }
            else
            {
                Logging.RecordError($"Received trace start notification for unknown target hash {sha1}");
                return false;
            }

            metaparams = infostr.Split('@');
            return true;
        }

        bool HandleTraceMeta(TraceRecord trace, string[] inparams)
        {
            Debug.Assert(trace != null);

            // Tells rgat how to route incominng remote trace data to local trace worker input pipes 
            if (inparams.Length == 7 && inparams[0] == "InitialPipes")
            {
                //start block handler
                if (inparams[1] == "C" && uint.TryParse(inparams[2], out uint cmdPipeID) &&
                    inparams[3] == "E" && uint.TryParse(inparams[4], out uint eventPipeID) &&
                    inparams[5] == "B" && uint.TryParse(inparams[6], out uint blockPipeID))
                {

                    ModuleHandlerThread moduleHandler = new ModuleHandlerThread(trace.Target, trace, blockPipeID);
                    trace.ProcessThreads.Register(moduleHandler);
                    moduleHandler.RemoteCommandPipeID = cmdPipeID;
                    RemoteDataMirror.RegisterRemotePipe(cmdPipeID, moduleHandler, null);
                    RemoteDataMirror.RegisterRemotePipe(eventPipeID, moduleHandler, moduleHandler.AddRemoteEventData);
                    moduleHandler.Begin();


                    BlockHandlerThread blockHandler = new BlockHandlerThread(trace.Target, trace, eventPipeID);
                    trace.ProcessThreads.Register(blockHandler);
                    RemoteDataMirror.RegisterRemotePipe(blockPipeID, blockHandler, blockHandler.AddRemoteBlockData);
                    blockHandler.Begin();

                }



                //start cmd handler

                return true;
            }

            Logging.RecordError($"Error unhandled cmd {String.Join("", inparams)}");
            return false;

        }





        bool ParseCommandFields(JObject cmd, out string? actualCmd, out int cmdID, out JToken? paramTok)
        {
            actualCmd = "";
            paramTok = null;
            cmdID = -1;

            if (!cmd.TryGetValue("Name", out JToken? nameTok) || nameTok.Type != JTokenType.String)
            {
                Logging.RecordError("Error: Invalid command.");
                return false;
            }
            actualCmd = nameTok.ToString();

            if (!cmd.TryGetValue("CmdID", out JToken? idTok) || idTok.Type != JTokenType.Integer)
            {
                Logging.RecordError("Error: Invalid command ID.");
                return false;
            }
            cmdID = idTok.ToObject<int>();

            if (!cmd.TryGetValue("Paramfield", out paramTok)) paramTok = null;
            return true;
        }

        //todo un-badify this
        void ProcessCommand(JObject cmd)
        {
            if (rgatState.NetworkBridge.GUIMode)
            {
                Logging.RecordError("Error: The GUI sent a tracer-only command.");
                rgatState.NetworkBridge.Teardown("GUI only command");
                return;
            }

            if (!ParseCommandFields(cmd, out string? actualCmd, out int cmdID, out JToken? paramfield))
            {
                rgatState.NetworkBridge.Teardown("Command parse failure");
                return;
            }


            Console.WriteLine("Processing command " + cmd);
            switch (actualCmd)
            {
                case "GetRecentBinaries":
                    rgatSettings.PathRecord[] recentPaths = GlobalConfig.Settings.RecentPaths.Get(rgatSettings.eRecentPathType.Binary);
                    rgatState.NetworkBridge.SendResponseObject(cmdID, recentPaths);
                    break;

                case "DirectoryInfo":
                    rgatState.NetworkBridge.SendResponseJSON(cmdID, GetDirectoryInfo(paramfield));
                    break;

                case "GetDrives":
                    rgatState.NetworkBridge.SendResponseObject(cmdID, rgatFilePicker.FilePicker.GetLocalDriveStrings());
                    break;

                case "UploadSignatures":
                    HandleSignatureUpload(paramfield);
                    //rgatState.NetworkBridge.SendResponseObject(cmdID, rgatFilePicker.FilePicker.GetLocalDriveStrings());
                    break;

                case "StartSigScan":
                    HandleSigScanCommand(paramfield);
                    break;

                case "LoadTarget":
                    JToken response = GatherTargetInitData(paramfield);
                    rgatState.NetworkBridge.SendResponseObject(cmdID, response);
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
                    Logging.RecordError($"Unknown command: {actualCmd} ({cmd})");
                    rgatState.NetworkBridge.Teardown("Bad Command");
                    break;
            }

        }

        void HandleSignatureUpload(JToken paramfield)
        {
            if (rgatState.NetworkBridge.GUIMode)
            {
                Logging.RecordError("Signature upload attempted from tracing host to GUI!");
                rgatState.NetworkBridge.Teardown("Tracing host tried to upload signatures");
                return;
            }

            if (paramfield == null || paramfield.Type is not JTokenType.Object)
            {
                Logging.RecordError("Failed to parse HandleSignatureUpload params");
                return;
            }

            JObject? paramsObj = paramfield.ToObject<JObject>();
            if (paramsObj is null ||
                !paramsObj.TryGetValue("Type", out JToken? typeTok) || typeTok.Type is not JTokenType.String ||
                !paramsObj.TryGetValue("Zip", out JToken? zipTok) || zipTok.Type is not JTokenType.String)
            {
                Logging.RecordError("Bad params for HandleSignatureUpload");
                return;
            }

            byte[]? zipBytes = zipTok.ToObject<byte[]>();
            if (zipBytes is not null)
            {
                string typeName = typeTok.ToString();
                switch (typeName)
                {
                    case "YARA":
                        rgatState.YARALib.ReplaceSignatures(zipBytes);
                        break;
                    case "DIE":
                        rgatState.DIELib.ReplaceSignatures(zipBytes);
                        break;
                    default:
                        Logging.RecordError($"Invalid signature type: {typeName}");
                        break;
                }
            }

        }

        void HandleSigScanCommand(JToken paramfield)
        {
            if (paramfield == null || paramfield.Type is not JTokenType.Object)
            {
                Logging.RecordError("Failed to parse HandleSigScanCommand params");
                return;
            }

            JObject? paramsObj = paramfield.ToObject<JObject>();
            if (paramsObj is null ||
                !paramsObj.TryGetValue("Type", out JToken? typeTok) || typeTok.Type is not JTokenType.String ||
                !paramsObj.TryGetValue("TargetSHA1", out JToken? shaTok) || shaTok.Type is not JTokenType.String)
            {
                Logging.RecordError("Bad params for HandleSigScanCommand");
                return;
            }

            if (!rgatState.targets.GetTargetBySHA1(shaTok.ToString(), out BinaryTarget? target) || target is null)
            {
                Logging.RecordLogEvent($"Tried to start scan for non-existent target hash {shaTok}");
                return;
            }

            bool reload = false;
            if (paramsObj.TryGetValue("Reload", out JToken? reloadtok) && reloadtok.Type == JTokenType.Boolean)
                reload = reloadtok.ToObject<bool>();

            string typeName = typeTok.ToString();
            switch (typeName)
            {
                case "YARA":
                    rgatState.YARALib?.StartYARATargetScan(target, reload: reload);
                    break;
                case "DIE":
                    rgatState.DIELib?.StartDetectItEasyScan(target, reload: reload);
                    break;
                default:
                    Logging.RecordError($"HandleSigScanCommand - Invalid signature type: {typeName}");
                    break;
            }
        }


        void StartHeadlessTrace(JToken paramfield)
        {
            if (paramfield.Type is not JTokenType.Object)
            {
                Logging.RecordError("Failed to parse StartHeadlessTrace params");
                return;
            }
            JObject? paramsObj = paramfield.ToObject<JObject>();
            if (paramsObj is null)
            {
                Logging.RecordError("Bad StartHeadlessTrace params");
                return;
            }

            long testID = -1; string? path = null;
            if (paramsObj.TryGetValue("TestID", out JToken? testIDTok) && testIDTok.Type == JTokenType.Integer)
            {
                testID = testIDTok.ToObject<long>();
            }
            if (paramsObj.TryGetValue("TargetPath", out JToken? pathTok) && pathTok.Type == JTokenType.String)
            {
                path = pathTok.ToString();
                if (!File.Exists(path))
                {
                    Logging.RecordError($"StartHeadlessTrace: Target {path} not found");
                    rgatState.NetworkBridge.Teardown("Target path not found");
                    return;
                }
            }
            else
            {
                Logging.RecordError($"StartHeadlessTrace: No valid target path in trace start request");
                rgatState.NetworkBridge.Teardown("No Target Path");
                return;
            }

            BinaryTarget target = rgatState.targets.AddTargetByPath(path);


            if (target.PEFileObj == null)
            {
                Logging.RecordError($"StartHeadlessTrace: Target could not be parsed as a Windows PE binary");
                rgatState.NetworkBridge.Teardown("Bad Target");
                return;
            }
            string pintool = target.BitWidth == 32 ?
                GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath32) :
                GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath64);

            bool isDLL = target.PEFileObj.IsDll;
            int ordinal = 0;

            if (isDLL && paramsObj.TryGetValue("Ordinal", out JToken? ordTok) && ordTok.Type == JTokenType.Integer)
            {
                ordinal = ordTok.ToObject<int>();
            }

            string? loaderName = null;
            if (isDLL && paramsObj.TryGetValue("LoaderName", out JToken? loaderTok) && loaderTok.Type == JTokenType.String)
            {
                loaderName = loaderTok.ToObject<string>();
            }

            Process? p = ProcessLaunching.StartLocalTrace(pintool, path, target.PEFileObj, loaderName: loaderName, ordinal: ordinal, testID: testID);
            if (p != null)
            {
                rgatState.NetworkBridge.SendLog($"Trace of {path} launched as remote process ID {p.Id}", Logging.LogFilterType.TextAlert);
            }
            else
            {
                rgatState.NetworkBridge.SendLog($"Trace of {path} failed to start", Logging.LogFilterType.TextAlert);
            }
        }



        bool StartThreadIngestWorker(int cmdID, JToken paramfield)
        {
            if (paramfield == null || paramfield.Type is not JTokenType.Object)
            {
                Logging.RecordError("Failed to parse StartThreadIngestWorker params");
                return false;
            }
            JObject? paramObj = paramfield.ToObject<JObject>();


            if (paramObj is not null &&
                paramObj.TryGetValue("TID", out JToken? tidTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("PID", out JToken? pidTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("RID", out JToken? ridTok) && tidTok.Type == JTokenType.Integer &&
                paramObj.TryGetValue("ref", out JToken? refTok) && tidTok.Type == JTokenType.Integer)
            {
                string pipename = ModuleHandlerThread.GetTracePipeName(pidTok.ToObject<uint>(), ridTok.ToObject<long>(), tidTok.ToObject<ulong>());
                Console.WriteLine("Opening pipe " + pipename);
                uint pipeID = RemoteDataMirror.RegisterPipe(pipename);
                NamedPipeServerStream threadListener = new NamedPipeServerStream(pipename, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.None);

                JObject response = new JObject();
                response.Add("Thread#", refTok);
                response.Add("Pipe#", pipeID);


                rgatState.NetworkBridge.SendResponseJSON(cmdID, response);
                threadListener.WaitForConnection();

                PipeTraceIngestThread worker = new PipeTraceIngestThread(null, threadListener, tidTok.ToObject<uint>(), pipeID);

                RemoteDataMirror.RegisterRemotePipe(pipeID, worker, null);
                worker.Begin();

                return true;
            }

            Logging.RecordError("Bad StartThreadIngestWorker params");
            return false;
        }

        readonly JsonLoadSettings _JSONLoadSettings = new JsonLoadSettings() { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error };



        JObject GetDirectoryInfo(JToken dirObj)
        {

            JObject data = new JObject();
            string dir = Environment.CurrentDirectory;
            if (dirObj != null && dirObj.Type is JTokenType.String)
            {
                string dirString = dirObj.ToString();
                if (dirString.Length != 0) dir = dirString.ToString();
            }

            DirectoryInfo dirinfo = new DirectoryInfo(dir);
            data.Add("Current", dir);
            data.Add("CurrentExists", Directory.Exists(dir));
            data.Add("Parent", (dirinfo.Parent != null) ? dirinfo.Parent.FullName : "");
            data.Add("ParentExists", dirinfo.Parent != null && Directory.Exists(dirinfo.Parent.FullName));
            data.Add("Contents", GetDirectoryListing(dir, out string? error));
            data.Add("Error", error);
            return data;
            //rootfolder
        }

        JObject GetDirectoryListing(string param, out string? error)
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
                    Console.WriteLine($"GetDirectoryListing non-unauth exception: {e.Message}");
                }
                error = e.Message;
            }

            JObject result = new JObject();
            result.Add("Files", files);
            result.Add("Dirs", dirs);
            return result;
        }


        JToken GatherTargetInitData(JToken pathTok)
        {
            if (pathTok != null && pathTok.Type == JTokenType.String)
            {
                BinaryTarget target = rgatState.targets.AddTargetByPath(pathTok.ToString());
                rgatState.YARALib.StartYARATargetScan(target);
                rgatState.DIELib.StartDetectItEasyScan(target);
                if (target != null)
                    return (JToken)target.GetRemoteLoadInitData();
            }

            JObject result = new JObject();
            result.Add("Error", "Not Loaded");
            return result;
        }



        bool ParseResponse(string messageJson, out int commandID, out JToken? responseData)
        {
            commandID = -1; responseData = null;
            try
            {
                JObject responseJsn = JObject.Parse(messageJson, _JSONLoadSettings);
                if (!responseJsn.TryGetValue("CommandID", out JToken? cID) || cID == null || cID.Type != JTokenType.Integer)
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

            IPAddress? localBinding = GetLocalAddress();
            if (localBinding == null)
            {
                Logging.RecordError($"Failed to get local address");
                return;
            }

            Logging.RecordLogEvent($"Initialising . {GlobalConfig.StartOptions.ConnectModeAddress}", Logging.LogFilterType.TextDebug);
            if (!GetRemoteAddress(GlobalConfig.StartOptions.ConnectModeAddress, out string? address, out int port))
            {
                Logging.RecordError($"Failed to parse address/port from param {GlobalConfig.StartOptions.ConnectModeAddress}");
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


        bool GetRemoteAddress(string param, out string? address, out int port)
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


        IPAddress? GetLocalAddress()
        {
            IPAddress? result = null;
            if (GlobalConfig.StartOptions.ActiveNetworkInterface == null && GlobalConfig.StartOptions.Interface != null)
            {
                GlobalConfig.StartOptions.ActiveNetworkInterface = NetworkUtilities.ValidateNetworkInterface(GlobalConfig.StartOptions.Interface);
            }

            if (GlobalConfig.StartOptions.ActiveNetworkInterface == null) //user didn't pass a param, or 
            {
                if (IPAddress.TryParse(GlobalConfig.StartOptions.Interface, out IPAddress? address))
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

            IPAddress? localAddr = GetLocalAddress();
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
            NETWORK_MSG[]? incoming = null;
            while (!rgatState.rgatIsExiting)
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
