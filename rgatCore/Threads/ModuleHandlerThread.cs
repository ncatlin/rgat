using Newtonsoft.Json.Linq;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using static rgat.TraceRecord;

namespace rgat
{
    /// <summary>
    /// A worker for processing process and thread events for a trace as well as symbol data and trace commands
    /// </summary>
    public class ModuleHandlerThread : TraceProcessorWorker
    {
        private readonly BinaryTarget target;
        private readonly TraceRecord trace;
        private NamedPipeServerStream? commandPipe = null;
        private NamedPipeServerStream? eventPipe = null;
        private readonly uint? _remoteEventPipeID;
        private uint? _remoteCommandPipeID = null;
        private System.Threading.Tasks.Task? _headlessCommandListener;

        /// <summary>
        /// The pipe ID of the command pipe connected to a remote tracing instance
        /// </summary>
        public uint? RemoteCommandPipeID
        {
            get => _remoteCommandPipeID;
            set
            {
                if (!_remoteCommandPipeID.HasValue)
                {
                    _remoteCommandPipeID = value;
                }
                else
                {
                    throw new InvalidOperationException("Remote command pipe ID has already been set");
                }
            }
        }

        /// <summary>
        /// Action to call when receiving new trace data
        /// </summary>
        /// <param name="buf">data received</param>
        /// <param name="bytesRead">How many bytes were received</param>
        public delegate void ProcessPipeMessageAction(byte[] buf, int bytesRead);

        /// <summary>
        /// Worker for ingesting process trace events and symbol data
        /// </summary>
        /// <param name="binaryTarg">Binary associated with the trace</param>
        /// <param name="runrecord">The trace record being recorded</param>
        /// <param name="remotePipeID">Optional ID of remote pipe</param>
        public ModuleHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, uint? remotePipeID = null)
        {
            target = binaryTarg;
            trace = runrecord;
            _remoteEventPipeID = remotePipeID;

        }

        /// <summary>
        /// Start work
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            ProcessPipeMessageAction param;
            if (_remoteEventPipeID != null)
            {
                if (rgatState.ConnectedToRemote)
                {
                    if (rgatState.NetworkBridge.HeadlessMode)
                    {
                        param = MirrorMessageToUI;
                        WorkerThread = new Thread(PipeEventListener);
                        _headlessCommandListener = System.Threading.Tasks.Task.Run(() => { RemoteCommandListener(); });
                    }
                    else
                    {
                        param = ProcessMessageLocal;
                        WorkerThread = new Thread(RemoteEventListener);
                    }
                    WorkerThread.Name = $"ModuleHandler_Remote_{_remoteEventPipeID}";
                }
                else
                {
                    Logging.RecordLogEvent("Refusing to start block handler with remote pipe without being connected", filter: Logging.LogFilterType.Error);
                    return;
                }
            }
            else
            {
                Debug.Assert(_remoteEventPipeID == null);
                WorkerThread = new Thread(PipeEventListener)
                {
                    Name = $"TraceModuleHandler_{trace.PID}_{trace.randID}"
                };
                param = ProcessMessageLocal;
            }
            WorkerThread.Start(param);
        }

        private string GetTracePipeName(ulong TID) => GetTracePipeName(trace.PID, trace.randID, TID);


        /// <summary>
        /// Derive a pipe name for threads in the instrumentation tool to connect on
        /// </summary>
        /// <param name="PID">Process ID</param>
        /// <param name="randID">Process UniqueID</param>
        /// <param name="TID">Thread ID</param> //probably fine if everything is cleaned up? still need a unique thread ID. todo
        /// <returns></returns>
        public static string GetTracePipeName(uint PID, long randID, ulong TID)
        {
            return "TR" + PID.ToString() + randID.ToString() + TID.ToString();
        }

        private void HandleSymbol(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 5);

            int modnum = int.Parse(fields[1]);
            ulong offset = Convert.ToUInt64(fields[2], 16);
            string name = fields[3];

            trace.DisassemblyData.AddSymbol(modnum, offset, name);
        }

        private void HandleModule(byte[] buf)
        {
            //todo - these are valid in filenames. b64 encode in client? length field would be better with path at end
            //do same for symbol
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 7);
            string path = fields[1];
            try
            {
                if (int.TryParse(fields[2], System.Globalization.NumberStyles.Integer, null, out int localmodnum))
                {
                    ulong start = Convert.ToUInt64(fields[3], 16);
                    ulong end = Convert.ToUInt64(fields[4], 16);
                    trace.DisassemblyData.AddModule(localmodnum, path, start, end, fields[5][0]);
                    return;
                }
            }
            catch { }


            Logging.RecordError($"Bad module data from trace {this.trace.PID}");
            Terminate();

        }

        private void HandleChildProcessMapping(byte[] buf)
        {
            //todo - these are valid in filenames. b64 encode in client? length field would be better with path at end
            //do same for symbol
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 4);

            if (uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint parent) &&
                uint.TryParse(fields[2], System.Globalization.NumberStyles.Integer, null, out uint child))
            {
                if (parent == this.trace.PID)
                {
                    ProcessCoordinatorThread.RegisterIncomingChild(child, trace);
                }
            }
        }


        /// <summary>
        /// Called after a new target thread has been spawned. We can expect it to try to 
        /// connect to the named pipe in dozens of milliseconds
        /// </summary>
        /// <param name="graph"></param>
        private void SpawnPipeTraceProcessorThreads(ProtoGraph graph)
        {
            string pipename = GetTracePipeName(graph.ThreadID);

            Logging.RecordLogEvent($"Opening pipe {pipename} for PID:{graph.TraceData.PID} TID:{graph.ThreadID}", Logging.LogFilterType.Debug);

            NamedPipeServerStream threadListener = new NamedPipeServerStream(pipename, PipeDirection.InOut, 1, PipeTransmissionMode.Byte);

            System.Threading.Tasks.Task waitTask = threadListener.WaitForConnectionAsync(rgatState.ExitToken);

            int attempts = 0;
            while (true)
            {
                //debugging loop
                if (!waitTask.IsCompleted)
                {
                    attempts += 1;
                    if (attempts > 10)
                    {
                        //https://trello.com/c/pqOdlGjc/256-sometimes-traces-just-dont-connect
                        Logging.RecordError($"Pin pipe connection abandoned (known error). Try running the trace again.");
                        graph.TraceData.ProcessThreads.BBthread?.Terminate();
                        foreach (ProtoGraph p in graph.TraceData.ProtoGraphs)
                        {
                            p.TraceProcessor?.Terminate();
                            p.TraceReader?.Terminate();
                        }
                        Terminate();
                        return;
                    }
                    Logging.RecordLogEvent($"Wait task {pipename} not complete - {waitTask.Status}");
                    Thread.Sleep(150);
                }
                else
                {
                    break;
                }

            }
            Logging.RecordLogEvent($"Instrumentation connection to pipe {pipename} for PID:{graph.TraceData.PID} TID:{graph.ThreadID}", Logging.LogFilterType.Debug);

            PlottedGraph MainGraph = new PlottedGraph(graph, _clientState!._GraphicsDevice!);

            graph.TraceReader = new PipeTraceIngestThread(threadListener, graph.ThreadID, graph);
            graph.TraceProcessor = new ThreadTraceProcessingThread(graph);
            graph.TraceReader.Begin();
            graph.TraceProcessor.Begin();

            PreviewRendererThread.AddGraphToPreviewRenderQueue(MainGraph);

            graph.TraceData.RecordTimelineEvent(type: Logging.eTimelineEvent.ThreadStart, graph:
                graph);
            if (!trace.InsertNewThread(graph, MainGraph))
            {
                Logging.WriteConsole("[rgat]ERROR: Trace rendering thread creation failed");
                return;
            }

        }

        private bool SpawnRemoteTraceProcessorThreads(JToken paramsTok)
        {
            if (paramsTok.Type == JTokenType.Object)
            {
                JObject parameters = (JObject)paramsTok;
                if (parameters.TryGetValue("Thread#", out JToken? threadTok) && (threadTok.Type == JTokenType.Integer) &&
                    parameters.TryGetValue("Pipe#", out JToken? pipeTok) && (pipeTok.Type == JTokenType.Integer))
                {
                    ProtoGraph? graph = null;
                    ulong ThreadRef = threadTok.ToObject<ulong>();
                    uint pipeID = pipeTok.ToObject<uint>();
                    lock (_lock)
                    {
                        if (!_pendingPipeThreads.TryGetValue(ThreadRef, out graph) || graph is null)
                        {
                            Logging.RecordLogEvent($"Error: SpawnRemoteTraceProcessorThreads has no pending pipe with ref {ThreadRef}", Logging.LogFilterType.Error);
                            return false;
                        }
                        _pendingPipeThreads.Remove(pipeID);
                    }

                    SocketTraceIngestThread reader = new SocketTraceIngestThread(graph);
                    graph.TraceReader = reader;
                    reader.Begin();

                    graph.TraceProcessor = new ThreadTraceProcessingThread(graph);
                    graph.TraceProcessor.Begin();

                    Config.RemoteDataMirror.RegisterRemotePipe(pipeID, reader, reader.QueueData);

                    graph.TraceData.RecordTimelineEvent(type: Logging.eTimelineEvent.ThreadStart, graph: graph);

                    PlottedGraph? graphPlot = null;
                    if (_clientState!._GraphicsDevice is not null)
                    {
                        graphPlot = new PlottedGraph(graph, _clientState._GraphicsDevice!);
                        PreviewRendererThread.AddGraphToPreviewRenderQueue(graphPlot);
                    }

                    if (!trace.InsertNewThread(graph, graphPlot))
                    {
                        Logging.RecordLogEvent("ERROR: Trace rendering thread creation failed", Logging.LogFilterType.Error);
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }

        private ulong spawnedThreadCount = 0;
        private readonly Dictionary<ulong, ProtoGraph> _pendingPipeThreads = new Dictionary<ulong, ProtoGraph>();

        private void HandleNewThread(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 4);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint TID))
            {
                Logging.RecordError("Bad threadID in new thread");
                return;
            }
            if (!ulong.TryParse(fields[2], System.Globalization.NumberStyles.HexNumber, null, out ulong startAddr))
            {
                Logging.RecordError($"Bad thread start address (ID:{TID})");
                return;
            }

            switch (trace.TraceType)
            {
                case TracingPurpose.eVisualiser:
                    ProtoGraph newProtoGraph = new ProtoGraph(trace, TID, startAddr);
                    if (!rgatState.ConnectedToRemote)
                    {
                        System.Threading.Tasks.Task.Run(() => SpawnPipeTraceProcessorThreads(newProtoGraph));
                    }
                    else
                    {
                        ulong traceRef;
                        lock (_lock)
                        {
                            traceRef = spawnedThreadCount++;
                            _pendingPipeThreads.Add(traceRef, newProtoGraph);
                        }
                        JObject params_ = new JObject
                        {
                            { "TID", TID },
                            { "PID", trace.PID },
                            { "RID", trace.randID },
                            { "ref", traceRef }
                        };
                        rgatState.NetworkBridge.SendCommand("ThreadIngest", trace.randID.ToString() + spawnedThreadCount.ToString(), 
                            SpawnRemoteTraceProcessorThreads, params_);
                    }

                    break;
                case TracingPurpose.eFuzzer:
                    {
                        /*
                        fuzzRun* fuzzinstance = (fuzzRun*)runRecord->fuzzRunPtr;
                        fuzzinstance->notify_new_thread(TID);
                        */
                        break;
                    }
                default:
                    Logging.RecordLogEvent("HandleNewThread Bad Trace Type " + trace.TraceType, Logging.LogFilterType.Error);
                    break;
            }

        }


        private void HandleTerminatedThread(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint TID))
            {
                Logging.RecordLogEvent("Bad thread termination buffer: " + Encoding.ASCII.GetString(buf));
                return;
            }

            ProtoGraph? protoGraph = trace.GetProtoGraphByTID(TID);
            if (protoGraph != null && !protoGraph.Terminated)
            {
                protoGraph.SetTerminated();
            }

            //shouldn't be needed - plotter should get this from the graph
            if (trace.PlottedGraphs.TryGetValue(TID, out PlottedGraph? graph))
            {
                graph.ReplayState = PlottedGraph.REPLAY_STATE.Ended;
                return;
            }

            Logging.RecordLogEvent($"Thread {TID} terminated (no plotted graph)");
        }


        private void HandleTerminatedProcess(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint PID))
            {
                Logging.RecordLogEvent("Bad process termination buffer: " + Encoding.ASCII.GetString(buf));
                return;
            }

            TraceRecord? termTrace = this.trace.GetTraceByID(PID);
            if (termTrace != null)
            {
                termTrace.RecordTimelineEvent(Logging.eTimelineEvent.ProcessEnd, trace);
            }
            else
            {
                Logging.RecordLogEvent($"Process {PID} terminated (no trace)");
            }
        }


        /// <summary>
        /// Send a command the the instrumentation tool in the traced process
        /// </summary>
        /// <param name="cmd">The command text</param>
        /// <returns>Sending succeeded</returns>
        public bool SendCommand(byte[] cmd)
        {
            Debug.Assert(commandPipe != null, "Error: Remote commands not yet implemented"); //todo - remote commands
            if (commandPipe.IsConnected)
            {
                try
                {
                    Console.WriteLine($"Commandpipe outputting async: {ASCIIEncoding.ASCII.GetString(cmd)}");
                    Logging.RecordLogEvent($"controlPipe.BeginWrite with {cmd.Length} bytes: {Encoding.ASCII.GetString(cmd)}", Logging.LogFilterType.Debug);
                    //This is async because the commandPipe can block, hanging the caller
                    System.Threading.Tasks.Task.Run(() => commandPipe.WriteAsync(cmd, 0, cmd.Length, rgatState.ExitToken));
                }
                catch (Exception e)
                {
                    Logging.RecordException($"MH:SendCommand failed with exception {e.Message}", e);
                    return false;
                }

                return true;
            }
            return false;
        }


        private bool CommandWrite(string msg)
        {
            if (_remoteCommandPipeID != null)
            {
                if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.GUIMode)
                {
                    rgatState.NetworkBridge.SendTraceCommand(this._remoteCommandPipeID.Value, msg);
                    return true;
                }
                return false;
            }

            Console.WriteLine($"Commandpipe outputting: {msg}");
            byte[] buf = Encoding.UTF8.GetBytes(msg);
            try { commandPipe!.Write(buf, 0, buf.Length); }
            catch (Exception e)
            {
                Logging.RecordException($"MH:CommandWrite Exception '{e.Message}' while writing command: {msg}", e);
                return false;
            }
            commandPipe.Flush();
            return true;
        }


        private void SendIncludeLists()
        {

            if (!CommandWrite($"INCLUDELISTS\n\x00\x00\x00"))
            {
                return;
            }

            byte[] buf;
            TraceChoiceSettings moduleChoices = target.LaunchSettings.TraceChoices;
            if (moduleChoices.TracingMode == ModuleTracingMode.eDefaultIgnore)
            {
                List<string> tracedDirs = moduleChoices.GetTracedDirs();
                List<string> tracedFiles = moduleChoices.GetTracedFiles();

                if (tracedDirs.Count == 0 && tracedFiles.Count == 0)
                {
                    Logging.RecordLogEvent("Warning: Exclude mode with nothing included. Nothing will be instrumented.");
                }

                foreach (string name in tracedDirs)
                {
                    Logging.RecordLogEvent($"Sending traced directory {name}", Logging.LogFilterType.Debug);
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00"))
                    {
                        return;
                    }
                }
                foreach (string name in tracedFiles)
                {
                    Logging.RecordLogEvent($"Sending traced file {name}", Logging.LogFilterType.Debug);
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@TF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00"))
                    {
                        return;
                    }
                }
            }
            else
            {
                List<string> ignoredDirs = moduleChoices.GetIgnoredDirs();
                List<string> ignoredFiles = moduleChoices.GetIgnoredFiles();

                Logging.RecordLogEvent($"Sending default trace settings: {ignoredDirs.Count} " +
                    $"ignored dirs and {ignoredFiles.Count} ignored files", Logging.LogFilterType.Debug);

                foreach (string name in ignoredDirs)
                {
                    Logging.RecordLogEvent($"Sending ignored dir {name}", Logging.LogFilterType.Debug);
                    buf = Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@ID@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00"))
                    {
                        return;
                    }
                }
                foreach (string name in ignoredFiles)
                {
                    Logging.RecordLogEvent($"Sending ignored file {name}", Logging.LogFilterType.Debug);
                    buf = Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@IF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00"))
                    {
                        return;
                    }
                }
            }

            CommandWrite($"@XX@0@@\n\x00");
        }


        private void SendConfiguration()
        {
            Dictionary<string, string> config = target.LaunchSettings.GetCurrentTraceConfiguration();

            if (!CommandWrite($"CONFIGKEYS@{config.Count}"))
            {
                return;
            }

            foreach (KeyValuePair<string, string> kvp in config)
            {
                string cmdc = $"@CK@{kvp.Key}@{kvp.Value}@\n\x00\x00\x00";
                Logging.RecordLogEvent("MH:SendConfiguration() sending command " + cmdc, Logging.LogFilterType.Debug);
                CommandWrite(cmdc);
            }
        }


        private void SendTraceSettings()
        {
            SendIncludeLists();
            SendConfiguration();
        }


        private void ConnectCallback(IAsyncResult ar)
        {
            string? pipeType = (string?)ar.AsyncState;
            try
            {
                if (pipeType == "Commands")
                {
                    commandPipe!.EndWaitForConnection(ar);
                }
                if (pipeType == "Events")
                {
                    eventPipe!.EndWaitForConnection(ar);
                }
                Logging.RecordLogEvent($"MH:ConnectCallback {pipeType} pipe connected to process PID " + trace.PID, Logging.LogFilterType.Debug);
            }
            catch (Exception e)
            {
                Logging.RecordException($"MH:{pipeType} pipe exception for PID {trace.PID}: + {e.Message}", e);
            }
        }


        private void MirrorMessageToUI(byte[] buf, int bytesRead)
        {
            rgatState.NetworkBridge.SendRawTraceData(_remoteEventPipeID!.Value, buf, bytesRead);
        }


        private void ProcessMessageLocal(byte[] buf, int bytesRead)
        {

            if (bytesRead < 3) //probably pipe ended
            {
                if (bytesRead != 0)
                {
                    Logging.RecordLogEvent($"MH:ReadCallback() Unhandled tiny control pipe message: {BitConverter.ToString(buf)}", Logging.LogFilterType.Error);
                }
                return;
            }

            if (buf[0] == 'T')
            {
                if (buf[1] == 'I')
                {
                    HandleNewThread(buf);
                    return;
                }

                if (buf[1] == 'Z')
                {
                    if (!rgatState.rgatIsExiting)
                    {
                        HandleTerminatedThread(buf);
                    }

                    return;
                }
            }

            if (buf[0] == 's' && buf[1] == '!')
            {
                HandleSymbol(buf);
                return;
            }

            if (buf[0] == 'm' && buf[1] == 'n')
            {
                HandleModule(buf);
                return;
            }

            if (buf[0] == 'c' && buf[1] == 'h')
            {
                HandleChildProcessMapping(buf);
                return;
            }

            if (bytesRead >= 4 && buf[0] == 'D' && buf[1] == 'B' && buf[2] == 'G')
            {
                char dbgCmd = (char)buf[3];
                switch (dbgCmd)
                {
                    case 'b':
                        Logging.RecordLogEvent(text: "Trace entered suspended state due to pingat break event", trace: trace);
                        trace.SetTraceState(ProcessState.eSuspended);
                        break;
                    case 'c':
                        Logging.RecordLogEvent(text: "Trace left suspended state to to pingat continue event", trace: trace);
                        trace.SetTraceState(ProcessState.eRunning);
                        break;
                    default:
                        Logging.RecordLogEvent($"Bad debug command response {dbgCmd}", Logging.LogFilterType.Error);
                        break;
                }
                return;
            }

            if (buf[0] == 'P' && buf[1] == 'X')
            {
                HandleTerminatedProcess(buf);
                return;
            }

            if (buf[0] == '!')
            {
                string text = ASCIIEncoding.ASCII.GetString(buf.Take(bytesRead).ToArray());
                Logging.RecordLogEvent($"!Log from instrumentation: '{text}'", trace: trace);
                if (text.Contains("Thread Connection Failure"))
                {
                    Logging.RecordError("Pin thread connection failure. Terminating trace.");
                }
                //Logging.WriteConsole($"!Log from instrumentation: '{text}'");
                return;
            }

            string errmsg = $"Control pipe read unhandled entry from PID {trace.PID}: {ASCIIEncoding.ASCII.GetString(buf)}";
            Logging.RecordLogEvent(errmsg, Logging.LogFilterType.Error, trace: trace);
        }

        //There is scope to randomise these in case it becomes a detection method, but 
        //there are so many other potential ones I'll wait and see if its needed first


        /// <summary>
        /// Get the pipe that the instrumentation tool will listen on for commands
        /// </summary>
        /// <param name="PID">Traced process ID</param>
        /// <param name="randID">Traced process unique ID</param>
        /// <returns>Command pipe name</returns>
        public static string GetCommandPipeName(uint PID, long randID)
        {
            return "CM" + PID.ToString() + randID.ToString();
        }

        /// <summary>
        /// Get the pipe that the instrumentation tool will send events to
        /// </summary>
        /// <param name="PID">Traced process ID</param>
        /// <param name="randID">Traced process unique ID</param>
        /// <returns>Event pipe name</returns>
        public static string GetEventPipeName(uint PID, long randID)
        {
            return "CR" + PID.ToString() + randID.ToString();
        }

        private readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();

        /// <summary>
        /// Cause the worker to stop processing and disconnect its pipes
        /// </summary>
        public override void Terminate()
        {
            try
            {
                cancelTokens.Cancel();
                if (commandPipe != null && commandPipe.IsConnected)
                {
                    commandPipe.Disconnect();
                }

                if (eventPipe != null && eventPipe.IsConnected)
                {
                    eventPipe.Disconnect();
                }
            }
            catch { return; }

        }

        /// <summary>
        /// Add event data recieved from a remotely traced process
        /// </summary>
        /// <param name="data">event data bytes</param>
        public void AddRemoteEventData(byte[] data)
        {
            lock (_lock)
            {
                _incomingRemoteEvents.Enqueue(data);
                NewDataEvent.Set();
            }
        }

        /// <summary>
        /// Process a trace command sent by the remote GUI
        /// </summary>
        /// <param name="data">bytes of the command</param>
        public void ProcessIncomingTraceCommand(byte[] data)
        {
            lock (_lock)
            {
                if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode)
                {
                    _incomingTraceCommands.Enqueue(ASCIIEncoding.ASCII.GetString(data, 0, data.Length));
                    NewDataEvent.Set();
                }
            }
        }

        private readonly Queue<byte[]> _incomingRemoteEvents = new Queue<byte[]>();
        private readonly Queue<string> _incomingTraceCommands = new Queue<string>();
        private readonly ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);
        private readonly object _lock = new object();

        /// <summary>
        /// This runs in headless mode, taking commands from the UI and passing them to the instrumentation tool
        /// in the target process
        /// </summary>
        private void RemoteCommandListener()
        {
            CancellationToken cancelToken = rgatState.NetworkBridge.CancelToken;
            while (!cancelToken.IsCancellationRequested && (commandPipe == null || commandPipe.IsConnected == false))
            {
                Thread.Sleep(25);
            }

            while (!rgatState.rgatIsExiting)
            {
                string[] newCommands;
                try
                {
                    NewDataEvent.Wait(cancelToken);
                }
                catch (Exception e)
                {
                    if (cancelToken.IsCancellationRequested is false && rgatState.rgatIsExiting is false)
                    {
                        Logging.RecordException($"BlockThread::RemoteCommandListener exception: {e.Message}", e);
                    }
                    break;
                }
                lock (_lock)
                {
                    newCommands = _incomingTraceCommands.ToArray();
                    _incomingTraceCommands.Clear();
                    NewDataEvent.Reset();
                }

                foreach (string item in newCommands)
                {
                    Logging.RecordLogEvent("RemoteCommandListener command:" + System.Text.ASCIIEncoding.ASCII.GetBytes(item), Logging.LogFilterType.Debug);
                    try
                    {
                        SendCommand(System.Text.ASCIIEncoding.ASCII.GetBytes(item));
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Remote command processing exception: {e.Message}", e);
                        rgatState.NetworkBridge.Teardown();
                        base.Finished();
                        return;
                    }
                }
            }
        }

        /// <summary>
        /// This is run by the UI in remote mode, passing trace events to the trace processor
        /// </summary>
        /// <param name="ProcessMessageobj"></param>
        private void RemoteEventListener(object? ProcessMessageobj)
        {
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj!;

            SendTraceSettings();

            byte[][] newEvents;
            while (rgatState.rgatIsExiting is false && this.trace.IsRunning)
            {
                try
                {
                    NewDataEvent.Wait(rgatState.NetworkBridge.CancelToken);
                }
                catch (System.OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    Logging.RecordException($"ModuleThread::RemoteEventListener exception {e.Message}", e);
                    break;
                }
                lock (_lock)
                {
                    newEvents = _incomingRemoteEvents.ToArray();
                    _incomingRemoteEvents.Clear();
                    NewDataEvent.Reset();
                }
                //these come from the remote tracer
                foreach (byte[] item in newEvents)
                {
                    try
                    {
                        ProcessMessage(item, item.Length);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Remote Event processing exception: {e.Message}", e);
                        rgatState.NetworkBridge.Teardown();
                        base.Finished();
                        return;
                    }
                }
                if (!this.trace.IsRunning) break;

                //todo: remote trace termination -> loop exit condition
            }
        }

        private async void PipeEventListener(object? ProcessMessageobj)
        {
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj!;
            string cmdPipeName = GetCommandPipeName(trace.PID, trace.randID);
            string eventPipeName = GetEventPipeName(trace.PID, trace.randID);

            try
            {
                eventPipe = new NamedPipeServerStream(eventPipeName, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 4096, 4096);
                commandPipe = new NamedPipeServerStream(cmdPipeName, PipeDirection.Out, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
                IAsyncResult res1 = eventPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Events");
                commandPipe.WaitForConnection(); //todo async
                //still need that todo done
            }
            catch (System.IO.IOException e)
            {
                Logging.RecordError("IO Exception on ModuleHandlerThreadListener: " + e.Message);
                eventPipe = null;
                Finished();
                return;
            }

            int totalWaited = 0;
            while (!rgatState.rgatIsExiting)
            {
                if (eventPipe.IsConnected & commandPipe.IsConnected)
                {
                    break;
                }

                Thread.Sleep(1000);
                totalWaited += 1000;
                if (totalWaited > 4000)
                {
                    Logging.WriteConsole($"ModuleHandlerThread Awaiting Pipe Connections: Command:{commandPipe.IsConnected}, Event:{eventPipe.IsConnected}, TotalTime:{totalWaited}");
                }
                if (totalWaited > 8000)
                {
                    Logging.RecordError($"Timeout waiting for rgat client sub-connections. ControlPipeConnected:{eventPipe.IsConnected} ");
                    break;
                }
            }

            if (commandPipe.IsConnected && !rgatState.ConnectedToRemote)
            {
                SendTraceSettings();
            }
            trace.SetTraceState(ProcessState.eRunning);


            byte[]? pendingBuf = null;
            const int BufMax = 4096;
            int bytesRead = 0;
            while (!rgatState.rgatIsExiting && eventPipe.IsConnected)
            {
                byte[] buf = new byte[BufMax];
                try
                {
                    bytesRead = await eventPipe.ReadAsync(buf.AsMemory(0, BufMax), cancelTokens.Token);
                }
                catch
                {
                    continue;
                }

                if (bytesRead < 1024)
                {
                    if (pendingBuf != null)
                    {
                        //this is multipart, tack it onto the next fragment
                        bytesRead = pendingBuf.Length + bytesRead;
                        buf = pendingBuf.Concat(buf).ToArray();
                        pendingBuf = null;
                    }
                    //Logging.RecordLogEvent("IncomingMessageCallback: " + Encoding.ASCII.GetString(buf, 0, bytesread), filter: Logging.LogFilterType.BulkDebugLogFile);
                    if (bytesRead > 0)
                    {
                        try
                        {
                            ProcessMessage(buf, bytesRead);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Local Event processing exception: {e.Message}", e);
                            rgatState.NetworkBridge?.Teardown();
                            base.Finished();
                            return;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    //multi-part message, queue this for reassembly
                    pendingBuf = (pendingBuf == null) ? buf : pendingBuf.Concat(buf).ToArray();
                }
            }

            trace.RecordTimelineEvent(Logging.eTimelineEvent.ProcessEnd, trace);


            if (this._remoteEventPipeID is not null)
            {
                string termString = $"PX@{this.trace.PID}@";
                MirrorMessageToUI(Encoding.ASCII.GetBytes(termString), termString.Length);
            }


            bool alldone = false;
            while (!rgatState.rgatIsExiting && !alldone)
            {
                var graphs = trace.GetPlottedGraphs();
                alldone = !graphs.Any(g => g.InternalProtoGraph.TraceProcessor is not null && g.InternalProtoGraph.TraceProcessor.Running);
                if (!alldone)
                {
                    Thread.Sleep(35);
                }
            }

            Logging.RecordLogEvent($"ControlHandler Listener thread exited for PID {trace.PID}", trace: trace);
            Finished();

            if (this.target.IsLibrary)
            {
                System.Threading.Tasks.Task.Run(() => {
                    System.Threading.Tasks.Task.Delay(2500).Wait();
                    rgatState.DeleteStaleLoaders();
                });
            }
        }

    }
}
