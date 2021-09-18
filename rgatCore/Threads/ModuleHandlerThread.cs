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
    public class ModuleHandlerThread : TraceProcessorWorker
    {

        BinaryTarget target;
        TraceRecord trace;
        NamedPipeServerStream commandPipe = null;
        NamedPipeServerStream eventPipe = null;
        uint? _remoteEventPipeID;
        uint? _remoteCommandPipeID = null;
        System.Threading.Tasks.Task _headlessCommandListener = null;

        public uint? RemoteCommandPipeID
        {
            get => _remoteCommandPipeID;
            set
            {
                if (!_remoteCommandPipeID.HasValue)
                    _remoteCommandPipeID = value;
                else
                    throw new InvalidOperationException("Remote command pipe ID has already been set");
            }
        }

        public delegate void ProcessPipeMessageAction(byte[] buf, int bytesRead);

        public ModuleHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord = null, uint? remotePipeID = null)
        {
            target = binaryTarg;
            trace = runrecord;
            _remoteEventPipeID = remotePipeID;

        }

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
                    Logging.RecordLogEvent("Refusing to start block handler with remote pipe without being connected", filter: Logging.LogFilterType.TextError);
                    return;
                }
            }
            else
            {
                Debug.Assert(_remoteEventPipeID == null);
                WorkerThread = new Thread(PipeEventListener);
                WorkerThread.Name = $"TraceModuleHandler_{trace.PID}_{trace.randID}";
                param = ProcessMessageLocal;
            }
            WorkerThread.Start((object)param);
        }

        private string GetTracePipeName(ulong TID)
        {
          return GetTracePipeName(trace.PID, trace.randID, TID);
        }

        public static string GetTracePipeName(uint PID, long randID, ulong TID)
        {
            return "TR" + PID.ToString() + randID.ToString() + TID.ToString();
        }



        void HandleSymbol(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 5);

            int modnum = int.Parse(fields[1]);
            ulong offset = Convert.ToUInt64(fields[2], 16);
            string name = fields[3];

            trace.DisassemblyData.AddSymbol(modnum, offset, name);
        }


        void HandleModule(byte[] buf)
        {
            //todo - these are valid in filenames. b64 encode in client? length field would be better with path at end
            //do same for symbol
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 7);
            string path = fields[1];
            int localmodnum = int.Parse(fields[2], System.Globalization.NumberStyles.Integer);
            ulong start = Convert.ToUInt64(fields[3], 16);
            ulong end = Convert.ToUInt64(fields[4], 16);
            trace.DisassemblyData.AddModule(localmodnum, path, start, end, fields[5][0]);
        }


        void SpawnPipeTraceProcessorThreads(ProtoGraph graph)
        {
            string pipename = GetTracePipeName(graph.ThreadID);

            Console.WriteLine("Opening pipe " + pipename);
            NamedPipeServerStream threadListener = new NamedPipeServerStream(pipename, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.None);

            Console.WriteLine("Waiting for thread connection... ");
            threadListener.WaitForConnection();
            Console.WriteLine("Trace thread connected");


            PlottedGraph MainGraph = new PlottedGraph(graph, _clientState._GraphicsDevice);

            graph.TraceReader = new PipeTraceIngestThread(graph, threadListener, graph.ThreadID);
            graph.TraceProcessor = new ThreadTraceProcessingThread(graph);
            graph.TraceReader.Begin();
            graph.TraceProcessor.Begin();

            graph.TraceData.RecordTimelineEvent(type: Logging.eTimelineEvent.ThreadStart, graph: graph);
            if (!trace.InsertNewThread(MainGraph))
            {
                Console.WriteLine("[rgat]ERROR: Trace rendering thread creation failed");
                return;
            }

        }


        bool SpawnRemoteTraceProcessorThreads(JToken paramsTok)
        {
            if (paramsTok.Type == JTokenType.Object)
            {
                JObject parameters = (JObject)paramsTok;
                if (parameters.TryGetValue("Thread#", out JToken threadTok) && (threadTok.Type == JTokenType.Integer) &&
                    parameters.TryGetValue("Pipe#", out JToken pipeTok) && (pipeTok.Type == JTokenType.Integer))
                {
                    ProtoGraph graph = null;
                    ulong ThreadRef = threadTok.ToObject<ulong>();
                    uint pipeID = pipeTok.ToObject<uint>();
                    lock (_lock)
                    {
                        if (!_pendingPipeThreads.TryGetValue(ThreadRef, out graph))
                        {
                            Logging.RecordLogEvent($"Error: SpawnRemoteTraceProcessorThreads has no pending pipe with ref {ThreadRef}", Logging.LogFilterType.TextError);
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

                    PlottedGraph MainGraph = new PlottedGraph(graph, _clientState._GraphicsDevice);

                    if (!trace.InsertNewThread(MainGraph))
                    {
                        Logging.RecordLogEvent("ERROR: Trace rendering thread creation failed", Logging.LogFilterType.TextError);
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }

        ulong spawnedThreadCount = 0;
        Dictionary<ulong, ProtoGraph> _pendingPipeThreads = new Dictionary<ulong, ProtoGraph>();

        void HandleNewThread(byte[] buf)
        {
            Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(buf));
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 4);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint TID))
            {
                Logging.RecordError("Bad threadID in new thread");
                return;
            }
            if(!ulong.TryParse(fields[2], System.Globalization.NumberStyles.HexNumber, null, out ulong startAddr))
            {
                Logging.RecordError($"Bad thread start address (ID:{TID})");
                return;
            }
            Console.WriteLine($"Thread {TID} started!");

            switch (trace.TraceType)
            {
                case eTracePurpose.eVisualiser:
                    ProtoGraph newProtoGraph = new ProtoGraph(trace, TID, startAddr);
                    if (!rgatState.ConnectedToRemote)
                        SpawnPipeTraceProcessorThreads(newProtoGraph);
                    else
                    {
                        ulong traceRef;
                        lock (_lock)
                        {
                            traceRef = spawnedThreadCount++;
                            _pendingPipeThreads.Add(traceRef, newProtoGraph);
                        }
                        JObject params_ = new JObject();
                        params_.Add("TID", TID);
                        params_.Add("PID", trace.PID);
                        params_.Add("RID", trace.randID);
                        params_.Add("ref", traceRef);
                        rgatState.NetworkBridge.SendCommand("ThreadIngest", trace.randID.ToString()+ spawnedThreadCount.ToString(), SpawnRemoteTraceProcessorThreads, params_);
                    }

                    break;
                case eTracePurpose.eFuzzer:
                    {
                        /*
                        fuzzRun* fuzzinstance = (fuzzRun*)runRecord->fuzzRunPtr;
                        fuzzinstance->notify_new_thread(TID);
                        */
                        break;
                    }
                default:
                    Logging.RecordLogEvent("HandleNewThread Bad Trace Type " + trace.TraceType, Logging.LogFilterType.TextError);
                    break;
            }

        }


        void HandleTerminatedThread(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint TID))
            {
                Logging.RecordLogEvent("Bad thread termination buffer: " + Encoding.ASCII.GetString(buf));
                return;
            }

            ProtoGraph protoGraph = trace.GetProtoGraphByID(TID);
            if (protoGraph != null && !protoGraph.Terminated)
            {
                protoGraph.SetTerminated();
            }

            //shouldn't be needed - plotter should get this from the graph
            if (trace.PlottedGraphs.TryGetValue(TID, out PlottedGraph graph))
            {
                graph.ReplayState = PlottedGraph.REPLAY_STATE.eEnded;
                return;
            }

            Logging.RecordLogEvent($"Thread {TID} terminated (no plotted graph)");
        }

        void HandleTerminatedProcess(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            if (!uint.TryParse(fields[1], System.Globalization.NumberStyles.Integer, null, out uint PID))
            {
                Logging.RecordLogEvent("Bad process termination buffer: " + Encoding.ASCII.GetString(buf));
                return;
            }

            TraceRecord termTrace = this.trace.GetTraceByID(PID);
            if (termTrace != null)
            {
                termTrace.RecordTimelineEvent(Logging.eTimelineEvent.ProcessEnd, trace);
            }
            else
            {
                Logging.RecordLogEvent($"Process {PID} terminated (no trace)");
            }
        }








        public bool SendCommand(byte[] cmd)
        {
            Debug.Assert(commandPipe != null, "Error: Remote commands not yet implemented"); //todo - remote commands
            if (commandPipe.IsConnected)
            {
                try
                {
                    Console.WriteLine($"controlPipe.BeginWrite with {cmd.Length} bytes {Encoding.ASCII.GetString(cmd)}");
                    commandPipe.Write(cmd, 0, cmd.Length);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"MH:SendCommand failed with exception {e.Message}");
                    return false;
                }

                return true;
            }
            return false;
        }

        bool CommandWrite(string msg)
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


            byte[] buf = Encoding.UTF8.GetBytes(msg);
            try { commandPipe.Write(buf, 0, buf.Length); }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"MH:CommandWrite Exception '{e.Message}' while writing command: {msg}");
                return false;
            }
            commandPipe.Flush();
            return true;
        }

        void SendIncludeLists()
        {

            if (!CommandWrite($"INCLUDELISTS\n\x00\x00\x00")) return;

            byte[] buf;
            if (target.traceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
            {
                List<string> tracedDirs = target.traceChoices.GetTracedDirs();
                List<string> tracedFiles = target.traceChoices.GetTracedFiles();

                if (tracedDirs.Count == 0 && tracedFiles.Count == 0)
                {
                    Logging.RecordLogEvent("Warning: Exclude mode with nothing included. Nothing will be instrumented.");
                }

                foreach (string name in tracedDirs)
                {
                    Logging.RecordLogEvent($"Sending traced directory {name}", Logging.LogFilterType.TextDebug);
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00")) return;
                }
                foreach (string name in tracedFiles)
                {
                    Logging.RecordLogEvent($"Sending traced file {name}", Logging.LogFilterType.TextDebug);
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@TF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00")) return;
                }
            }
            else
            {
                List<string> ignoredDirs = target.traceChoices.GetIgnoredDirs();
                List<string> ignoredFiles = target.traceChoices.GetIgnoredFiles();

                foreach (string name in ignoredDirs)
                {
                    Logging.RecordLogEvent($"Sending ignored dir {name}", Logging.LogFilterType.TextDebug);
                    buf = Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@ID@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00")) return;
                }
                foreach (string name in ignoredFiles)
                {
                    Logging.RecordLogEvent($"Sending ignored file {name}", Logging.LogFilterType.TextDebug);
                    buf = Encoding.ASCII.GetBytes(name);
                    if (!CommandWrite($"@IF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00")) return;
                }
            }

            CommandWrite($"@XX@0@@\n\x00");
        }

        void SendConfiguration()
        {
            Dictionary<string, string> config = target.GetCurrentTraceConfiguration();

            if (!CommandWrite($"CONFIGKEYS@{config.Count}")) return;
            foreach (KeyValuePair<string, string> kvp in config)
            {
                string cmdc = $"@CK@{kvp.Key}@{kvp.Value}@\n\x00\x00\x00";
                Logging.RecordLogEvent("MH:SendConfiguration() sending command " + cmdc, Logging.LogFilterType.TextDebug);
                CommandWrite(cmdc);
            }
        }


        void SendTraceSettings()
        {
            SendIncludeLists();
            SendConfiguration();
        }



        void ConnectCallback(IAsyncResult ar)
        {
            string pipeType = (string)ar.AsyncState;
            try
            {
                if (pipeType == "Commands")
                {
                    commandPipe.EndWaitForConnection(ar);
                }
                if (pipeType == "Events")
                {
                    eventPipe.EndWaitForConnection(ar);
                }
                Logging.RecordLogEvent($"MH:ConnectCallback {pipeType} pipe connected to process PID " + trace.PID, Logging.LogFilterType.TextDebug);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"MH:{pipeType} pipe exception for PID {trace.PID}: + {e.Message}");
            }
        }


        void MirrorMessageToUI(byte[] buf, int bytesRead)
        {
            rgatState.NetworkBridge.SendRawTraceData(_remoteEventPipeID.Value, buf, bytesRead);
        }

        void ProcessMessageLocal(byte[] buf, int bytesRead)
        {

            if (bytesRead < 3) //probably pipe ended
            {
                if (bytesRead != 0)
                {
                    Logging.RecordLogEvent($"MH:ReadCallback() Unhandled tiny control pipe message: {buf}", Logging.LogFilterType.TextError);
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
                    if (!rgatState.rgatIsExiting) HandleTerminatedThread(buf);

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

            if (bytesRead >= 4 && buf[0] == 'D' && buf[1] == 'B' && buf[2] == 'G')
            {
                char dbgCmd = (char)buf[3];
                switch (dbgCmd)
                {
                    case 'b':
                        Logging.RecordLogEvent(text: "Trace entered suspended state to to pingat break event", trace: trace);
                        trace.SetTraceState(eTraceState.eSuspended);
                        break;
                    case 'c':
                        Logging.RecordLogEvent(text: "Trace left suspended state to to pingat continue event", trace: trace);
                        trace.SetTraceState(eTraceState.eRunning);
                        break;
                    default:
                        Logging.RecordLogEvent($"Bad debug command response {dbgCmd}", Logging.LogFilterType.TextError);
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
                Console.WriteLine($"!Log from instrumentation: '{text}'");
                return;
            }

            string errmsg = $"Control pipe read unhandled entry from PID {trace.PID}: {ASCIIEncoding.ASCII.GetString(buf)}";
            Logging.RecordLogEvent(errmsg, Logging.LogFilterType.TextError, trace: trace);
        }

        //There is scope to randomise these in case it becomes a detection method, but 
        //there are so many other potential ones I'll wait and see if its needed first
        public static string GetCommandPipeName(uint PID, long randID)
        {
            return "CM" + PID.ToString() + randID.ToString();
        }

        public static string GetEventPipeName(uint PID, long randID)
        {
            return "CR" + PID.ToString() + randID.ToString();
        }

        CancellationTokenSource cancelTokens = new CancellationTokenSource();

        public void Terminate()
        {
            try
            {
                cancelTokens.Cancel();
                if (commandPipe != null && commandPipe.IsConnected)
                    commandPipe.Disconnect();
                if (eventPipe != null && eventPipe.IsConnected)
                    eventPipe.Disconnect();
            }
            catch { return; }

        }

        public void AddRemoteEventData(byte[] data, int startIndex)
        {
            lock (_lock)
            {
                _incomingRemoteEvents.Enqueue(data);
                NewDataEvent.Set();
            }
        }

        public void ProcessIncomingTraceCommand(byte[] data, int startIndex)
        {
            lock (_lock)
            {
                if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode)
                {
                    _incomingTraceCommands.Enqueue(ASCIIEncoding.ASCII.GetString(data, startIndex, data.Length - startIndex));
                    NewDataEvent.Set();
                }
            }
        }


        Queue<byte[]> _incomingRemoteEvents = new Queue<byte[]>();
        Queue<string> _incomingTraceCommands = new Queue<string>();
        ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);
        readonly object _lock = new object();

        /// <summary>
        /// This runs in headless mode, taking commands from the UI and passing them to the instrumentation tool
        /// in the target process
        /// </summary>
        void RemoteCommandListener()
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
                    Logging.RecordError($"BlockThread::RemoteCommandListener exception {e.Message}");
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
                    try
                    {
                        SendCommand(System.Text.ASCIIEncoding.ASCII.GetBytes(item));
                    }
                    catch (Exception e)
                    {
                        Logging.RecordError($"Remote command processing exception: {e}");
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
        void RemoteEventListener(object ProcessMessageobj)
        {
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj;

            SendTraceSettings();

            byte[][] newEvents;
            while (!rgatState.rgatIsExiting)
            {
                try
                {
                    NewDataEvent.Wait(rgatState.NetworkBridge.CancelToken);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"BlockThread::RemoteEventListener exception {e.Message}");
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
                        Logging.RecordError($"Remote Event processing exception: {e}");
                        rgatState.NetworkBridge.Teardown();
                        base.Finished();
                        return;
                    }
                }


                //todo: remote trace termination -> loop exit condition
            }
        }





        async void PipeEventListener(object ProcessMessageobj)
        {
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj;
            string cmdPipeName = GetCommandPipeName(trace.PID, trace.randID);
            string eventPipeName = GetEventPipeName(trace.PID, trace.randID);

            try
            {
                eventPipe = new NamedPipeServerStream(eventPipeName, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 4096, 4096);
                commandPipe = new NamedPipeServerStream(cmdPipeName, PipeDirection.Out, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
                IAsyncResult res1 = eventPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Events");
                commandPipe.WaitForConnection();
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
                if (eventPipe.IsConnected & commandPipe.IsConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Awaiting Pipe Connections: Command:{commandPipe.IsConnected}, Event:{eventPipe.IsConnected}, TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. ControlPipeConnected:{eventPipe.IsConnected} ");
                    break;
                }
            }

            if (commandPipe.IsConnected && !rgatState.ConnectedToRemote)
            {
                SendTraceSettings();
            }


            byte[] pendingBuf = null;
            const int BufMax = 4096;
            int bytesRead = 0;
            while (!rgatState.rgatIsExiting && eventPipe.IsConnected)
            {
                byte[] buf = new byte[BufMax];
                try
                {
                    bytesRead = await eventPipe.ReadAsync(buf, 0, BufMax, cancelTokens.Token);
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
                            Logging.RecordError($"Local Event processing exception: {e}");
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

            bool alldone = false;
            while (!rgatState.rgatIsExiting && !alldone)
            {
                var graphs = trace.GetPlottedGraphs();
                alldone = !graphs.Any(g => g.InternalProtoGraph.TraceProcessor.Running);
                if (!alldone) Thread.Sleep(35);
            }

            Logging.RecordLogEvent($"ControlHandler Listener thread exited for PID {trace.PID}", trace: trace);
            Finished();
        }

    }
}
