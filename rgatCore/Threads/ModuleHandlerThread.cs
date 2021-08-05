using rgat.Threads;
using System;
using System.Collections.Generic;
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

        public ModuleHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord)
        {
            target = binaryTarg;
            trace = runrecord;
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ControlEventListener);
            WorkerThread.Name = $"TraceModuleHandler_{trace.PID}_{trace.randID}";
            WorkerThread.Start();
        }

        private string GetTracePipeName(ulong TID)
        {
            return "TR" + trace.PID.ToString() + trace.randID.ToString() + TID.ToString();
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


        void HandleNewVisualiserThread(uint TID)
        {
            string pipename = GetTracePipeName(TID);

            Console.WriteLine("Opening pipe " + pipename);
            NamedPipeServerStream threadListener = new NamedPipeServerStream(pipename, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.None);

            Console.WriteLine("Waiting for thread connection... ");
            threadListener.WaitForConnection();
            Console.WriteLine("Trace thread connected");

            ProtoGraph newProtoGraph = new ProtoGraph(trace, TID);
            if (!_clientState.CreateNewPlottedGraph(newProtoGraph, out PlottedGraph MainGraph))
            {
                Console.WriteLine("ERROR: Failed to create plotted graphs for new thread, abandoning");
                return;
            }

            newProtoGraph.TraceReader = new ThreadTraceIngestThread(newProtoGraph, threadListener);
            newProtoGraph.TraceProcessor = new ThreadTraceProcessingThread(newProtoGraph);
            newProtoGraph.TraceReader.Begin();
            newProtoGraph.TraceProcessor.Begin();

            newProtoGraph.TraceData.RecordTimelineEvent(type: Logging.eTimelineEvent.ThreadStart, graph: newProtoGraph);
            if (!trace.InsertNewThread(MainGraph))
            {
                Console.WriteLine("[rgat]ERROR: Trace rendering thread creation failed");
                return;
            }

        }


        void HandleNewThread(byte[] buf)
        {
            Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(buf));
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            uint TID = uint.Parse(fields[1], System.Globalization.NumberStyles.Integer);
            Console.WriteLine($"Thread {TID} started!");



            switch (trace.TraceType)
            {
                case eTracePurpose.eVisualiser:
                    HandleNewVisualiserThread(TID);
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








        public int SendCommand(byte[] cmd)
        {
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
                    return -1;
                }

                return cmd.Length;
            }
            return -1;
        }

        bool CommandWrite(string msg)
        {
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


        void ProcessMessage(byte[] buf, int bytesRead)
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
                    if (!_clientState.rgatIsExiting) HandleTerminatedThread(buf);

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

        async void ControlEventListener(object instanceID)
        {
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
                Logging.RecordLogEvent("IO Exception on ModuleHandlerThreadListener: " + e.Message);
                eventPipe = null;
                Finished();
                return;
            }

            int totalWaited = 0;
            while (!_clientState.rgatIsExiting)
            {
                if (eventPipe.IsConnected & commandPipe.IsConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Waiting ControlPipeConnected:{eventPipe.IsConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. ControlPipeConnected:{eventPipe.IsConnected} ");
                    break;
                }
            }

            if (commandPipe.IsConnected)
            {
                SendTraceSettings();
            }


            byte[] pendingBuf = null;
            const int BufMax = 4096;
            int bytesRead = 0;
            while (!_clientState.rgatIsExiting && eventPipe.IsConnected)
            {
                byte[] buf = new byte[BufMax];
                //controlPipe.Read(buf);
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
                        ProcessMessage(buf, bytesRead);
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
            while (!_clientState.rgatIsExiting && !alldone)
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
