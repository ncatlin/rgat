using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace rgat.Threads
{
    /// <summary>
    /// Listens for connections from new processes and spawns workers to handle them
    /// </summary>
    public class ProcessCoordinatorThread : TraceProcessorWorker
    {
        private readonly byte[] buf = new byte[CONSTANTS.TRACING.InitialExchangeSize];
        private NamedPipeServerStream? coordPipe = null;
        private static readonly object _lock = new();
        private static readonly Dictionary<uint, TraceRecord> _pendingProcessMappings = new();

        /// <summary>
        /// Start work
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(Listener)
            {
                Name = $"Coordinator"
            };
            WorkerThread.Start();
        }

        private void GotMessage(IAsyncResult ir)
        {

            int bytesRead = coordPipe!.EndRead(ir);

            bytesRead = Array.FindIndex(buf, elem => elem == 0);

            if (bytesRead > 0 && bytesRead < CONSTANTS.TRACING.InitialExchangeSize)
            {

                string csString = System.Text.Encoding.UTF8.GetString(buf[0..bytesRead]);

                //	"PID, rgat version, pid, arch, libraryFlag, instanceID, programName, testRunID
                string[] fields = csString.Split('@');
                const int expectedFieldCount = 8;
                Logging.RecordLogEvent($"Coordinator thread read: {bytesRead} bytes, {fields.Length} fields: {fields}", Logging.LogFilterType.Debug);

                //sanity check pintool version. don't error if wrong, but the user will know why it failed if it fails
                if (fields.Length > 1)
                {
                    if (!Version.TryParse(fields[1], out Version? versionResult) || versionResult is null)
                    {
                        Logging.RecordError("Unable to parse version of incoming trace");
                    }
                    else if (versionResult != CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC)
                    {
                        Logging.RecordError($"Incoming trace version {versionResult} mismatch with expected {CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC}");
                    }
                }

                if (fields.Length == expectedFieldCount)
                {
                    bool success = true;
                    if (fields[0] != "PID")
                    {
                        success = false;
                    }



                    if (!uint.TryParse(fields[2], out uint PID))
                    {
                        success = false;
                    }

                    if (!int.TryParse(fields[3], out int arch))
                    {
                        success = false;
                    }

                    if (!int.TryParse(fields[4], out int libraryFlag))
                    {
                        success = false;
                    }

                    if (!long.TryParse(fields[5], out long randno))
                    {
                        success = false;
                    }

                    if (!long.TryParse(fields[7], out long testRunID))
                    {
                        success = false;
                    }

                    if (success)
                    {
                        string programName = fields[6];
                        if (libraryFlag == 1)
                        {
                            programName = programName.Split(',')[0];
                        }

                        string cmdPipeName = ModuleHandlerThread.GetCommandPipeName(PID, randno);
                        string eventPipeName = ModuleHandlerThread.GetEventPipeName(PID, randno);
                        string blockPipeName = BlockHandlerThread.GetBlockPipeName(PID, randno);

                        string response = $"CM@{cmdPipeName}@CR@{eventPipeName}@BB@{blockPipeName}@\x00";
                        try
                        {
                            coordPipe.Write(System.Text.Encoding.UTF8.GetBytes(response));

                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Failed to write to coordinator pipe: {e.Message}", e);
                            if (coordPipe.IsConnected) coordPipe.Disconnect();
                            return;
                        }

                        Task startTask = Task.Run(() => ProcessNewPinConnection(PID, arch, libraryFlag == 1, randno, programName, testRunID));
                        Logging.RecordLogEvent($"Coordinator connection initiated", Logging.LogFilterType.Debug);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Coordinator got bad data from client: " + csString, Logging.LogFilterType.Error);
                    }
                }
            }

            if (coordPipe.IsConnected)
            {
                coordPipe.Disconnect();
            }
        }

        private void ConnectCallback(IAsyncResult ar)
        {
            NamedPipeServerStream? nps = (NamedPipeServerStream?)ar.AsyncState;

            try
            {
                nps!.EndWaitForConnection(ar);
                Logging.RecordLogEvent($"Incoming connection on coordinator pipe", Logging.LogFilterType.Debug);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Coordinator pipe callback exception {e.Message}", e);
            }

        }

        /// <summary>
        /// The actual listener function
        /// </summary>
        public void Listener()
        {
            try
            {

                coordPipe = new NamedPipeServerStream(rgatState.LocalCoordinatorPipeName!, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
            }
            catch (System.IO.IOException e)
            {
                string errmsg = $"Error: Failed to start bootstrap thread '{e.Message}' so rgat will not process incoming traces";
                Logging.RecordLogEvent(errmsg, Logging.LogFilterType.Alert);
                //todo: does this happen outside of debugging? if so A: figure out why, B:give visual indication
                return;
            }

            while (!rgatState.rgatIsExiting)
            {
                try
                {
                    AsyncCallback acb = new AsyncCallback(ConnectCallback);
                    IAsyncResult res1 = coordPipe.BeginWaitForConnection(acb, coordPipe);
                }
                catch (Exception e)
                {
                    Logging.RecordException($"PCT::Listener BeginWaitForConnection exception {e.Message}", e);
                    Thread.Sleep(80);
                    continue;
                }


                while (!coordPipe.IsConnected)
                {
                    if (rgatState.rgatIsExiting)
                    {
                        Logging.RecordLogEvent("rgat exited before the coordinator connection completed", Logging.LogFilterType.Debug);
                        Finished();
                        return;
                    }
                    Thread.Sleep(100);
                }

                try
                {
                    Logging.RecordLogEvent($"rgatCoordinator pipe connected", Logging.LogFilterType.Debug);

                    var readres = coordPipe.BeginRead(buf, 0, CONSTANTS.TRACING.InitialExchangeSize, new AsyncCallback(GotMessage), null);

                    Logging.RecordLogEvent("rgatCoordinator began read", Logging.LogFilterType.Debug);

                    _ = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

                    if (!readres.IsCompleted)
                    {
                        Logging.RecordLogEvent("Warning: Read timeout for coordinator connection, abandoning");
                    }

                    int connectionMax = 0;
                    while (coordPipe.IsConnected && !rgatState.rgatIsExiting)
                    {
                        connectionMax += 5;
                        Thread.Sleep(5);
                        if (connectionMax > 1000)
                        {
                            Logging.RecordError("Trace connection took too long to negotiate. Terminating it.");
                            coordPipe.Disconnect();
                        }
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordException($"Trace connection experienced an unknown error: {e.Message}", e);
                    if (coordPipe.IsConnected)
                    {
                        coordPipe.Disconnect();
                    }
                }
            }
            Finished();

        }


        private static void ProcessNewPinConnection(uint PID, int arch, bool isLibrary, long ID, string programName, long testID = -1)
        {

            string binaryName = Path.GetFileName(programName);
            string shortName = binaryName.Substring(0, Math.Min(binaryName.Length, 20));
            bool isTest = testID > -1;
            string msg = $"New {(isTest ? "test case" : "instrumentation")} connection with {arch}-bit trace: {shortName} (PID:{PID})";

            Logging.RecordLogEvent(msg, Logging.LogFilterType.Debug);

            BinaryTarget? target;
            if (!rgatState.targets.GetTargetByPath(path: programName, out target) || target is null)
            {
                target = rgatState.AddTargetByPath(path: programName, arch: arch, isLibrary: isLibrary, makeActive: true);
            }

            if (target.BitWidth != arch)
            {
                if (target.BitWidth != 0)
                {
                    msg = $"Warning: Incoming process reports different arch {arch} to binary {target.BitWidth}";
                    Logging.RecordLogEvent(msg, Logging.LogFilterType.Error);
                }
                target.BitWidth = arch;
            }

            target.CreateNewTrace(DateTime.Now, PID, (uint)ID, out TraceRecord tr, testID: testID);


            lock (_lock)
            {
                if (_pendingProcessMappings.TryGetValue(PID, out TraceRecord? parent))
                {
                    Logging.RecordLogEvent($"New Trace: {PID} - {tr.Target.FileName} [parent: {parent.PID} - {parent.Target.FileName}]", Logging.LogFilterType.Alert);
                    parent.AddChildTrace(tr);
                    _pendingProcessMappings.Remove(PID);
                }
                else
                {
                    Logging.RecordLogEvent($"New Trace: {PID} - {tr.Target.FileName}", Logging.LogFilterType.Alert);
                }
            }

            if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode)
            {
                //SpawnTracePipeProxy();
                if (!target.RemoteInitDataSent)
                {
                    Newtonsoft.Json.Linq.JObject newTarget = new();
                    newTarget.Add("Path", target.FilePath);
                    newTarget.Add("InitData", target.GetRemoteLoadInitData(requested: false));
                    rgatState.NetworkBridge.SendAsyncData("ChildBinary", newTarget);
                }

                string pipename = ModuleHandlerThread.GetEventPipeName(tr.PID, tr.randID);
                uint eventPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);
                pipename = ModuleHandlerThread.GetCommandPipeName(tr.PID, tr.randID);
                uint cmdPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);
                pipename = BlockHandlerThread.GetBlockPipeName(tr.PID, tr.randID);
                uint blockPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);

                string pipeMessage = $"InitialPipes@C@{cmdPipeID}@E@{eventPipeID}@B@{blockPipeID}";
                rgatState.NetworkBridge.SendTraceMeta(tr, pipeMessage);

                ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, eventPipeID)
                {
                    RemoteCommandPipeID = cmdPipeID
                };
                Config.RemoteDataMirror.RegisterRemotePipe(cmdPipeID, moduleHandler, moduleHandler.ProcessIncomingTraceCommand);
                tr.ProcessThreads.Register(moduleHandler);
                moduleHandler.Begin();

                BlockHandlerThread blockHandler = new BlockHandlerThread(target, tr, blockPipeID);
                tr.ProcessThreads.Register(blockHandler);
                blockHandler.Begin();

            }
            else
            {
                StartLocalTraceThreads(tr, testID);
            }
        }


        /// <summary>
        /// Launch threads to handle a trace running on the local system
        /// </summary>
        /// <param name="trace">The running trace</param>
        /// <param name="testID">Optional test ID if the trace is a test</param>
        public static void StartLocalTraceThreads(TraceRecord trace, long testID = -1)
        {
            System.Diagnostics.Debug.Assert(_clientState is not null);
            if (testID != -1)
            {
                trace.Target.MarkTestBinary();
                _clientState!.RecordTestRunConnection(testID, trace);
            }

            ModuleHandlerThread moduleHandler = new ModuleHandlerThread(trace.Target, trace);
            trace.ProcessThreads.Register(moduleHandler);
            moduleHandler.Begin();

            trace.RecordTimelineEvent(Logging.eTimelineEvent.ProcessStart, trace);


            BlockHandlerThread blockHandler = new BlockHandlerThread(trace.Target, trace);
            trace.ProcessThreads.Register(blockHandler);
            blockHandler.Begin();
        }


        /// <summary>
        /// Note a parent->child process creation relationship for use when the child connects
        /// </summary>
        /// <param name="child">Child process ID</param>
        /// <param name="parent">Parent Trace</param>
        public static void RegisterIncomingChild(uint child, TraceRecord parent)
        {
            lock (_lock)
            {
                _pendingProcessMappings[child] = parent;
            }
        }
    }
}
