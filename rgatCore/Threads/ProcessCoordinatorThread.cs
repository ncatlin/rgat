using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace rgat.Threads
{
    public class ProcessCoordinatorThread : TraceProcessorWorker
    {
        byte[] buf = new byte[1024];
        NamedPipeServerStream coordPipe = null;


        public ProcessCoordinatorThread()
        {
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(Listener);
            WorkerThread.Name = $"Coordinator";
            WorkerThread.Start();
        }

        void GotMessage(IAsyncResult ir)
        {

            int bytesRead = coordPipe.EndRead(ir);

            bytesRead = Array.FindIndex(buf, elem => elem == 0);

            if (bytesRead > 0 && bytesRead < 1024)
            {

                string csString = System.Text.Encoding.UTF8.GetString(buf[0..bytesRead]);

                //	"PID,%u,%d,%ld,%s,%ld", pid, arch, instanceID, programName, testRunID
                string[] fields = csString.Split(',');
                Logging.RecordLogEvent($"Coordinator thread read: {bytesRead} bytes, {fields.Length} fields: {fields}", Logging.LogFilterType.TextDebug);

                if (fields.Length == 6)
                {
                    bool success = true;
                    if (fields[0] != "PID") success = false;
                    if (!uint.TryParse(fields[1], out uint PID)) success = false;
                    if (!int.TryParse(fields[2], out int arch)) success = false;
                    if (!long.TryParse(fields[3], out long randno)) success = false;
                    if (!long.TryParse(fields[5], out long testRunID)) success = false;
                    if (success)
                    {
                        string programName = fields[4];
                        string cmdPipeName = ModuleHandlerThread.GetCommandPipeName(PID, randno);
                        string eventPipeName = ModuleHandlerThread.GetEventPipeName(PID, randno);
                        string blockPipeName = BlockHandlerThread.GetBlockPipeName(PID, randno);
                        string response = $"CM@{cmdPipeName}@CR@{eventPipeName}@BB@{blockPipeName}@\x00";
                        byte[] outBuffer = System.Text.Encoding.UTF8.GetBytes(response);
                        coordPipe.Write(outBuffer);
                        Task startTask = Task.Run(() => process_new_pin_connection(PID, arch, randno, programName, testRunID));
                        Logging.RecordLogEvent($"Coordinator connection initiated", Logging.LogFilterType.TextDebug);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Coordinator got bad data from client: " + csString, Logging.LogFilterType.TextError);
                    }
                }
            }

            if (coordPipe.IsConnected) coordPipe.Disconnect();
        }

        void ConnectCallback(IAsyncResult ar)
        {
            NamedPipeServerStream nps = (NamedPipeServerStream)ar.AsyncState;

            try
            {
                nps.EndWaitForConnection(ar);
                Logging.RecordLogEvent($"Incoming connection on coordinator pipe", Logging.LogFilterType.TextDebug);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Coordinator pipe callback exception {e.Message}", Logging.LogFilterType.TextError);
            }

        }


        public void Listener()
        {
            try
            {

                coordPipe = new NamedPipeServerStream(rgatState.LocalCoordinatorPipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.WriteThrough);
            }
            catch (System.IO.IOException e)
            {
                string errmsg = $"Error: Failed to start bootstrap thread '{e.Message}' so rgat will not process incoming traces";
                Logging.RecordLogEvent(errmsg, Logging.LogFilterType.TextAlert);
                //todo: does this happen outside of debugging? if so A: figure out why, B:give visual indication
                return;
            }

            while (!rgatState.RgatIsExiting)
            {
                try
                {
                    AsyncCallback acb = new AsyncCallback(ConnectCallback);
                    IAsyncResult res1 = coordPipe.BeginWaitForConnection(acb, coordPipe);
                }
                catch (System.ExecutionEngineException e)
                {
                    Logging.RecordLogEvent($"PCT::Listener BeginWaitForConnection Execution Engine exception {e.Message}", Logging.LogFilterType.TextError);
                    Thread.Sleep(80);
                    continue;
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"PCT::Listener BeginWaitForConnection exception {e.Message}", Logging.LogFilterType.TextError);
                    Thread.Sleep(80);
                    continue;
                }


                while (!coordPipe.IsConnected)
                {
                    if (rgatState.RgatIsExiting)
                    {
                        Finished();
                        return;
                    }
                    Thread.Sleep(100);
                }


                Logging.RecordLogEvent($"rgatCoordinator pipe connected", Logging.LogFilterType.TextDebug);

                var readres = coordPipe.BeginRead(buf, 0, 1024, new AsyncCallback(GotMessage), null);

                Logging.RecordLogEvent("rgatCoordinator began read", Logging.LogFilterType.TextDebug);

                int mush = WaitHandle.WaitAny(new WaitHandle[] { readres.AsyncWaitHandle }, 2000);

                if (!readres.IsCompleted)
                {
                    Logging.RecordLogEvent("Warning: Read timeout for coordinator connection, abandoning");
                }
                while (coordPipe.IsConnected && !rgatState.RgatIsExiting) Thread.Sleep(5);
            }
            Finished();

        }





        private void process_new_pin_connection(uint PID, int arch, long ID, string programName, long testID = -1)
        {

            string binaryName = Path.GetFileName(programName);
            string shortName = binaryName.Substring(0, Math.Min(binaryName.Length, 20));
            bool isTest = testID > -1;
            string msg;
            if (!isTest)
                msg = $"New instrumentation connection with {arch}-bit trace: {shortName} (PID:{PID})";
            else
                msg = $"New test case connection with {arch}-bit trace: {shortName} (PID:{PID})";

            Logging.RecordLogEvent(msg, Logging.LogFilterType.TextDebug);

            BinaryTarget target;
            if (!rgatState.targets.GetTargetByPath(programName, out target))
            {
                target = _clientState.AddTargetByPath(programName, arch, true);
            }

            if (target.BitWidth != arch)
            {
                if (target.BitWidth != 0)
                {
                    msg = $"Warning: Incoming process reports different arch {arch} to binary {target.BitWidth}";
                    Logging.RecordLogEvent(msg, Logging.LogFilterType.TextError);
                }
                target.BitWidth = arch;
            }

            target.CreateNewTrace(DateTime.Now, PID, (uint)ID, out TraceRecord tr);
            _clientState.IncreaseTraceCount();

            if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode)
            {
                //SpawnTracePipeProxy();

                string pipename = ModuleHandlerThread.GetEventPipeName(tr.PID, tr.randID);
                uint eventPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);
                pipename = ModuleHandlerThread.GetCommandPipeName(tr.PID, tr.randID); 
                uint cmdPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);
                pipename = BlockHandlerThread.GetBlockPipeName(tr.PID, tr.randID); 
                uint blockPipeID = Config.RemoteDataMirror.RegisterPipe(pipename);

                string pipeMessage = $"InitialPipes@C@{cmdPipeID}@E@{eventPipeID}@B@{blockPipeID}";
                rgatState.NetworkBridge.SendTraceMeta(tr, pipeMessage);

                ModuleHandlerThread moduleHandler = new ModuleHandlerThread(target, tr, eventPipeID);
                moduleHandler.RemoteCommandPipeID = cmdPipeID;
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


        public void StartLocalTraceThreads(TraceRecord trace, long testID = -1)
        {
            if (testID != -1)
            {
                trace.SetTestRunID(testID);
                trace.binaryTarg.MarkTestBinary();
                _clientState.RecordTestRunConnection(testID, trace);
            }

            ModuleHandlerThread moduleHandler = new ModuleHandlerThread(trace.binaryTarg, trace);
            trace.ProcessThreads.Register(moduleHandler);
            moduleHandler.Begin();

            trace.RecordTimelineEvent(Logging.eTimelineEvent.ProcessStart, trace);


            BlockHandlerThread blockHandler = new BlockHandlerThread(trace.binaryTarg, trace);
            trace.ProcessThreads.Register(blockHandler);
            blockHandler.Begin();

            ProcessLaunching.launch_new_visualiser_threads(trace.binaryTarg, trace, _clientState);
        }
    }
}
