﻿using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using static rgatCore.TraceRecord;

namespace rgatCore
{
    class ModuleHandlerThread
    {

        BinaryTarget target;
        TraceRecord trace;
        rgatState _clientState;
        int threadsCount = 0;
        NamedPipeServerStream commandPipe = null;
        NamedPipeServerStream eventPipe = null;
        Thread listenerThread = null;


        public ModuleHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, rgatState clientState)
        {
            target = binaryTarg;
            trace = runrecord;
            _clientState = clientState;
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

            ThreadTraceProcessingThread graph_builder = new ThreadTraceProcessingThread(newProtoGraph);

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
                    Console.WriteLine("[rgat]HandleNewThread Bad Trace Type " + trace.TraceType);
                    break;
            }

        }


        void HandleTerminatedThread(byte[] buf)
        {
            Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(buf));
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 3);
            uint TID = uint.Parse(fields[1], System.Globalization.NumberStyles.Integer);
            Console.WriteLine($"Thread {TID} ended!");

            if (trace.PlottedGraphs[TID].TryGetValue(eRenderingMode.eStandardControlFlow, out PlottedGraph graph))
            {
                graph.internalProtoGraph.Terminated = true;
                graph.ReplayState = PlottedGraph.REPLAY_STATE.eEnded;
            }
        }


        public static string GetCommandPipeName(uint PID, long instanceID)
        {
            return "CM" + PID.ToString() + instanceID.ToString();
        }

        public static string GetEventPipeName(uint PID, long instanceID)
        {
            return "CR" + PID.ToString() + instanceID.ToString();
        }

        public void Begin(long traceID)
        {
            listenerThread = new Thread(new ParameterizedThreadStart(ControlEventListener));
            listenerThread.Name = "ControlThread";
            listenerThread.Start(traceID);
        }


        void WriteCallback(IAsyncResult ar)
        {
            Console.WriteLine("WriteCallback, calling endwrite");
            commandPipe.EndWrite(ar);
            Console.WriteLine("EndWrite done");
        }

        public int SendCommand(byte[] cmd)
        {
            if (commandPipe.IsConnected)
            {
                try
                {
                    Console.WriteLine($"controlPipe.BeginWrite with {cmd.Length} bytes {cmd}");

                    //controlPipe.Write(cmd);
                    //controlPipe.Write();
                    //controlPipe.Flush();
                    IAsyncResult res = commandPipe.BeginWrite(cmd, 0, cmd.Length, WriteCallback, null);
                    Thread.Sleep(500);

                    //res = controlPipe.BeginWrite(Encoding.ASCII.GetBytes("\n"), 0, 1, null, null);
                    //controlPipe.EndWrite(res);

                }
                catch (Exception e)
                {
                    Console.WriteLine($"SendCommand failed with exception {e.Message}");
                    return -1;
                }

                return cmd.Length;
            }
            return -1;
        }


        void SendIncludeLists()
        {
            byte[] buf;
            if (target.traceChoices.TracingMode == eModuleTracingMode.eDefaultIgnore)
            {
                List<string> tracedDirs = target.traceChoices.GetTracedDirs();
                List<string> tracedFiles = target.traceChoices.GetTracedFiles();

                if (tracedDirs.Count == 0 && tracedFiles.Count == 0)
                    Console.WriteLine("Warning: Exclude mode with nothing included. Nothing will be instrumented.");


                foreach (string name in tracedDirs)
                {
                    Console.Write("Sending included dir " + name + "\n");
                    //buf = System.Text.Encoding.Unicode.GetBytes(name);
                    //buf = System.Text.Encoding.Unicode.GetBytes($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    buf = System.Text.Encoding.ASCII.GetBytes($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { commandPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[rgat]Exception '{e.Message}' while sending tracedDir data");
                        return;
                    }
                }
                foreach (string name in tracedFiles)
                {
                    Console.Write("Sending included file " + name + "\n");
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    buf = System.Text.Encoding.ASCII.GetBytes($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { commandPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception '{e.Message}' while sending tracedFile data");
                        return;
                    }
                }
            }
            else
            {
                List<string> ignoredDirs = target.traceChoices.GetIgnoredDirs();
                List<string> ignoredFiles = target.traceChoices.GetIgnoredFiles();

                foreach (string name in ignoredDirs)
                {
                    Console.Write("Sending ignored dir " + name + "\n");

                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    buf = System.Text.Encoding.ASCII.GetBytes($"@ID@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { commandPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[rgat]Exception '{e.Message}' while sending ignored dir data");
                        return;
                    }
                }
                foreach (string name in ignoredFiles)
                {
                    Console.Write("Sending ignored file " + name + "\n");
                    buf = System.Text.Encoding.ASCII.GetBytes(name);
                    buf = System.Text.Encoding.ASCII.GetBytes($"@IF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { commandPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception '{e.Message}' while sending ignored File data");
                        return;
                    }
                }
            }

            buf = System.Text.Encoding.UTF8.GetBytes($"@XX@0@@\x00");
            try { commandPipe.Write(buf, 0, buf.Length); }
            catch (Exception e)
            {
                Console.WriteLine($"Exception '{e.Message}' while finalising ignored File data");
                return;
            }
        }


        void SendTraceSettings()
        {
            SendIncludeLists();
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
                Console.WriteLine($"{pipeType} pipe connected for PID " + trace.PID);
            }
            catch (Exception e)
            {
                Console.WriteLine($"{pipeType} pipe exception for PID " + trace.PID + " :" + e.Message);
            }
        }


        void ReadCallback(IAsyncResult ar)
        {
            int bytesread = 0;
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                bytesread = eventPipe.EndRead(ar);
                //Console.WriteLine($"In ctrl endread cB. br: {bytesread} {Encoding.ASCII.GetString(buf)}");
            }
            catch (Exception e)
            {
                Console.WriteLine("ModuleHandlerThread Readcall back exception " + e.Message);
                return;
            }

            if (bytesread < 3) //probably pipe ended
            {
                if (bytesread != 0)
                    Console.WriteLine($"Unhandled tiny control pipe message: {buf}");
                return;
            }

            if (buf[0] == 'T' && buf[1] == 'I')
            {
                HandleNewThread(buf);
                return;
            }

            if (buf[0] == 'T' && buf[1] == 'Z')
            {

                HandleTerminatedThread(buf);
                return;
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

            if (bytesread >= 4 && buf[0] == 'D' && buf[1] == 'B' && buf[2] == 'G')
            {
                char dbgCmd = (char)buf[3];
                switch (dbgCmd)
                {
                    case 'b':
                        this.trace.SetTraceState(eTraceState.eSuspended);
                        return;
                    case 'c':
                        this.trace.SetTraceState(eTraceState.eRunning);
                        return;
                    default:
                        Console.WriteLine($"Bad debug command response {dbgCmd}");
                        return;
                }
#pragma warning disable CS0162 // Unreachable code detected
                return;
#pragma warning restore CS0162 // Unreachable code detected
            }


            if (buf[0] == '!')
            {
                Console.WriteLine($"[!Log Msg from instrumentation]: {System.Text.ASCIIEncoding.ASCII.GetString(buf)}");
                return;
            }

            Console.WriteLine($"Control pipe read unhandled entry from PID {trace.PID}: {System.Text.ASCIIEncoding.ASCII.GetString(buf)}");
        }


        void ControlEventListener(object instanceID)
        {
            string cmdPipeName = GetCommandPipeName(this.trace.PID, (long)instanceID);
            string eventPipeName = GetEventPipeName(this.trace.PID, (long)instanceID);

            try
            {
                eventPipe = new NamedPipeServerStream(eventPipeName, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 4096, 4096);
                commandPipe = new NamedPipeServerStream(cmdPipeName, PipeDirection.Out, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 4096, 4096);
                IAsyncResult res1 = eventPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Events");
                IAsyncResult res2 = commandPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Commands");
            }
            catch (System.IO.IOException e)
            {
                Console.WriteLine("IO Exception on ModuleHandlerThreadListener: " + e.Message);
                eventPipe = null;
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

            while (!_clientState.rgatIsExiting && eventPipe.IsConnected)
            {
                byte[] buf = new byte[4096 * 4];
                //controlPipe.Read(buf);

                IAsyncResult res = eventPipe.BeginRead(buf, 0, 4096 * 4, new AsyncCallback(ReadCallback), buf);

                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);

                if (!res.IsCompleted)
                {
                    eventPipe.EndRead(res);
                }
            }

            eventPipe.Dispose();
            Console.WriteLine($"ControlHandler Listener thread exited for PID {trace.PID}");
        }

    }
}
