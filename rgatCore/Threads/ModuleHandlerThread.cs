using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class ModuleHandlerThread
    {

        BinaryTarget target;
        TraceRecord trace;
        rgatState _clientState;
        int threadsCount = 0;
        ulong instanceID = 0;
        NamedPipeServerStream controlPipe = null;
        List<IAsyncResult> pipeWaits = new List<IAsyncResult>();
        Thread listenerThread = null;


        public ModuleHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, rgatState clientState, ulong IDno)
        {
            target = binaryTarg;
            trace = runrecord;
            _clientState = clientState;
            instanceID = IDno;

        }



        private string GetTracePipeName()
        {
            return "TR" + trace.PID.ToString() + threadsCount.ToString() + instanceID.ToString();
        }


        void ConnectCallback(IAsyncResult ar)
        {
            Console.WriteLine("CONNCALLbk");
            string pipeName = (String)ar.AsyncState;

            if (pipeName == "Control")
            {

                try
                {
                    controlPipe.EndWaitForConnection(ar);
                    Console.WriteLine("Control pipe connected for PID " + trace.PID);
                }
                catch (Exception e)
                {

                }
            }
        }

         

        void HandleSymbol(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@',5);

            int modnum = int.Parse(fields[1]);
            ulong offset = Convert.ToUInt64(fields[2], 16);
            string name = fields[3];

            trace.DisassemblyData.AddSymbol(modnum, offset, name);
        }

        void HandleModule(byte[] buf)
        {
            string[] fields = Encoding.ASCII.GetString(buf).Split('@', 6);

            Console.WriteLine(fields);
            string path = fields[1];
            int modnum = int.Parse(fields[2]);
            ulong start = Convert.ToUInt64(fields[3], 16);
            ulong end = Convert.ToUInt64(fields[4], 16);
            trace.DisassemblyData.AddModule(modnum, path, start, end);


        }



        void ReadCallback(IAsyncResult ar)
        {
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                controlPipe.EndRead(ar);
            }
            catch (Exception e)
            {
                Console.WriteLine("Readcall back exception " + e.Message);
                return;
            }

            if (buf[0] == 'T' && buf[1] == 'I')
            {
                Console.WriteLine("New Thread!");
                return;
            }

            if (buf[0] == 's' && buf[1] == '!')
            {
                HandleSymbol(buf);
                return;
            }

            if (buf[0] == 'm' && buf[1] == 'n')
            {
                Console.WriteLine("New Module! "+ System.Text.ASCIIEncoding.ASCII.GetString(buf));
                HandleModule(buf);
                return;
            }

            Console.WriteLine("Control pipe read unhandled entry from PID " + trace.PID);
            Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(buf));
        }

        public void Begin(string controlPipeName)
        {

            listenerThread = new Thread(new ParameterizedThreadStart(Listener));

            listenerThread.Start(controlPipeName);
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
                    buf = System.Text.Encoding.Unicode.GetBytes(name);
                    buf = System.Text.Encoding.Unicode.GetBytes($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { controlPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception '{e.Message}' while sending tracedDir data");
                        return;
                    }
                }
                foreach (string name in tracedFiles)
                {
                    Console.Write("Sending included file " + name + "\n");
                    buf = System.Text.Encoding.Unicode.GetBytes(name);
                    buf = System.Text.Encoding.UTF8.GetBytes($"@TD@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { controlPipe.Write(buf, 0, buf.Length); }
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
                    Console.Write("Sending ignored dir " + name +"\n");

                    buf = System.Text.Encoding.Unicode.GetBytes(name);
                    buf = System.Text.Encoding.UTF8.GetBytes($"@ID@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { controlPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception '{e.Message}' while sending ignored dir data");
                        return;
                    }
                }
                foreach (string name in ignoredFiles)
                {
                    Console.Write("Sending ignored file " + name + "\n");
                    buf = System.Text.Encoding.Unicode.GetBytes(name);
                    buf = System.Text.Encoding.UTF8.GetBytes($"@IF@{System.Convert.ToBase64String(buf)}@E\x00\x00\x00");
                    try { controlPipe.Write(buf, 0, buf.Length); }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Exception '{e.Message}' while sending ignored File data");
                        return;
                    }
                }
            }

            buf = System.Text.Encoding.UTF8.GetBytes($"@XX@0@@\x00");
            try { controlPipe.Write(buf, 0, buf.Length); }
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

        void Listener(Object pipenameO)
        {
            string name = (string)pipenameO;
            controlPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = controlPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Control");


            int totalWaited = 0;
            while (!_clientState.rgatIsExiting)
            {
                if (controlPipe.IsConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Waiting ControlPipeConnected:{controlPipe.IsConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. ControlPipeConnected:{controlPipe.IsConnected} ");
                    break;
                }
            }

            if (controlPipe.IsConnected)
            {
                SendTraceSettings();
            }

            while (!_clientState.rgatIsExiting && controlPipe.IsConnected)
            {
                byte[] buf = new byte[4096 * 4];
                IAsyncResult res =  controlPipe.BeginRead(buf, 0, 2000, new AsyncCallback(ReadCallback), buf);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);
                if (!res.IsCompleted)
                {
                    try { controlPipe.EndRead(res); } catch { };
                }
            }

            controlPipe.Dispose();
            Console.WriteLine($"ControlHandler Listener thread exited for PID {trace.PID}");
        }

    }
}
