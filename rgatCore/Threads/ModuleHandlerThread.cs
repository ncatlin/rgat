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
        public bool ControlPipeConnected = false;
        public bool ModulePipeConnected = false;
        NamedPipeServerStream controlPipe = null;
        NamedPipeServerStream modulePipe = null;
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

            if (pipeName == "Control") {

                try
                {
                    controlPipe.EndWaitForConnection(ar);
                    Console.WriteLine("Control pipe connected for PID " + trace.PID);
                    ControlPipeConnected = true;
                } 
                catch (Exception e)
                {

                    ControlPipeConnected = false;
                }
            }

            if (pipeName == "Module")
            {
                try
                {
                    modulePipe.EndWaitForConnection(ar);
                    Console.WriteLine("Module pipe connected for PID " + trace.PID);
                    ModulePipeConnected = true;
                }
                catch (Exception e)
                {

                    ModulePipeConnected = false;
                }
            }
        }

        public void OpenPipes(string controlPipeName, string modulePipeName)
        {

           listenerThread = new Thread(new ParameterizedThreadStart(Listener));
           
            listenerThread.Start(new Tuple<string,string>(controlPipeName, modulePipeName));
        }

        void Listener(Object pipenames)
        {
            Tuple<string, string> names = (Tuple<string, string>)pipenames;
            controlPipe = new NamedPipeServerStream(names.Item1, PipeDirection.Out, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = controlPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Control");

            modulePipe = new NamedPipeServerStream(names.Item2, PipeDirection.In, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res2 = modulePipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Module");


            int totalWaited = 0;
            while (!_clientState.rgatIsExiting)
            {
                if (ModulePipeConnected && ControlPipeConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Waiting ModulePipeConnected:{ModulePipeConnected} ControlPipeConnected:{ControlPipeConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. ModulePipeConnected:{ModulePipeConnected} ControlPipeConnected:{ControlPipeConnected} ");
                    break;
                }
            }



            Console.WriteLine("Both pipes connected!");




            while (!_clientState.rgatIsExiting && controlPipe.IsConnected && modulePipe.IsConnected)
            {
                /*
                if (buf[0] == 'T' && buf[1] == 'I')
                {
                    Console.WriteLine("New Thread!");
                }

                if (buf[0] == 's' && buf[1] == '!')
                {
                    Console.WriteLine("New Symbol!");
                }

                if (buf[0] == 'm' && buf[1] == 'n')
                {
                    Console.WriteLine("New module!");
                }
                */
                Thread.Sleep(1000);
            }

            controlPipe.Dispose();
            modulePipe.Dispose();
        }

    }
}
