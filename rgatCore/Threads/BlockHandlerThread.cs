using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class BlockHandlerThread
    {

        BinaryTarget target;
        TraceRecord trace;
        rgatState _clientState;
        int threadsCount = 0;
        NamedPipeServerStream blockPipe = null;
        Thread listenerThread = null;

        public BlockHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, rgatState clientState)
        {
            target = binaryTarg;
            trace = runrecord;
            _clientState = clientState;
        }


        void ConnectCallback(IAsyncResult ar)
        {
            string pipeName = (String)ar.AsyncState;

            if (pipeName == "Block")
            {

                try
                {
                    blockPipe.EndWaitForConnection(ar);
                    Console.WriteLine("Block pipe connected for PID " + trace.PID);
                }
                catch (Exception e)
                {

                }
            }
        }


        void ReadCallback(IAsyncResult ar)
        {
            int bytesread = 0;
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                bytesread = blockPipe.EndRead(ar);
            }
            catch (Exception e)
            {
                Console.WriteLine("BlockHandler Read callback exception " + e.Message);
                return;
            }

            if (bytesread == 0)
            {
                Console.WriteLine($"WARNING: BlockHandler pipe read 0 bytes from PID {trace.PID}");
                return;
            }

            Console.WriteLine("BlockHandler pipe read unhandled entry from PID {trace.PID}");
            Console.WriteLine("\t" + System.Text.ASCIIEncoding.ASCII.GetString(buf));
        }

        public void Begin(string controlPipeName)
        {

            listenerThread = new Thread(new ParameterizedThreadStart(Listener));

            listenerThread.Start(controlPipeName);
        }

        void Listener(Object pipenameO)
        {
            string name = (string)pipenameO;
            blockPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = blockPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Block");


            int totalWaited = 0;
            while (!_clientState.rgatIsExiting)
            {
                if (blockPipe.IsConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Waiting BlockPipeConnected:{blockPipe.IsConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. BlockPipeConnected:{blockPipe.IsConnected} ");
                    break;
                }
            }


            while (!_clientState.rgatIsExiting && blockPipe.IsConnected)
            {
                byte[] buf = new byte[14096 * 4];
                IAsyncResult res = blockPipe.BeginRead(buf, 0, 2000, new AsyncCallback(ReadCallback), buf);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);
                if (!res.IsCompleted)
                {
                    try { blockPipe.EndRead(res); }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception on blockreader read : " + e.Message);
                    };
                }
            }


            /*
            while (!_clientState.rgatIsExiting && blockPipe.IsConnected)
            {
                

                
                Thread.Sleep(1000);
                try
                {
                    blockPipe.Write(System.Text.Encoding.Unicode.GetBytes("@HB@\x00\x00"));
                } catch (Exception e)
                {
                    if (e.Message != "Pipe is broken.") {
                        Console.WriteLine($"Blockhandler heartbeat stopped: {e.Message}");
                   }
                    else
                    {
                        Console.WriteLine("Blockhandler pipe broke");
                        break;
                    }
                }
            }
            */

            blockPipe.Dispose(); 
            Console.WriteLine($"BlockHandler Listener thread exited for PID {trace.PID}");
        }

    }
}
