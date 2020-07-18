using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO.Pipes;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class ThreadTraceIngestThread
    {
        uint TraceBufSize = GlobalConfig.TraceBufferSize;
        ProtoGraph protograph;
        NamedPipeServerStream threadpipe;
        Thread runningThread;
        ulong PendingDataSize = 0;
        ulong ProcessedDataSize = 0;
        ulong TotalProcessedData = 0;
        public bool StopFlag = false;

        public ManualResetEvent dataReadyEvent = new ManualResetEvent(false);
        bool WakeupRequested = false;

        public bool HasPendingData() { return PendingDataSize != 0; }
        public void RequestWakeupOnData() { if (!StopFlag) { WakeupRequested = true; dataReadyEvent.Reset(); } }

        private readonly object QueueSwitchLock = new object();
        int readIndex = 0;
        List<byte[]> FirstQueue = new List<byte[]>();
        List<byte[]> SecondQueue = new List<byte[]>();
        List<byte[]> ReadingQueue = null;
        List<byte[]> WritingQueue = null;



        public ThreadTraceIngestThread(ProtoGraph newProtoGraph, NamedPipeServerStream _threadpipe)
        {
            TraceBufSize = GlobalConfig.TraceBufferSize;
            protograph = newProtoGraph;
            threadpipe = _threadpipe;
            List<byte[]> ReadingQueue = FirstQueue;
            List<byte[]> WritingQueue = SecondQueue;

            runningThread = new Thread(Reader);
            runningThread.Name = "TraceReader" + this.protograph.ThreadID;
            runningThread.Start();
        }


        public byte[] DeQueueData()
        {
            byte[] nextMessage = null;
            lock (QueueSwitchLock)
            {
                if (ReadingQueue == null) return null;
                if (ReadingQueue.Count == 0 || readIndex >= ReadingQueue.Count)
                {

                    if (ReadingQueue.Count != 0)
                    {
                        ReadingQueue.Clear();
                    }
                    readIndex = 0;

                    //swap to the other queue
                    ReadingQueue = (ReadingQueue == FirstQueue) ? SecondQueue : FirstQueue;
                    WritingQueue = (ReadingQueue == FirstQueue) ? SecondQueue : FirstQueue;

                    if (ProcessedDataSize > 0)
                    {
                        PendingDataSize -= ProcessedDataSize;
                        ProcessedDataSize = 0;
                    }
                }

                if (ReadingQueue.Count == 0)
                {
                    return null;
                }

                nextMessage = ReadingQueue[readIndex++];

            }
            ProcessedDataSize += (ulong)nextMessage.Length;
            TotalProcessedData += (ulong)nextMessage.Length;
            return nextMessage;
        }

        void EnqueueData(byte[] datamsg)
        {
            lock (QueueSwitchLock)
            {
                if (WritingQueue.Count < GlobalConfig.TraceBufferSize)
                {
                    WritingQueue.Add(datamsg);
                    PendingDataSize += (ulong)datamsg.Length;
                    return;
                }
            }

            Console.WriteLine("Trace Buffer maxed out, waiting for reader to catch up");
            do
            {

                Thread.Sleep(1000);
                Console.WriteLine($"Trace queue has {WritingQueue.Count}/{GlobalConfig.TraceBufferSize} items");
                if (WritingQueue.Count < (GlobalConfig.TraceBufferSize / 2))
                {
                    Console.WriteLine("Resuming ingest...");
                    break;
                }
            } while (!StopFlag);

            lock (QueueSwitchLock)
            {
                WritingQueue.Add(datamsg);

                PendingDataSize += (ulong)datamsg.Length;
            }
            Console.WriteLine($"Now {PendingDataSize} bytes of pending data");

            if (WakeupRequested)
            {
                dataReadyEvent.Set();
            }
        }

        void IncomingMessageCallback(IAsyncResult ar)
        {
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                int bytesread = threadpipe.EndRead(ar);
                if (bytesread > 0)
                {
                    buf[bytesread] = 0;
                    Console.WriteLine("Splitting: "+Encoding.ASCII.GetString(buf, 0, buf.Length));
                    int msgstart = 0;
                    int toks = 0;
                    for (int tokenpos = 0; tokenpos < bytesread; tokenpos++)
                    {
                        if (buf[tokenpos] == '\x00')
                        {
                            Console.WriteLine($"Null break at {tokenpos}");
                            toks++;
                            break; 
                        }

                        if (buf[tokenpos] == '\x01')
                        {
                            toks++;
                            Console.WriteLine($"1 tok at {tokenpos}");
                            int msgsize = tokenpos - msgstart;
                            if (msgsize == 0) {
                                Console.WriteLine($"msg size 0 break");
                                break; 
                            }
                            byte[] msg = new byte[msgsize];
                            Buffer.BlockCopy(buf, msgstart, msg, 0, msgsize);
                            Console.WriteLine($"\tQueued [{msgstart}]: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                            EnqueueData(msg);
                            msgstart = tokenpos + 1;
                        }
                    }
                    if (toks == 0)
                    {
                        Console.WriteLine("no toks");
                    }

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("TraceIngest Readcall back exception " + e.Message);
                return;
            }
            Console.WriteLine("End incomingmsg");
        }


        //thread handler to build graph for a thread
        void Reader()
        {
            if (!threadpipe.IsConnected)
            {
                Console.WriteLine("Error - ThreadTraceIngestThread expected a connected thread pipe");
                return;
            }



            lock (QueueSwitchLock)
            {
                WritingQueue = FirstQueue;
                ReadingQueue = SecondQueue;
            }

            while (!StopFlag && threadpipe.IsConnected)
            {
                const int TAGCACHESIZE = 1024 ^ 2;
                byte[] TagReadBuffer = new byte[TAGCACHESIZE];
                IAsyncResult res = threadpipe.BeginRead(TagReadBuffer, 0, TAGCACHESIZE, new AsyncCallback(IncomingMessageCallback), TagReadBuffer);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);
                if (!res.IsCompleted)
                {
                    try { threadpipe.EndRead(res); }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception on threadreader read : " + e.Message);
                    };
                }
            }

            threadpipe.Disconnect();
            threadpipe.Dispose();

            //wait until buffers emptied
            while ((FirstQueue.Count > 0 || SecondQueue.Count > 0) && !StopFlag)
            {
                if (WakeupRequested) dataReadyEvent.Set();
                Thread.Sleep(25);
            }
            StopFlag = true;
            dataReadyEvent.Set();
            Console.WriteLine(runningThread.Name + " finished after ingesting " + TotalProcessedData + " bytes of trace data");

        }




    }
}
