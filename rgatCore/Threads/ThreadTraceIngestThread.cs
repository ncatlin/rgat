﻿using rgatCore.Threads;
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
            lock (QueueSwitchLock)
            {
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

            }

            if (ReadingQueue.Count == 0)
            {
                return null;
            }

            byte[] nextMessage = ReadingQueue[readIndex++];
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

        void ReadCallback(IAsyncResult ar)
        {
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                int bytesread = threadpipe.EndRead(ar);
                if (bytesread > 0)
                {
                    byte[] msg = new byte[bytesread];
                    Buffer.BlockCopy(buf, 0, msg, 0, bytesread);
                    EnqueueData(msg);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("TraceIngest Readcall back exception " + e.Message);
                return;
            }
        }


        //thread handler to build graph for a thread
        void Reader()
        {
            if (!threadpipe.IsConnected)
            {
                Console.WriteLine("Error - ThreadTraceIngestThread expected a connected thread pipe");
                return;
            }

            const uint TAGCACHESIZE = 1024 ^ 2;
            char[] TagReadBuffer = new char[TAGCACHESIZE];

            WritingQueue = FirstQueue;
            ReadingQueue = SecondQueue;

            while (!StopFlag && threadpipe.IsConnected)
            {
                byte[] buf = new byte[4096 * 4];
                IAsyncResult res = threadpipe.BeginRead(buf, 0, 2000, new AsyncCallback(ReadCallback), buf);
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
            Console.WriteLine(runningThread.Name + " finished after ingesting "+TotalProcessedData+" bytes of trace data");

        }




    }
}