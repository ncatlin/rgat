using rgatCore.Threads;
using System;
using System.Collections.Concurrent;
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
        Thread splittingThread;
        ulong PendingDataSize = 0;
        ulong ProcessedDataSize = 0;
        ulong TotalProcessedData = 0;
        public bool StopFlag = false;
        bool PipeBroke = false;

        public ManualResetEvent TagDataReadyEvent = new ManualResetEvent(false);
        public ManualResetEvent RawIngestCompleteEvent = new ManualResetEvent(false);
        bool WakeupRequested = false;

        public bool HasPendingData() { return PendingDataSize != 0; }
        public void RequestWakeupOnData() { if (!StopFlag) { WakeupRequested = true; TagDataReadyEvent.Reset(); } }

        private readonly object QueueSwitchLock = new object();
        private readonly object RawQueueLock = new object();
        int readIndex = 0;
        List<byte[]> FirstQueue = new List<byte[]>();
        List<byte[]> SecondQueue = new List<byte[]>();
        List<byte[]> ReadingQueue = null;
        List<byte[]> WritingQueue = null;
        ConcurrentQueue<Tuple<byte[], int>> RawQueue = new ConcurrentQueue<Tuple<byte[], int>>();
        public ulong QueueSize = 0;


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
            splittingThread = new Thread(MessageSplitterThread);
            splittingThread.Name = "MessageSplitter" + this.protograph.ThreadID;
            splittingThread.Start();
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
                }

                if (ReadingQueue.Count == 0)
                {
                    return null;
                }

                nextMessage = ReadingQueue[readIndex++];

            }

            QueueSize -= 1;
            PendingDataSize -= (ulong)nextMessage.Length;
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
                    QueueSize += 1;
                    PendingDataSize += (ulong)datamsg.Length;

                    if (WakeupRequested)
                    {
                        TagDataReadyEvent.Set();
                    }
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
                QueueSize += 1;
                PendingDataSize += (ulong)datamsg.Length;
            }
            Console.WriteLine($"Now {PendingDataSize} bytes of pending data");

            if (WakeupRequested)
            {
                TagDataReadyEvent.Set();
            }
        }

        /*
         * It's very important that we clear data from the named pipe as fast as possible 
         * as this will slow the traced program. This second ingest thread receives tag
         * blobs and splits them up to be queued for the trace processor to handle
         * 
         * Could possibly have the ingest thread deal with this but then the full buffers 
         * are in the main queues
         */
        void MessageSplitterThread()
        {
            while (threadpipe.IsConnected || RawQueue.Count > 0)
            {
                if (!RawQueue.TryDequeue(out Tuple<byte[], int> buf_sz))
                {
                    RawIngestCompleteEvent.WaitOne();
                    RawIngestCompleteEvent.Reset();
                    continue; 
                }

                byte[] buf = buf_sz.Item1;
                int bytesread = buf_sz.Item2;

                buf[bytesread] = 0;
                //Console.WriteLine("Splitting: " + Encoding.ASCII.GetString(buf, 0, buf.Length));
                int msgstart = 0;
                for (int tokenpos = 0; tokenpos < bytesread; tokenpos++)
                {
                    if (buf[tokenpos] == '\x00')
                    {
                        Console.WriteLine($"Null break at {tokenpos}");
                        break;
                    }

                    if (buf[tokenpos] == '\x01')
                    {
                        int msgsize = tokenpos - msgstart;
                        if (msgsize == 0)
                        {
                            Console.WriteLine($"msg size 0 break");
                            break;
                        }
                        byte[] msg = new byte[msgsize];
                        Buffer.BlockCopy(buf, msgstart, msg, 0, msgsize);
                        //Console.WriteLine($"\tQueued [{msgstart}]: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                        EnqueueData(msg);
                        msgstart = tokenpos + 1;
                    }
                }
            }
        }



        void IncomingMessageCallback(IAsyncResult ar)
        {
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                lock (RawQueueLock)
                {
                    int bytesread = threadpipe.EndRead(ar);
                    if (bytesread == 0 || threadpipe.IsConnected == false)
                    {
                        PipeBroke = true;
                    }
                    else
                    { 
                        RawQueue.Enqueue(new Tuple<byte[], int>(buf, bytesread));
                        RawIngestCompleteEvent.Set();
                    }
                } 
            }
            catch (Exception e)
            {
                Console.WriteLine("TraceIngest Readcall back exception " + e.Message);
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

            lock (QueueSwitchLock)
            {
                WritingQueue = FirstQueue;
                ReadingQueue = SecondQueue;
            }

            while (!StopFlag && !PipeBroke)
            {
                const int TAGCACHESIZE = 1024 ^ 2;
                byte[] TagReadBuffer = new byte[TAGCACHESIZE];
                IAsyncResult res = threadpipe.BeginRead(TagReadBuffer, 0, TAGCACHESIZE, new AsyncCallback(IncomingMessageCallback), TagReadBuffer);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 1500); //timeout so we can check for rgat exit
                
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

            while ((RawQueue.Count > 0 || FirstQueue.Count > 0 || SecondQueue.Count > 0) && !StopFlag)
            {
                if (WakeupRequested) TagDataReadyEvent.Set();
                Thread.Sleep(25);
            }
            StopFlag = true;
            TagDataReadyEvent.Set();
            Console.WriteLine(runningThread.Name + " finished after ingesting " + TotalProcessedData + " bytes of trace data");

        }




    }
}
