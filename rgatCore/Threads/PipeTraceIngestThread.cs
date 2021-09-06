using rgat.Threads;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Threading;
using System.Timers;

namespace rgat
{
    public class PipeTraceIngestThread : TraceIngestWorker
    {
        uint TraceBufSize = GlobalConfig.Settings.Tracing.TraceBufferSize;
        ProtoGraph protograph;
        NamedPipeServerStream threadpipe;
        Thread splittingThread;
        bool PipeBroke = false;

        public ManualResetEventSlim RawIngestCompleteEvent = new ManualResetEventSlim(false);
        delegate void QueueIngestedData(byte[] data);

        private readonly object QueueSwitchLock = new object();
        int readIndex = 0;
        List<byte[]> FirstQueue = new List<byte[]>();
        List<byte[]> SecondQueue = new List<byte[]>();
        List<byte[]> ReadingQueue = null;
        List<byte[]> WritingQueue = null;
        ConcurrentQueue<Tuple<byte[], int>> RawQueue = new ConcurrentQueue<Tuple<byte[], int>>();

        uint _threadID;
        uint? _remotePipe;

        public PipeTraceIngestThread(ProtoGraph newProtoGraph, NamedPipeServerStream _threadpipe, uint threadID, uint? remotePipe = null)
        {
            Debug.Assert(newProtoGraph == null || newProtoGraph.ThreadID == threadID);
            _threadID = threadID;
            TraceBufSize = GlobalConfig.Settings.Tracing.TraceBufferSize;
            protograph = newProtoGraph;
            threadpipe = _threadpipe;
            ReadingQueue = FirstQueue;
            WritingQueue = SecondQueue;
            _remotePipe = remotePipe;
        }


        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(Reader);
            WorkerThread.Name = "TraceReader" + _threadID;
            WorkerThread.Start();

            splittingThread = new Thread(MessageSplitterThread);
            splittingThread.Name = "MessageSplitter" + _threadID;

            QueueIngestedData queueFunction;

            if (_remotePipe.HasValue)
                queueFunction = MirrorMessageToUI;
            else 
                queueFunction = EnqueueData;

            splittingThread.Start(queueFunction);
        }


        void MirrorMessageToUI(byte[] buf)
        {
            rgatState.NetworkBridge.SendRawTraceData(_remotePipe.Value, buf, buf.Length);
        }



        public override byte[] DeQueueData()
        {
            byte[] nextMessage;
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

                QueueSize -= 1;
                PendingDataSize -= (ulong)nextMessage.Length;
                ProcessedDataSize += (ulong)nextMessage.Length;
                TotalProcessedData += (ulong)nextMessage.Length;
                return nextMessage;
            }
        }



        void EnqueueData(byte[] datamsg)
        {
            lock (QueueSwitchLock)
            {
                if (WritingQueue.Count < GlobalConfig.Settings.Tracing.TraceBufferSize)
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
                Console.WriteLine($"Trace queue has {WritingQueue.Count}/{GlobalConfig.Settings.Tracing.TraceBufferSize} items");
                if (WritingQueue.Count < (GlobalConfig.Settings.Tracing.TraceBufferSize / 2))
                {
                    Console.WriteLine("Resuming ingest...");
                    break;
                }
            } while (!StopFlag && !rgatState.rgatIsExiting);

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
        void MessageSplitterThread(object queueFunc)
        {
            QueueIngestedData AddData = (QueueIngestedData)queueFunc;
            while (!rgatState.rgatIsExiting && (threadpipe.IsConnected || RawQueue.Count > 0))
            {
                if (!RawQueue.TryDequeue(out Tuple<byte[], int> buf_sz))
                {
                    try
                    {
                        RawIngestCompleteEvent.Wait(-1, CancelToken);
                    }
                    catch
                    {
                        continue;
                    }
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
                        AddData(msg);
                        IncreaseMessageCount();
                        msgstart = tokenpos + 1;
                    }
                }
            }
        }

        public override void Terminate()
        {
            if (!StopFlag)
            {
                try
                {
                    RawIngestCompleteEvent.Set();
                }
                catch { }
                base.Terminate();
            }
        }

        byte[] pendingBuf;


        //thread handler to build graph for a thread
        async void Reader()
        {
            if (!threadpipe.IsConnected)
            {
                Logging.RecordLogEvent("Error - ThreadTraceIngestThread expected a connected thread pipe", filter: Logging.LogFilterType.TextError);
                return;
            }

            lock (QueueSwitchLock)
            {
                WritingQueue = FirstQueue;
                ReadingQueue = SecondQueue;
            }


            while (!StopFlag && !PipeBroke)
            {
                byte[] TagReadBuffer = new byte[RGAT_CONSTANTS.TRACING.TagCacheSize];
                int bytesRead = await threadpipe.ReadAsync(TagReadBuffer, 0, RGAT_CONSTANTS.TRACING.TagCacheSize, CancelToken);

                if (bytesRead < RGAT_CONSTANTS.TRACING.TagCacheSize)
                {
                    if (pendingBuf != null)
                    {
                        //this is multipart, tack it onto the next fragment
                        bytesRead = pendingBuf.Length + bytesRead;
                        TagReadBuffer = pendingBuf.Concat(TagReadBuffer).ToArray();
                        pendingBuf = null;
                    }
                    //Logging.RecordLogEvent("IncomingMessageCallback: " + Encoding.ASCII.GetString(buf, 0, bytesread), filter: Logging.LogFilterType.BulkDebugLogFile);
                    if (bytesRead > 0)
                    {
                        RawQueue.Enqueue(new Tuple<byte[], int>(TagReadBuffer, bytesRead));
                        RawIngestCompleteEvent.Set();
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    //multi-part message, queue this for reassembly
                    pendingBuf = (pendingBuf == null) ?
                        TagReadBuffer :
                        pendingBuf.Concat(TagReadBuffer).ToArray();
                }
            }

            threadpipe.Disconnect();
            threadpipe.Dispose();

            //wait for the queue to be empty before destroying self
            while ((RawQueue.Count > 0 || FirstQueue.Count > 0 || SecondQueue.Count > 0) && !StopFlag)
            {
                if (WakeupRequested) TagDataReadyEvent.Set();
                Thread.Sleep(25);
            }
            Terminate();

            RawIngestCompleteEvent.Set();
            TagDataReadyEvent.Set();

            Console.WriteLine(WorkerThread.Name + " finished after ingesting " + TotalProcessedData + " bytes of trace data");

            if (protograph != null && !protograph.Terminated)
                protograph.SetTerminated();
            Finished();
        }




    }
}
