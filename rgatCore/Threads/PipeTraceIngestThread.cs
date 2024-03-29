﻿using rgat.Threads;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Threading;

namespace rgat
{

    /// <summary>
    /// A worker to ingest trace data from a named pipe
    /// </summary>
    public class PipeTraceIngestThread : TraceIngestWorker
    {
        private readonly ProtoGraph? protograph;
        private readonly NamedPipeServerStream threadpipe;
        private readonly Thread splittingThread;
        private readonly bool PipeBroke = false;

        /// <summary>
        /// Set when there is no more data to ingest (eg: pipe broke)
        /// </summary>
        public ManualResetEventSlim RawIngestCompleteEvent = new ManualResetEventSlim(false);

        private delegate void QueueIngestedData(byte[] data);

        private readonly object QueueSwitchLock = new object();
        private int readIndex = 0;
        private readonly List<byte[]> FirstQueue = new List<byte[]>();
        private readonly List<byte[]> SecondQueue = new List<byte[]>();
        private List<byte[]> ReadingQueue;
        private List<byte[]> WritingQueue;
        private readonly ConcurrentQueue<Tuple<byte[], int>> RawQueue = new ConcurrentQueue<Tuple<byte[], int>>();
        private readonly uint _threadID;
        private readonly uint? _remotePipe;
        private byte[]? pendingBuf;

        /// <summary>
        /// Create a pipe ingest worker
        /// </summary>
        /// <param name="_threadpipe">The pipe to read</param>
        /// <param name="threadID">The ID of the graph being read</param>
        /// <param name="newProtoGraph">The graph to ingest. Can be null if a remote trace</param>
        /// <param name="remotePipe">ID of the remote pipe, or null if a local trace</param>
        public PipeTraceIngestThread(NamedPipeServerStream _threadpipe, uint threadID, ProtoGraph? newProtoGraph, uint? remotePipe = null)
        {
            Debug.Assert(newProtoGraph == null || newProtoGraph.ThreadID == threadID);
            _threadID = threadID;
            protograph = newProtoGraph;
            threadpipe = _threadpipe;
            ReadingQueue = FirstQueue;
            WritingQueue = SecondQueue;
            _remotePipe = remotePipe;
            splittingThread = new Thread(MessageSplitterThread);
        }

        /// <summary>
        /// Start work
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(Reader)
            {
                Name = "TraceReader" + _threadID
            };
            WorkerThread.Start();

            splittingThread.Name = "MessageSplitter" + _threadID;

            QueueIngestedData queueFunction;

            if (_remotePipe.HasValue)
            {
                queueFunction = MirrorMessageToRemoteUI;
            }
            else
            {
                queueFunction = EnqueueData;
            }

            splittingThread.Start(queueFunction);
        }

        private void MirrorMessageToRemoteUI(byte[] buf)
        {
            rgatState.NetworkBridge.SendRawTraceData(_remotePipe!.Value, buf, buf.Length);
        }

        /// <summary>
        /// Clear the queues
        /// </summary>
        public override void ClearQueue()
        {
            lock (QueueSwitchLock)
            {
                ReadingQueue?.Clear();
                WritingQueue?.Clear();
                PendingDataSize = 0;
                QueueSize = 0;
            }
        }

        /// <summary>
        /// Fetch the next trace data item to process
        /// </summary>
        /// <returns>The bytes of the trace data</returns>
        public override byte[]? DeQueueData()
        {
            byte[] nextMessage;
            lock (QueueSwitchLock)
            {
                if (ReadingQueue == null)
                {
                    return null;
                }

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

                IncreaseProcessedCount();
                QueueSize -= 1;
                PendingDataSize -= (ulong)nextMessage.Length;
                ProcessedDataSize += (ulong)nextMessage.Length;
                return nextMessage;
            }
        }


        private void EnqueueData(byte[] datamsg)
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

            Logging.WriteConsole("Trace Buffer maxed out, waiting for reader to catch up");
            do
            {
                Thread.Sleep(1000);
                Logging.WriteConsole($"Trace queue has {WritingQueue.Count}/{GlobalConfig.Settings.Tracing.TraceBufferSize} items");
                if (WritingQueue.Count < (GlobalConfig.Settings.Tracing.TraceBufferSize / 2))
                {
                    Logging.WriteConsole("Resuming ingest...");
                    break;
                }
            } while (!StopFlag && !rgatState.rgatIsExiting);

            lock (QueueSwitchLock)
            {
                WritingQueue.Add(datamsg);
                QueueSize += 1;
                PendingDataSize += (ulong)datamsg.Length;
            }
            Logging.WriteConsole($"Now {PendingDataSize} bytes of pending data");

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
        private void MessageSplitterThread(object? queueFunc)
        {
            QueueIngestedData AddData = (QueueIngestedData)queueFunc!;
            while (!rgatState.rgatIsExiting && (threadpipe.IsConnected || !RawQueue.IsEmpty))
            {
                if (!RawQueue.TryDequeue(out Tuple<byte[], int>? buf_sz))
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
                //Logging.WriteConsole("Splitting: " + Encoding.ASCII.GetString(buf, 0, buf.Length));
                int msgstart = 0;
                for (int tokenpos = 0; tokenpos < bytesread; tokenpos++)
                {
                    if (buf[tokenpos] == '\x00')
                    {
                        Logging.WriteConsole($"Null break at {tokenpos}");
                        break;
                    }

                    if (buf[tokenpos] == '\x01')
                    {
                        int msgsize = tokenpos - msgstart;
                        if (msgsize == 0)
                        {
                            Logging.WriteConsole($"msg size 0 break");
                            break;
                        }
                        byte[] msg = new byte[msgsize];
                        Buffer.BlockCopy(buf, msgstart, msg, 0, msgsize);
                        //Logging.WriteConsole($"\tQueued [{msgstart}]: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                        AddData(msg);
                        IncreaseMessageCount();
                        msgstart = tokenpos + 1;
                    }
                }
            }
        }


        /// <summary>
        /// Terminate the ingest worker, remove any queued items
        /// </summary>
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
                lock (QueueSwitchLock)
                {
                    FirstQueue.Clear();
                    SecondQueue.Clear();
                    QueueSize = 0;
                }
            }
        }



        //This reads data from a locally running trace and queues it
        private async void Reader()
        {
            if (!threadpipe.IsConnected)
            {
                Logging.RecordLogEvent("Error - ThreadTraceIngestThread expected a connected thread pipe", filter: Logging.LogFilterType.Error);
                return;
            }

            lock (QueueSwitchLock)
            {
                WritingQueue = FirstQueue;
                ReadingQueue = SecondQueue;
            }


            while (!StopFlag && !PipeBroke)
            {
                byte[] TagReadBuffer = new byte[CONSTANTS.TRACING.TagCacheSize];
                int bytesRead;
                try
                {
                    bytesRead = await threadpipe.ReadAsync(TagReadBuffer.AsMemory(0, CONSTANTS.TRACING.TagCacheSize), CancelToken);
                }
                catch(Exception e)
                {
                    if (CancelToken.IsCancellationRequested is false)
                    {
                        Logging.RecordException("Exception in threadreader", e);
                    }
                    break;
                }

                if (bytesRead < CONSTANTS.TRACING.TagCacheSize)
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
            while ((RawQueue.IsEmpty is false || FirstQueue.Count > 0 || SecondQueue.Count > 0) && !StopFlag)
            {
                if (WakeupRequested)
                {
                    TagDataReadyEvent.Set();
                }

                Thread.Sleep(25);
            }
            Terminate();


            RawIngestCompleteEvent.Set();
            TagDataReadyEvent.Set();

            Logging.RecordLogEvent(WorkerThread?.Name + " finished after ingesting "
                + ProcessedDataSize + " bytes of trace data", Logging.LogFilterType.Debug );

            if (protograph != null && !protograph.Terminated)
            {
                protograph.SetTerminated();
            }

            Finished();
        }




    }
}
