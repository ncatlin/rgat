using System.Collections.Generic;
using System.Threading;

namespace rgat.Threads
{
    internal class SocketTraceIngestThread : TraceIngestWorker
    {
        private readonly ProtoGraph protograph;
        private readonly Queue<byte[]> InQueue = new Queue<byte[]>();
        private readonly object _lock = new object(); //functionality first, performance later

        public SocketTraceIngestThread(ProtoGraph newProtoGraph)
        {
            protograph = newProtoGraph;
            /*
            _updateRates = Enumerable.Repeat(0.0f, _StatCacheSize).ToList();

            StatsTimer = new System.Timers.Timer(1000.0 / GlobalConfig.IngestStatsPerSecond);
            StatsTimer.Elapsed += StatsTimerFired;
            StatsTimer.AutoReset = true;
            StatsTimer.Start();
            */
        }


        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(Reader)
            {
                Name = "SocketTraceReader" + protograph.ThreadID
            };
            WorkerThread.Start();

            //splittingThread = new Thread(MessageSplitterThread);
            //splittingThread.Name = "MessageSplitter" + _threadID;
            //splittingThread.Start();
        }


        public override void Terminate()
        {
            base.Terminate();
        }

        public void QueueData(byte[] data)
        {
            lock (_lock)
            {
                InQueue.Enqueue(data);
                QueueSize += 1;
                PendingDataSize += (ulong)data.Length;

                if (WakeupRequested)
                {
                    TagDataReadyEvent.Set();
                }
            }
            IncreaseMessageCount();
        }


        public override byte[]? DeQueueData()
        {
            if (InQueue.Count == 0)
            {
                return null;
            }

            lock (_lock)
            {
                byte[] nextMessage = InQueue.Dequeue();
                IncreaseProcessedCount();
                PendingDataSize -= (ulong)nextMessage.Length;
                ProcessedDataSize += (ulong)nextMessage.Length;
                QueueSize -= 1;
                return nextMessage;
            }
        }

        private void Reader()
        {
            while (!StopFlag && !rgatState.NetworkBridge.CancelToken.IsCancellationRequested)
            {
                Thread.Sleep(100);
            }



            Logging.RecordLogEvent($"{WorkerThread?.Name} finished after ingesting {ProcessedDataSize} bytes of trace data", Logging.LogFilterType.Debug);

            if (!protograph.Terminated)
            {
                protograph.SetTerminated();
            }

            Finished();
        }

    }


}
