using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    public abstract class TraceIngestWorker : TraceProcessorWorker
    {
        public bool StopFlag { get; private set; }
        protected ulong PendingDataSize = 0;
        protected ulong ProcessedDataSize = 0;
        protected ulong TotalProcessedData = 0;
        public ulong QueueSize { get; protected set; } = 0;
        long _recentMsgCount = 0;



        protected bool WakeupRequested { get; private set; } = false;

        readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();
        public CancellationToken CancelToken => cancelTokens.Token;
        public ManualResetEventSlim TagDataReadyEvent = new ManualResetEventSlim(false);
        public void RequestWakeupOnData() { if (!StopFlag) { WakeupRequested = true; TagDataReadyEvent.Reset(); } }

        protected TraceIngestWorker()
        {
            _updateRates = Enumerable.Repeat(0.0f, _StatCacheSize).ToList();

            StatsTimer = new System.Timers.Timer(1000.0 / GlobalConfig.IngestStatsPerSecond);
            StatsTimer.Elapsed += StatsTimerFired;
            StatsTimer.AutoReset = true;
            StatsTimer.Start();
        }

        protected void IncreaseMessageCount() => _recentMsgCount += 1;

        public virtual void Terminate()
        {
            if (!StopFlag)
            {
                StopFlag = true;
                cancelTokens.Cancel();
            }
        }

        public abstract byte[] DeQueueData();

        public virtual bool HasPendingData() { return PendingDataSize != 0; }

        private readonly Object _statsLock = new Object();
        readonly System.Timers.Timer StatsTimer;
        DateTime _lastStatsUpdate = DateTime.Now;
        private readonly List<float> _updateRates = new List<float>();
        readonly int _StatCacheSize = (int)Math.Floor(GlobalConfig.IngestStatWindow * GlobalConfig.IngestStatsPerSecond);
        public float[] RecentMessageRates()
        {
            lock (_statsLock)
            {
                return _updateRates.ToArray();
            }
        }

        /*
         * The purpose of this is for plotting a little thread activity graph on the
         * preview pane, we don't really care about precision and want to minimise 
         * performance impact, so don't use any locks that contend with the I/O.
         */
        private void StatsTimerFired(object sender, System.Timers.ElapsedEventArgs e)
        {
            long messagesSinceLastUpdate = _recentMsgCount;
            DateTime lastUpdate = _lastStatsUpdate;

            _lastStatsUpdate = DateTime.Now;
            _recentMsgCount = 0;

            float elapsedTimeS = ((float)(DateTime.Now - lastUpdate).Milliseconds) / 1000.0f;

            float updateRate = (float)(messagesSinceLastUpdate) / elapsedTimeS;
            lock (_statsLock)
            {
                if (_updateRates.Count > _StatCacheSize)
                {
                    _updateRates.RemoveAt(0);
                }
                _updateRates.Add(updateRate);

                if (StopFlag)
                {
                    //stop updating once all activity has gone
                    if (_updateRates.Max() == 0) StatsTimer.Stop();
                }
            }

        }




    }
}
