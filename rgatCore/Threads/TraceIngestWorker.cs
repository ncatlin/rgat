using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// A worker for ingesting trace data
    /// </summary>
    public abstract class TraceIngestWorker : TraceProcessorWorker
    {
        /// <summary>
        /// This worker is stopping
        /// </summary>
        public bool StopFlag { get; private set; }
        /// <summary>
        /// How many bytes of data remain to be processed
        /// </summary>
        protected ulong PendingDataSize = 0;
        /// <summary>
        /// How many bytes of data have been processed
        /// </summary>
        protected ulong ProcessedDataSize = 0;

        /// <summary>
        /// How many items of data are awaiting ingest
        /// </summary>
        public ulong QueueSize { get; protected set; } = 0;
        long _recentMsgCount = 0;


        /// <summary>
        /// New data is ready for ingest
        /// </summary>
        protected bool WakeupRequested { get; private set; } = false;

        readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();

        /// <summary>
        /// Cancellation token cancelled if Terminate is called
        /// </summary>
        public CancellationToken CancelToken => cancelTokens.Token;

        /// <summary>
        /// Data ready event
        /// </summary>
        public ManualResetEventSlim TagDataReadyEvent = new ManualResetEventSlim(false);

        /// <summary>
        /// Announce interest in being notified when new data is available
        /// </summary>
        public void RequestWakeupOnData() { if (!StopFlag) { WakeupRequested = true; TagDataReadyEvent.Reset(); } }

        /// <summary>
        /// Create a generic trace ingest worker
        /// </summary>
        protected TraceIngestWorker()
        {
            _updateRates = Enumerable.Repeat(0.0f, _StatCacheSize).ToList();

            StatsTimer = new System.Timers.Timer(1000.0 / GlobalConfig.IngestStatsPerSecond);
            StatsTimer.Elapsed += StatsTimerFired;
            StatsTimer.AutoReset = true;
            StatsTimer.Start();
        }

        /// <summary>
        /// count a new message
        /// </summary>
        protected void IncreaseMessageCount() => _recentMsgCount += 1;

        /// <summary>
        /// Stop processing, cause the worker to exit
        /// </summary>
        public virtual void Terminate()
        {
            if (!StopFlag)
            {
                StopFlag = true;
                cancelTokens.Cancel();
            }
        }

        /// <summary>
        /// Fetch the next data from the queue
        /// </summary>
        /// <returns>The next data, or null if none</returns>
        public abstract byte[]? DeQueueData();

        /// <summary>
        /// Is there queued data to process
        /// </summary>
        /// <returns></returns>
        public virtual bool HasPendingData => PendingDataSize != 0;

        private readonly object _statsLock = new object();
        readonly System.Timers.Timer StatsTimer;
        DateTime _lastStatsUpdate = DateTime.Now;
        private readonly List<float> _updateRates = new List<float>();
        readonly int _StatCacheSize = (int)Math.Floor(GlobalConfig.IngestStatWindow * GlobalConfig.IngestStatsPerSecond);

        /// <summary>
        /// Get recnt messages/second ingest rates
        /// </summary>
        /// <returns></returns>
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

            float elapsedTimeS = (DateTime.Now - lastUpdate).Milliseconds / 1000.0f;

            float updateRate = messagesSinceLastUpdate / elapsedTimeS;
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
                    if (_updateRates.Max() == 0)
                    {
                        StatsTimer.Stop();
                    }
                }
            }

        }




    }
}
