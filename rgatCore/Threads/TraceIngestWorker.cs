﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// An abstract worker for ingesting trace data
    /// Inherited by local named pipe and remote socket ingest workers
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

        private long _recentMsgCount = 0;
        private long _recentProcessedCount = 0;


        /// <summary>
        /// New data is ready for ingest
        /// </summary>
        protected bool WakeupRequested { get; private set; } = false;

        private readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();

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
            _incomingRates = Enumerable.Repeat(0.0f, _StatCacheSize).ToList();

            StatsTimer = new System.Timers.Timer(1000.0 / GlobalConfig.IngestStatsPerSecond);
            StatsTimer.Elapsed += StatsTimerFired;
            StatsTimer.AutoReset = true;
            StatsTimer.Start();
        }

        /// <summary>
        /// count a new message being received
        /// </summary>
        protected void IncreaseMessageCount() => _recentMsgCount += 1;
        /// <summary>
        /// Count a queued message being collected
        /// </summary>
        protected void IncreaseProcessedCount() => _recentProcessedCount += 1;


        /// <summary>
        /// Stop processing, cause the worker to exit
        /// </summary>
        public override void Terminate()
        {
            if (!StopFlag)
            {
                StopFlag = true;
                cancelTokens.Cancel();
                base.Terminate();
            }
        }

        /// <summary>
        /// Empty the queue
        /// </summary>
        public abstract void ClearQueue();

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
        private readonly System.Timers.Timer StatsTimer;
        private DateTime _lastStatsUpdate = DateTime.Now;
        private readonly List<float> _incomingRates = new List<float>();
        private readonly List<float> _outgoingRates = new List<float>();
        private readonly int _StatCacheSize = (int)Math.Floor(GlobalConfig.IngestStatWindow * GlobalConfig.IngestStatsPerSecond);


        /// <summary>
        /// Get recent message ingest rates
        /// </summary>
        /// <returns></returns>
        public void RecentMessageRates(out float[] _incoming)
        {
            lock (_statsLock)
            {
                _incoming = _incomingRates.ToArray();
            }
        }

        /// <summary>
        /// Get recent message ingest/processing rates
        /// </summary>
        /// <returns></returns>
        public void RecentProcessingRates(out float[] _outgoing)
        {
            lock (_statsLock)
            {
                _outgoing = _outgoingRates.ToArray();
            }
        }

        /*
         * The purpose of this is for plotting a little thread activity graph on the
         * preview pane, we don't really care about precision and want to minimise 
         * performance impact, so don't use any locks that contend with the I/O.
         */
        private void StatsTimerFired(object sender, System.Timers.ElapsedEventArgs e)
        {
            DateTime lastUpdate = _lastStatsUpdate;

            _lastStatsUpdate = DateTime.Now;

            float elapsedTimeS = (DateTime.Now - lastUpdate).Milliseconds / 1000.0f;

            lock (_statsLock)
            {
                float incomingRate = _recentMsgCount / elapsedTimeS;
                float outgoingRate = _recentProcessedCount / elapsedTimeS;
                _recentMsgCount = 0;
                _recentProcessedCount = 0;

                if (_incomingRates.Count > _StatCacheSize)
                {
                    _incomingRates.RemoveAt(0);
                    _outgoingRates.RemoveAt(0);
                }
                _incomingRates.Add(incomingRate);
                _outgoingRates.Add(outgoingRate);

                if (StopFlag)
                {
                    //stop updating once all activity has gone
                    if (_incomingRates.Max() == 0)
                    {
                        StatsTimer.Stop();
                        _incomingRates.Clear();
                        _outgoingRates.Clear();
                    }
                }
            }

        }




    }
}
