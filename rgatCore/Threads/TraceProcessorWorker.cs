using System.Diagnostics;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// General worker thread
    /// </summary>
    public abstract class TraceProcessorWorker
    {
        /// <summary>
        /// rgat state object
        /// </summary>
        protected static rgatState? _clientState;

        /// <summary>
        /// init the state property
        /// </summary>
        /// <param name="state_">rgatState object</param>
        public static void SetRgatState(rgatState state_)
        {
            _clientState = state_;
        }

        private bool stopped = true;
        /// <summary>
        /// The worker is running
        /// </summary>
        public bool Running
        {
            get
            {
                return !stopped;
            }
        }
        /// <summary>
        /// The system thread for the worker
        /// </summary>
        public Thread? WorkerThread = null;

        /// <summary>
        /// Start work
        /// </summary>
        public virtual void Begin()
        {
            stopped = false;
        }

        /// <summary>
        /// The worker is finished
        /// </summary>
        protected virtual void Finished()
        {
            Debug.Assert(!stopped);
            stopped = true;
        }
    }
}
