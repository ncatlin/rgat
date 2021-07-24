using System.Diagnostics;
using System.Threading;

namespace rgatCore.Threads
{
    public abstract class TraceProcessorWorker
    {
        protected static rgatState _clientState;
        public static void SetRgatState(rgatState state_)
        {
            _clientState = state_;
        }

        bool stopped = true;
        public bool Running
        {
            get
            {
                return !stopped && WorkerThread != null && WorkerThread.IsAlive;
            }
        }
        public Thread WorkerThread = null;

        public TraceProcessorWorker()
        {

        }

        public virtual void Begin()
        {
            stopped = false;
        }


        public void Finished()
        {
            Debug.Assert(!stopped);
            stopped = true;
        }
    }
}
