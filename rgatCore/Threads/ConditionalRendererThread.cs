namespace rgat.Threads
{
    public class ConditionalRendererThread : TraceProcessorWorker
    {
        readonly TraceRecord RenderedTrace = null;

        public ConditionalRendererThread(TraceRecord _renderedTrace)
        {
            RenderedTrace = _renderedTrace;
        }

        public void ThreadProc()
        {

        }
    }
}
