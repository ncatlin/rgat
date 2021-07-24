namespace rgatCore.Threads
{
    public class ConditionalRendererThread : TraceProcessorWorker
    {
        TraceRecord RenderedTrace = null;

        public ConditionalRendererThread(TraceRecord _renderedTrace)
        {
            RenderedTrace = _renderedTrace;
        }

        public void ThreadProc()
        {

        }
    }
}
