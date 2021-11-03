using rgat.Widgets;

using System.Threading;

namespace rgat.Threads
{
    internal class VisualiserBarRendererThread : TraceProcessorWorker
    {
        public VisualiserBarRendererThread(VisualiserBar visualiserbar)
        {
            _visualiserBarWidget = visualiserbar;
        }


        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"VisualiserBarRenderer";
            WorkerThread.Start();
        }

        public static void Dispose()
        {

        }

        private readonly VisualiserBar _visualiserBarWidget;

        public void ThreadProc()
        {
            PlottedGraph? activeGraph;
            while (!rgatState.rgatIsExiting)
            {
                activeGraph = rgatState.GetActiveGraph();
                while (activeGraph == null)
                {
                    Thread.Sleep(50);
                    if (rgatState.rgatIsExiting)
                    {
                        Finished();
                        return;
                    }
                    activeGraph = rgatState.GetActiveGraph();
                    continue;
                }

                if (activeGraph.InternalProtoGraph.Terminated)
                {
                    _visualiserBarWidget.GenerateReplay(activeGraph.InternalProtoGraph);
                }
                else
                {
                    _visualiserBarWidget.GenerateLive(activeGraph.InternalProtoGraph);
                }

                _visualiserBarWidget.Render();
                Thread.Sleep(GlobalConfig.MainGraphRenderDelay + 100);
            }
            Finished();
        }
    }
}
