using rgat.Widgets;

using System.Threading;
using System.Timers;

namespace rgat.Threads
{
    class VisualiserBarRendererThread : TraceProcessorWorker
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

        public void Dispose()
        {

        }

        readonly VisualiserBar _visualiserBarWidget;

        void update_rendering(PlottedGraph graph)
        {


        }

        public void ThreadProc()
        {
            PlottedGraph? activeGraph;
            while (!rgatState.rgatIsExiting)
            {
                activeGraph = _clientState!.getActiveGraph();
                while (activeGraph == null)
                {
                    Thread.Sleep(50);
                    if (rgatState.rgatIsExiting)
                    {
                        Finished();
                        return;
                    }
                    activeGraph = _clientState.getActiveGraph();
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
