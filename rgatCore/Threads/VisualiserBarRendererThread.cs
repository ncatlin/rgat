using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.Text;

using System.Threading;
using System.Timers;

namespace rgat.Threads
{
    class VisualiserBarRendererThread : TraceProcessorWorker
    {
        public VisualiserBarRendererThread(VisualiserBar visualiserbar)
        {
            _visualiserBarWidget = visualiserbar;

            _IrregularActionTimer = new System.Timers.Timer(600);
            _IrregularActionTimer.Elapsed += FireIrregularTimer;
            _IrregularActionTimer.AutoReset = true;

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
            _IrregularActionTimer?.Stop();
            _IrregularActionTimer?.Dispose();

        }

        VisualiserBar _visualiserBarWidget;

        System.Timers.Timer _IrregularActionTimer;
        bool _IrregularActionTimerFired;

        private void FireIrregularTimer(object sender, ElapsedEventArgs e) { _IrregularActionTimerFired = true; }

        void update_rendering(PlottedGraph graph)
        {


        }

        public void ThreadProc()
        {
            PlottedGraph? activeGraph;
            Veldrid.CommandList cl = _clientState._GraphicsDevice.ResourceFactory.CreateCommandList();
            while (!rgatState.rgatIsExiting)
            {

                activeGraph = _clientState.getActiveGraph();
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
