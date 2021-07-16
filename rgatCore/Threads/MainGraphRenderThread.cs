using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Timers;

namespace rgatCore.Threads
{
    class MainGraphRenderThread : TraceProcessorWorker
    {
        public MainGraphRenderThread(GraphPlotWidget maingraphwidget)
        {
            _graphWidget = maingraphwidget;

            _IrregularActionTimer = new System.Timers.Timer(600);
            _IrregularActionTimer.Elapsed += FireIrregularTimer;
            _IrregularActionTimer.AutoReset = true;

        }


        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"MainGraphRenderer";
            WorkerThread.Start();
            _IrregularActionTimer.Start();
        }

        public void Dispose()
        {
            _IrregularActionTimer?.Stop();
            _IrregularActionTimer?.Dispose();

        }

        GraphPlotWidget _graphWidget;
        int _nextReplayStep = 0;
        int _FramesBetweenAnimationUpdates = 2;

        System.Timers.Timer _IrregularActionTimer;
        bool _IrregularActionTimerFired;

        private void FireIrregularTimer(object sender, ElapsedEventArgs e) { _IrregularActionTimerFired = true; }

        void update_rendering(PlottedGraph graph)
        {
            ProtoGraph protoGraph = graph.InternalProtoGraph;
            if (protoGraph == null || protoGraph.EdgeList.Count == 0) return;

            //if (graph.NodesDisplayData == null)// || !graph.setGraphBusy(true, 2))
            //	return;

            if (graph.ReplayState == PlottedGraph.REPLAY_STATE.eEnded && protoGraph.Terminated)
            {
                graph.ResetAnimation();
            }

            //update the render if there are more verts/edges or graph is being resized

            graph.UpdateMainRender();

            if (!protoGraph.Terminated)
            {
                if (graph.IsAnimated)
                    graph.render_live_animation(GlobalConfig.animationFadeRate);
            }
            else
            {
                if (graph.ReplayState == PlottedGraph.REPLAY_STATE.ePlaying || graph.userSelectedAnimPosition != -1)
                {
                    if (--_nextReplayStep <= 0)
                    {
                        graph.render_replay_animation(GlobalConfig.animationFadeRate);
                        _nextReplayStep = _FramesBetweenAnimationUpdates;
                    }
                }
            }


        }


        public void ThreadProc()
        {
            PlottedGraph activeGraph = null;

            while (!_clientState.rgatIsExiting)
            {

                activeGraph = _clientState.getActiveGraph(false);
                while (activeGraph == null)
                {
                    Thread.Sleep(50);
                    if (_clientState.rgatIsExiting)
                    {
                        Finished();
                        return;
                    }
                    activeGraph = _clientState.getActiveGraph(false);
                    continue;
                }

                update_rendering(activeGraph);

                if (_IrregularActionTimerFired)
                    _graphWidget.PerformIrregularActions();

                _graphWidget.GenerateMainGraph();

                //todo get rid of this 1000 after testing
                //Thread.Sleep(GlobalConfig.renderFrequency + 100);
            }
            Finished();
        }
    }
}
