using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Timers;

namespace rgatCore.Threads
{
    class MainGraphRenderThread
    {
        private Thread runningThread = null;
        public MainGraphRenderThread(rgatState _clientState, GraphPlotWidget maingraphwidget)
        {
            rgatState = _clientState;
            _graphWidget = maingraphwidget;
            runningThread = new Thread(ThreadProc);
            runningThread.Name = "MainGraphRender";
            runningThread.Start();

            _IrregularActionTimer = new System.Timers.Timer(600);
            _IrregularActionTimer.Elapsed += FireIrregularTimer;
            _IrregularActionTimer.AutoReset = true;
            _IrregularActionTimer.Start();

        }

        public void Dispose()
        {
            if (_IrregularActionTimer != null) _IrregularActionTimer.Dispose();
        }

        private rgatState rgatState = null;
        public bool running = true;
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
            running = true;

            while (!rgatState.rgatIsExiting)
            {

                activeGraph = rgatState.getActiveGraph(false);
                while (activeGraph == null)
                {
                    Thread.Sleep(50);
                    if (rgatState.rgatIsExiting) return;
                    activeGraph = rgatState.getActiveGraph(false);
                    continue;
                }

                update_rendering(activeGraph);

                if (_IrregularActionTimerFired)
                  _graphWidget.PerformIrregularActions();

                _graphWidget.GenerateMainGraph();

                //todo get rid of this 1000 after testing
                //Thread.Sleep(GlobalConfig.renderFrequency + 100);
            }

            running = false;
        }
    }
}
