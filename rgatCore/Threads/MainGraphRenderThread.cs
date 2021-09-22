using System.Threading;

namespace rgat.Threads
{
    class MainGraphRenderThread : TraceProcessorWorker
    {
        public MainGraphRenderThread(GraphPlotWidget maingraphwidget)
        {
            _graphWidget = maingraphwidget;
            System.Diagnostics.Debug.Assert(maingraphwidget != null);
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"MainGraphRenderer";
            WorkerThread.Start();
        }

        public void Dispose()
        {
        }

        readonly GraphPlotWidget _graphWidget;
        int _nextReplayStep = 0;
        readonly int _FramesBetweenAnimationUpdates = 2;


        void update_rendering(PlottedGraph graph)
        {
            ProtoGraph protoGraph = graph.InternalProtoGraph;
            if (protoGraph == null || protoGraph.EdgeList.Count == 0) return;

            //if (graph.NodesDisplayData == null)// || !graph.setGraphBusy(true, 2))
            //	return;

            if (graph.ReplayState == PlottedGraph.REPLAY_STATE.Ended && protoGraph.Terminated)
            {
                graph.ResetAnimation();
            }

            //update the render if there are more verts/edges or graph is being resized

            graph.RenderGraph();

            if (!protoGraph.Terminated)
            {
                if (graph.IsAnimated)
                    graph.ProcessLiveAnimationUpdates();
            }
            else
            {
                if (graph.ReplayState == PlottedGraph.REPLAY_STATE.Playing || graph._userSelectedAnimPosition != -1)
                {
                    if (--_nextReplayStep <= 0)
                    {
                        graph.ProcessReplayUpdates();
                        _nextReplayStep = _FramesBetweenAnimationUpdates;
                    }
                }
            }


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

                update_rendering(activeGraph);

                _graphWidget.GenerateMainGraph(cl);

                //todo get rid of this 1000 after testing
                if (GlobalConfig.MainGraphRenderDelay > 0)
                    Thread.Sleep(GlobalConfig.MainGraphRenderDelay);
            }

            Finished();
        }


    }
}
