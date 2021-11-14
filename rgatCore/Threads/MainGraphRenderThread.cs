using System;
using System.Threading;

namespace rgat.Threads
{
    internal class MainGraphRenderThread : TraceProcessorWorker
    {
        public MainGraphRenderThread(GraphPlotWidget maingraphwidget)
        {
            _graphWidget = maingraphwidget;
            System.Diagnostics.Debug.Assert(maingraphwidget != null);
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc)
            {
                Name = $"MainGraphRenderer"
            };
            WorkerThread.Start();
        }

        public static void Dispose()
        {
        }

        private readonly GraphPlotWidget _graphWidget;
        private int _nextReplayStep = 0;
        private readonly int _FramesBetweenAnimationUpdates = 2;

        private void update_rendering(PlottedGraph graph)
        {
            ProtoGraph protoGraph = graph.InternalProtoGraph;
            if (protoGraph == null || protoGraph.EdgeCount == 0)
            {
                return;
            }

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
                {
                    graph.ProcessLiveAnimationUpdates(out int doneCount);
                }
            }
            else
            {
                if (graph.InternalProtoGraph.TraceData.DiscardTraceData is false &&
                    (graph.ReplayState == PlottedGraph.REPLAY_STATE.Playing ||
                    graph._userSelectedAnimPosition != -1))
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
            System.Diagnostics.Stopwatch st = new();
            PlottedGraph? activeGraph;
            int exceptionCount = 0;

            Veldrid.CommandList cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();
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


                st.Restart();
                try
                {
                    update_rendering(activeGraph);
                }
                catch (Exception e)
                {
                    Logging.RecordException($"update_rendering error: {e.Message}", e);
                    if (exceptionCount++ > 5)
                    {
                        Logging.RecordError("Maingraph renderer terminating due to excess exceptions");
                        break;
                    }
                }

                st.Stop();
                //if (st.ElapsedMilliseconds > 0) System.Console.WriteLine($"u_R took {st.ElapsedMilliseconds} ms");

                //st.Restart();

                try
                {
                    _graphWidget.GenerateMainGraph(cl);
                }
                catch (Exception e)
                {
                    Logging.RecordException($"update_rendering error: {e.Message}", e);
                    if (exceptionCount++ > 5)
                    {
                        Logging.RecordError("Maingraph renderer terminating due to excess exceptions");
                        break;
                    }
                }



                //clear staging buffers
                //https://github.com/mellinoe/veldrid/issues/411
                cl.Dispose();
                cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();
                st.Stop();
                //if (st.ElapsedMilliseconds > 0) System.Console.WriteLine($"gmg took {st.ElapsedMilliseconds} ms");

                Thread.Sleep(GlobalConfig.MainGraphRenderDelay);

            }

            Finished();
        }


    }
}
