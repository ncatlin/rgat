using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace rgatCore.Threads
{
    class PreviewRendererThread
    {
        TraceRecord RenderedTrace;
        bool running;
        public rgatState rgatState;

        public PreviewRendererThread(TraceRecord _renderedTrace, rgatState _clientState)
        {
            RenderedTrace = _renderedTrace;
            rgatState = _clientState;
        }

        public void ThreadProc()
        {
            running = true;
            List<PlottedGraph> graphlist;
            int StopTimer = -1;
            bool moreRenderingNeeded = false;

            while (!rgatState.rgatIsExiting)
            {
                //only write we are protecting against happens while creating new threads
                //so not important to release this quickly
                graphlist = RenderedTrace.GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);

                moreRenderingNeeded = false;
                foreach (PlottedGraph graph in graphlist)
                {
                    if (graph == null || graph == rgatState.ActiveGraph) continue;

                    //check for trace data that hasn't been rendered yet
                    ProtoGraph protoGraph = graph.internalProtoGraph;

                        //Console.WriteLine($"Rendering new preview verts for thread {graph.tid}");
                        graph.render_graph();
                        if (!graph.RenderingComplete())
                            moreRenderingNeeded = true;

                    if (!running) break;
                    Thread.Sleep((int)GlobalConfig.Preview_PerThreadLoopSleepMS);
                }

                graphlist.Clear();

                int waitForNextIt = 0;
                while (waitForNextIt < GlobalConfig.Preview_PerProcessLoopSleepMS && running)
                {
                    Thread.Sleep(50);
                    waitForNextIt += 50;
                }

                if (StopTimer < 0 && !moreRenderingNeeded && !RenderedTrace.IsRunning)
                    StopTimer = 60;
                else if (StopTimer > 0)
                    StopTimer--;

            }
            running = false;
        }

    }
}
