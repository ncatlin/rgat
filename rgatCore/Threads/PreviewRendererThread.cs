using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace rgatCore.Threads
{
    class PreviewRendererThread
    {
        TraceRecord RenderedTrace = null;
		bool running = false;
		public rgatState rgatState = null;

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
				graphlist = RenderedTrace.GetPlottedGraphsList(eRenderingMode.ePreview);

				moreRenderingNeeded = false;
				foreach (PlottedGraph graph in graphlist)
				{
					//check for trace data that hasn't been rendered yet
					ProtoGraph protoGraph = graph.internalProtoGraph;
					lock (graph.RenderingLock)
					{
						if ((graph.NodesDisplayData.CountVerts() < protoGraph.get_num_nodes()) ||
							(graph.EdgesDisplayData.CountRenderedEdges < protoGraph.get_num_edges()))
						{
							//Console.WriteLine($"Rendering new preview verts for thread {graph.tid}");
							moreRenderingNeeded = true;
							graph.render_static_graph();
						}
					}

					if (!running) break;
					Thread.Sleep((int)GlobalConfig.Preview_PerThreadLoopSleepMS);
				}
				/*
				for (auto graph : graphlist)
				{
					graph.decrease_thread_references(1288);
				}
				*/
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
