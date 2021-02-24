using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace rgatCore.Threads
{
    class MainGraphRenderThread
    {
		private Thread runningThread = null;
		public MainGraphRenderThread(rgatState _clientState)
		{
			rgatState = _clientState;
			runningThread = new Thread(ThreadProc);
			runningThread.Name = "MainGraphRender";
			runningThread.Start();
		}


		private rgatState rgatState = null;
		public bool running = true;

		int _nextReplayStep = 0;
		int _FramesBetweenAnimationUpdates = 2;

		void update_rendering(PlottedGraph graph)
		{
			ProtoGraph protoGraph = graph.internalProtoGraph;
			if (protoGraph == null || protoGraph.edgeList.Count == 0) return;

			if (graph.NodesDisplayData == null)// || !graph.setGraphBusy(true, 2))
				return;

			if (graph.ReplayState == PlottedGraph.REPLAY_STATE.eEnded && protoGraph.Terminated)
			{
				graph.ResetAnimation();
			}

			//update the render if there are more verts/edges or graph is being resized
			if (
				(graph.NodesDisplayData.CountVerts() < protoGraph.get_num_nodes()) ||
				(graph.EdgesDisplayData.CountRenderedEdges < protoGraph.get_num_edges()) ||
				graph.vertResizeIndex != 0)
			{
				lock (graph.RenderingLock)
				{
					graph.UpdateMainRender();
				}
			}


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

			graph.draw_highlight_lines();
		}


		public void ThreadProc()
		{
			PlottedGraph activeGraph = null;
			running = true;

			while (!rgatState.rgatIsExiting)
			{

				activeGraph = (PlottedGraph)rgatState.getActiveGraph(false);
				while (activeGraph == null || activeGraph.EdgesDisplayData == null)
				{
					Thread.Sleep(50);
					if (rgatState.rgatIsExiting) return;
					activeGraph = rgatState.getActiveGraph(false);
					continue;
				}


				update_rendering(activeGraph);
				
				//todo get rid of this 1000 after testing
				Thread.Sleep(GlobalConfig.renderFrequency + 100);
			}

			running = false;
		}
	}
}
