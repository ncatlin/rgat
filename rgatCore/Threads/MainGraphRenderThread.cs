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

		public void SetRenderingMode(eRenderingMode newMode)
        {

        }

		private rgatState rgatState = null;
		public bool running = true;

		static void update_rendering(PlottedGraph graph)
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
				Console.WriteLine("Doing updatemainrender");
				graph.UpdateMainRender();
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
					graph.render_replay_animation(GlobalConfig.animationFadeRate);
				}
				
			}

			graph.draw_highlight_lines();


			//graph.setGraphBusy(false, 2);
		}

		void perform_full_render(PlottedGraph renderGraph, bool replot_existing)
		{

			//_rgatstate.ActiveGraph?.InitMainGraphTexture(graphWidgetSize, _gd);


			//save current rotation/scaling
			GRAPH_SCALE newScaleFactors = renderGraph.scalefactors;

			//schedule purge of the current rendering
			//renderGraph.setBeingDeleted();
			//renderGraph.decrease_thread_references(1);

			rgatState.ClearActiveGraph();

			TraceRecord activeTrace = renderGraph.internalProtoGraph.TraceData;

			while (rgatState.getActiveGraph(false) == renderGraph)
				Thread.Sleep(25);
			//activeTrace.graphListLock.lock () ;

			ProtoGraph protoGraph = renderGraph.internalProtoGraph;

			//renderGraph.setGraphBusy(true, 101);
			activeTrace.PlottedGraphs[protoGraph.ThreadID][eRenderingMode.eStandardControlFlow] = null;

			//now everything has finished with the old rendering, do the actual deletion
			//delete activeGraph;


			Console.WriteLine("Deleted graph " + renderGraph);

			//create a new rendering
			rgatState.CreateNewPlottedGraph(protoGraph, out PlottedGraph maingraph, out PlottedGraph previewgraph);
			if (replot_existing)
			{
				maingraph.initialiseCustomDimensions(newScaleFactors);
			}

			bool setactive = rgatState.SetActiveGraph(renderGraph); //todo can we get rid
			Debug.Assert(setactive);
			activeTrace.PlottedGraphs[protoGraph.ThreadID][eRenderingMode.eStandardControlFlow] = renderGraph;
			activeTrace.PlottedGraphs[protoGraph.ThreadID][eRenderingMode.ePreview] = previewgraph; //do we want to rerender this?

			//activeTrace.graphListLock.unlock();
			//if they dont exist, create threads to rebuild alternate renderings
			/*

			if (!activeTrace.ProcessThreads.conditionalThread.is_alive())
			{
				std::thread condthread(&conditional_renderer::ThreadEntry, activeTrace.ProcessThreads.conditionalThread);
				condthread.detach();
			}

			if (!activeTrace.ProcessThreads.heatmapThread.is_alive())
			{
				std::thread heatthread(&heatmap_renderer::ThreadEntry, activeTrace.ProcessThreads.heatmapThread);
				heatthread.detach();
			}
			*/
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

				if (true)
				{
					
					bool layoutChanged = activeGraph.layout != rgatState.newGraphLayout;
					if (layoutChanged || activeGraph.NeedReplotting)
					{
						activeGraph.ReRender();
						continue;
					}
			
					update_rendering(activeGraph);
				}
				Thread.Sleep(GlobalConfig.renderFrequency);
			}

			running = false;
		}
	}
}
