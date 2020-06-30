using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Threads
{
    class MainGraphRenderThread
    {
		MainGraphRenderThread(rgatState _clientState) => rgatState = _clientState;

		public rgatState rgatState = null;
		public bool running = true;

		void update_rendering(PlottedGraph graph)
		{
			ProtoGraph protoGraph = graph.internalProtoGraph;
			if (protoGraph == null || protoGraph.edgeList.Count == 0) return;

			if (graph.mainnodesdata == null)// || !graph.setGraphBusy(true, 2))
				return;

			graph.reset_animation_if_scheduled();

			//update the render if there are more verts/edges or graph is being resized
			if (
				(graph.mainnodesdata.CountVerts < protoGraph.get_num_nodes()) ||
				(graph.mainlinedata.CountRenderedEdges < protoGraph.get_num_edges()) ||
				graph.vertResizeIndex != 0)
			{
				graph.UpdateMainRender();
			}

			if (protoGraph.IsActive)
			{
				if (graph.isAnimated())
					graph.render_live_animation(GlobalConfig.animationFadeRate);
				else
					graph.highlight_last_active_node();
			}
			else if (protoGraph.terminated)
			{
				graph.schedule_animation_reset();
				graph.reset_animation_if_scheduled();
				protoGraph.terminated = false;
			}

			else if (graph.replayState == ePlaying || graph.userSelectedAnimPosition != -1)
			{
				graph.render_replay_animation(GlobalConfig.animationFadeRate);
			}

			graph.setGraphBusy(false, 2);
		}

		void perform_full_render(PlottedGraph activeGraph, bool replot_existing)
		{

			//save current rotation/scaling
			float xrot = activeGraph.view_shift_x, yrot = activeGraph.view_shift_y;
			double zoom = activeGraph.cameraZoomlevel;
			GRAPH_SCALE newScaleFactors = *activeGraph.main_scalefactors;

			//schedule purge of the current rendering
			activeGraph.setBeingDeleted();
			activeGraph.decrease_thread_references(1);

			rgatState.clearActiveGraph();

			TraceRecord activeTrace = activeGraph.internalProtoGraph.get_traceRecord();

			while (rgatState.getActiveGraph(false) == activeGraph)
				std::this_thread::sleep_for(25ms);
			activeTrace.graphListLock.lock () ;

			ProtoGraph protoGraph = activeGraph.internalProtograph;

			activeGraph.setGraphBusy(true, 101);

			activeTrace.plottedGraphs.at(protoGraph.get_TID()) = NULL;

			//now everything has finished with the old rendering, do the actual deletion
			delete activeGraph;
			Console.WriteLine("Deleted graph " + activeGraph);

			//create a new rendering
			activeGraph = rgatState.createNewPlottedGraph(protoGraph);
			if (replot_existing)
			{
				activeGraph.initialiseCustomDimensions(newScaleFactors);
				activeGraph.view_shift_x = xrot;
				activeGraph.view_shift_y = yrot;
				activeGraph.cameraZoomlevel = zoom;
			}
			else
			{
				activeGraph.initialiseDefaultDimensions();
			}

			Debug.Assert(rgatState.setActiveGraph(activeGraph));
			activeTrace.plottedGraphs.at(protoGraph.get_TID()) = activeGraph;

			activeTrace.graphListLock.unlock();

			//if they dont exist, create threads to rebuild alternate renderings
			if (!activeTrace.ProcessThreads.previewThread.is_alive())
			{
				std::thread prevthread(&preview_renderer::ThreadEntry, activeTrace.ProcessThreads.previewThread);
				prevthread.detach();
			}

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
		}

		void ThreadProc()
		{
			PlottedGraph activeGraph = null;
			running = true;

			while (!rgatState.rgatIsExiting())
			{

				activeGraph = (PlottedGraph)rgatState.getActiveGraph(false);
				while (!activeGraph || !activeGraph.get_mainlines())
				{
					std::this_thread::sleep_for(50ms);
					activeGraph = (PlottedGraph)rgatState.getActiveGraph(false);
					continue;
				}

				if (activeGraph.increase_thread_references(1))
				{
					bool layoutChanged = activeGraph.getLayout() != rgatState.newGraphLayout;
					bool doReplot = activeGraph.needsReplotting();
					if (layoutChanged || doReplot)
					{
						//graph gets destroyed, this resets references, don't need to decrease
						perform_full_render(activeGraph, doReplot);
						continue;
					}

					update_rendering(activeGraph);
					activeGraph.decrease_thread_references(1);
				}
				activeGraph = NULL;

				std::this_thread::sleep_for(std::chrono::milliseconds(rgatState.config.renderFrequency));
			}

			running = false;
		}
	}
}
