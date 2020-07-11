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
			runningThread.Start();
		}



		private rgatState rgatState = null;
		public bool running = true;

		static void update_rendering(PlottedGraph graph)
		{
			ProtoGraph protoGraph = graph.internalProtoGraph;
			if (protoGraph == null || protoGraph.edgeList.Count == 0) return;

			if (graph.mainnodesdata == null)// || !graph.setGraphBusy(true, 2))
				return;

			graph.reset_animation_if_scheduled();

			//update the render if there are more verts/edges or graph is being resized
			if (
				(graph.mainnodesdata.CountVerts() < protoGraph.get_num_nodes()) ||
				(graph.mainlinedata.CountRenderedEdges < protoGraph.get_num_edges()) ||
				graph.vertResizeIndex != 0)
			{
				graph.UpdateMainRender();
			}

			if (protoGraph.IsActive)
			{
				if (graph.IsAnimated)
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

			else if (graph.replayState == PlottedGraph.REPLAY_STATE.ePlaying || 
				graph.userSelectedAnimPosition != -1)
			{
				graph.render_replay_animation(GlobalConfig.animationFadeRate);
			}

			//graph.setGraphBusy(false, 2);
		}

		void perform_full_render(PlottedGraph renderGraph, bool replot_existing)
		{

			//_rgatstate.ActiveGraph?.InitMainGraphTexture(graphWidgetSize, _gd);


			//save current rotation/scaling
			float xrot = renderGraph.view_shift_x, yrot = renderGraph.view_shift_y;
			double zoom = renderGraph.cameraZoomlevel;
			GRAPH_SCALE newScaleFactors = renderGraph.main_scalefactors;

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

			activeTrace.PlottedGraphs[protoGraph.ThreadID] = null;

			//now everything has finished with the old rendering, do the actual deletion
			//delete activeGraph;
			Console.WriteLine("Deleted graph " + renderGraph);

			//create a new rendering
			renderGraph = rgatState.CreateNewPlottedGraph(protoGraph);
			if (replot_existing)
			{
				renderGraph.initialiseCustomDimensions(newScaleFactors);
				renderGraph.view_shift_x = xrot;
				renderGraph.view_shift_y = yrot;
				renderGraph.cameraZoomlevel = zoom;
			}
			else
			{
				renderGraph.InitialiseDefaultDimensions();
			}

			bool setactive = rgatState.SetActiveGraph(renderGraph);
			Debug.Assert(setactive);
			activeTrace.PlottedGraphs[protoGraph.ThreadID] = renderGraph;

			//activeTrace.graphListLock.unlock();
			//if they dont exist, create threads to rebuild alternate renderings
			/*
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
			*/
		}

		public void ThreadProc()
		{
			PlottedGraph activeGraph = null;
			running = true;

			while (!rgatState.rgatIsExiting)
			{

				activeGraph = (PlottedGraph)rgatState.getActiveGraph(false);
				while (activeGraph == null || activeGraph.mainlinedata == null)
				{
					Thread.Sleep(50);
					if (rgatState.rgatIsExiting) return;
					activeGraph = (PlottedGraph)rgatState.getActiveGraph(false);
					continue;
				}

				//TODO
				//if (activeGraph.increase_thread_references(1))
				if (true)
				{
					bool layoutChanged = activeGraph.layout != rgatState.newGraphLayout;
					if (layoutChanged || activeGraph.replotScheduled)
					{
						//graph gets destroyed, this resets references, don't need to decrease
						perform_full_render(activeGraph, activeGraph.replotScheduled);
						continue;
					}

					update_rendering(activeGraph);
					//activeGraph.decrease_thread_references(1);
				}
				activeGraph = null;

				Thread.Sleep(GlobalConfig.renderFrequency);
			}

			running = false;
		}
	}
}
