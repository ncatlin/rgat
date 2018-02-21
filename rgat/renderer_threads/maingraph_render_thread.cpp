/*
Copyright 2016-2017 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
The thread that performs high (ie:interactive) performance rendering of the selected graph
*/

#include "stdafx.h"
#include "maingraph_render_thread.h"
#include "processLaunching.h"
#include "ui_rgat.h"

void maingraph_render_thread::update_rendering(plotted_graph *graph)
{
	proto_graph *protoGraph = graph->get_protoGraph();
	if (!protoGraph || protoGraph->edgeList.empty()) return;

	if (!graph->get_mainnodes() || !graph->setGraphBusy(true, 2))
		return;

	graph->reset_animation_if_scheduled();

	//update the render if there are more verts/edges or graph is being resized
	if (
		(graph->get_mainnodes()->get_numVerts() < protoGraph->get_num_nodes()) ||
		(graph->get_mainlines()->get_renderedEdges() < protoGraph->get_num_edges()) ||
		graph->vertResizeIndex)
	{
		graph->updateMainRender();
	}
	
	if (protoGraph->active)
	{
		if (graph->isAnimated())
			graph->render_live_animation(clientState->config.animationFadeRate);
		else
			graph->highlight_last_active_node();
	}
	else if (protoGraph->terminated)
	{
		graph->schedule_animation_reset();	
		graph->reset_animation_if_scheduled();
		protoGraph->terminated = false;
	}

	else if (!protoGraph->active && (graph->replayState == ePlaying || graph->userSelectedAnimPosition != -1))
	{
		graph->render_replay_animation(clientState->config.animationFadeRate);
	}

	graph->setGraphBusy(false, 2);
}

void maingraph_render_thread::perform_full_render(plotted_graph *activeGraph, bool replot_existing)
{

	//save current rotation/scaling
	float xrot = activeGraph->view_shift_x, yrot = activeGraph->view_shift_y;
	double zoom = activeGraph->cameraZoomlevel;
	GRAPH_SCALE newScaleFactors = *activeGraph->main_scalefactors;

	//schedule purge of the current rendering
	activeGraph->setBeingDeleted();
	activeGraph->decrease_thread_references(1);

	clientState->clearActiveGraph();

	traceRecord *activeTrace = (traceRecord *)activeGraph->get_protoGraph()->get_traceRecord();

	while (clientState->getActiveGraph(false) == activeGraph)
		Sleep(25);
	activeTrace->graphListLock.lock();

	proto_graph *protoGraph = activeGraph->get_protoGraph();

	activeGraph->setGraphBusy(true, 101);

	activeTrace->plottedGraphs.at(protoGraph->get_TID()) = NULL;

	//now everything has finished with the old rendering, do the actual deletion
	delete activeGraph;

	//create a new rendering
	activeGraph = (plotted_graph *)clientState->createNewPlottedGraph(protoGraph);
	if (replot_existing)
	{
		activeGraph->initialiseCustomDimensions(newScaleFactors);
		activeGraph->view_shift_x = xrot;
		activeGraph->view_shift_y = yrot;
		activeGraph->cameraZoomlevel = zoom;
	}
	else
		activeGraph->initialiseDefaultDimensions();

	assert(clientState->setActiveGraph(activeGraph));
	activeTrace->plottedGraphs.at(protoGraph->get_TID()) = activeGraph;

	activeTrace->graphListLock.unlock();

	//if they dont exist, create threads to rebuild alternate renderings
	RGAT_THREADS_STRUCT *processThreads = (RGAT_THREADS_STRUCT *)activeTrace->processThreads;
	if (!processThreads->previewThread->is_alive())
	{
		std::thread prevthread(&preview_renderer::ThreadEntry, processThreads->previewThread);
		prevthread.detach();
	}

	if (!processThreads->conditionalThread->is_alive())
	{
		std::thread condthread(&conditional_renderer::ThreadEntry, processThreads->conditionalThread);
		condthread.detach();
	}

	if (!processThreads->heatmapThread->is_alive())
	{
		std::thread heatthread(&heatmap_renderer::ThreadEntry, processThreads->heatmapThread);
		heatthread.detach();
	}
}

void maingraph_render_thread::main_loop()
{
	plotted_graph *activeGraph = NULL;
	alive = true;

	while (!clientState->rgatIsExiting())
	{
		
		activeGraph = (plotted_graph *)clientState->getActiveGraph(false);
		while (!activeGraph || !activeGraph->get_mainlines()) 
		{
			Sleep(50);
			activeGraph = (plotted_graph *)clientState->getActiveGraph(false);
			continue;
		}

		if (activeGraph->increase_thread_references(1))
		{
			bool layoutChanged = activeGraph->getLayout() != clientState->newGraphLayout;
			bool doReplot = activeGraph->needsReplotting();
			if (layoutChanged || doReplot)
			{
				//graph gets destroyed, this handles references, don't need to decrease
				perform_full_render(activeGraph, doReplot);
				continue;
			}

			update_rendering(activeGraph);
			activeGraph->decrease_thread_references(1);
		}
		activeGraph = NULL;

		Sleep(clientState->config.renderFrequency);
	}

	alive = false;
}