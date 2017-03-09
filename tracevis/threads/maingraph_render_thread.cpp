/*
Copyright 2016 Nia Catlin

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
#include "GUIManagement.h"
#include "rendering.h"

void maingraph_render_thread::performMainGraphRendering(plotted_graph *graph)
{
	if(!graph->setGraphBusy(true))
		return;
	proto_graph *protoGraph = graph->get_protoGraph();
	if (
		(graph->get_mainnodes()->get_numVerts() < protoGraph->get_num_nodes()) ||
		(graph->get_mainlines()->get_renderedEdges() < protoGraph->get_num_edges()) ||
		clientState->rescale || ((plotted_graph *)clientState->activeGraph)->vertResizeIndex)
	{
		graph->updateMainRender(clientState);
	}
	
	if (protoGraph->active)
	{
		if (clientState->modes.animation)
			graph->render_live_animation(clientState->config->animationFadeRate);
		else
			graph->set_last_active_node();
	}
	else if (protoGraph->terminated)
	{
		clientState->animationUpdate = 0;
		clientState->modes.animation = false;
		graph->reset_animation();
		protoGraph->terminated = false;
		HIGHLIGHT_DATA *highlightData = &graph->highlightData;
		if (highlightData->highlightState)
		{
			TraceVisGUI* gui = (TraceVisGUI*)clientState->widgets;
			gui->highlightWindow->updateHighlightNodes(highlightData, protoGraph, clientState->activePid);
		}
	}

	else if (!protoGraph->active && clientState->animationUpdate)
	{
		int animationResult = graph->render_replay_animation(clientState->animationUpdate, clientState->config->animationFadeRate);

		if (clientState->modes.animation)
		{
			if (animationResult == ANIMATION_ENDED)
			{
				graph->reset_animation();
				clientState->animationUpdate = 0;
				clientState->modes.animation = false;
				clientState->animFinished = true;
			}
		}
		else
			clientState->animationUpdate = 0;
	}

	graph->setGraphBusy(false);
}

void maingraph_render_thread::main_loop()
{
	alive = true;
	plotted_graph *activeGraph = 0;
	int renderFrequency = clientState->config->renderFrequency;

	while (!clientState->die)
	{
		
		activeGraph = (plotted_graph *)clientState->activeGraph;
		while (!activeGraph) {
			activeGraph = (plotted_graph *)clientState->activeGraph;
			Sleep(5); continue;
		}

		activeGraph->increase_thread_references();
		getMutex();
		performMainGraphRendering(activeGraph);
		dropMutex();

		activeGraph->decrease_thread_references();
		activeGraph = 0;

		Sleep(renderFrequency);
	}
	alive = false;
}