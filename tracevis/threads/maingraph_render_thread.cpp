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

void maingraph_render_thread::updateMainRender(thread_graph_data *graph)
{

	render_static_graph(graph, clientState);

	updateTitle_NumPrimitives(clientState->maindisplay, clientState, graph->get_mainnodes()->get_numVerts(),
		graph->get_mainlines()->get_renderedEdges());
}


void maingraph_render_thread::performMainGraphRendering(thread_graph_data *graph)
{
	graph->setGraphBusy(true);
	
	if (
		(graph->get_mainnodes()->get_numVerts() < graph->get_num_nodes()) ||
		(graph->get_mainlines()->get_renderedEdges() < graph->get_num_edges()) ||
		clientState->rescale || clientState->activeGraph->vertResizeIndex)
	{
		updateMainRender(graph);
	}
	
	if (graph->active)
	{
		if (clientState->modes.animation)
			graph->render_live_animation(clientState->config->animationFadeRate);
	}
	else if (graph->terminated)
	{
		clientState->animationUpdate = 0;
		clientState->modes.animation = false;
		graph->reset_animation();
		graph->terminated = false;
		if (clientState->highlightData.highlightState)
		{
			TraceVisGUI* gui = (TraceVisGUI*)clientState->widgets;
			gui->highlightWindow->updateHighlightNodes(&clientState->highlightData,
				graph, clientState->activePid);
		}
	}

	else if (!graph->active && clientState->animationUpdate)
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
	thread_graph_data *activeGraph;
	int renderFrequency = clientState->config->renderFrequency;

	while (!clientState->die)
	{
		activeGraph = clientState->activeGraph;
		if (!activeGraph) {
			Sleep(5); continue;
		}
		performMainGraphRendering(activeGraph);
		Sleep(renderFrequency);
	}
	alive = false;
}