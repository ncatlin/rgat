#include "stdafx.h"
#include "maingraph_render_thread.h"
#include "GUIManagement.h"
#include "rendering.h"

void __stdcall maingraph_render_thread::ThreadEntry(void* pUserData) {
	return ((maingraph_render_thread*)pUserData)->rendering_thread();
}

void maingraph_render_thread::updateMainRender()
{
	render_main_graph(clientState);

	updateTitle_NumPrimitives(clientState->maindisplay, clientState, clientState->activeGraph->get_mainnodes()->get_numVerts(),
		clientState->activeGraph->get_mainlines()->get_renderedEdges());
}


void maingraph_render_thread::performMainGraphRendering(thread_graph_data *graph)
{

	if (
		(graph->get_mainnodes()->get_numVerts() < graph->get_num_nodes()) ||
		(graph->get_mainlines()->get_renderedEdges() < graph->get_num_edges()) ||
		clientState->rescale || clientState->activeGraph->vertResizeIndex)
	{
		updateMainRender();
	}

	if (!graph->active && clientState->animationUpdate)
	{
		int result = graph->updateAnimation(clientState->animationUpdate,
			clientState->modes.animation, clientState->skipLoop);
		if (clientState->skipLoop) clientState->skipLoop = false;

		if (clientState->modes.animation)
		{
			if (result == ANIMATION_ENDED)
			{
				graph->reset_animation();
				clientState->animationUpdate = 0;
				clientState->modes.animation = false;
				TraceVisGUI* widgets = (TraceVisGUI*)clientState->widgets;
				widgets->controlWindow->notifyAnimFinished();
			}
			else
				graph->update_animation_render(clientState->config->animationFadeRate);
		}
		else
			clientState->animationUpdate = 0;
	}

	if (graph->active)
	{
		if (clientState->modes.animation)
			graph->animate_latest(clientState->config->animationFadeRate);
	}
	else
		if (graph->terminated)
		{
			graph->reset_animation();
			clientState->modes.animation = false;
			graph->terminated = false;
			if (clientState->highlightData.highlightState)
			{
				TraceVisGUI* gui = (TraceVisGUI*)clientState->widgets;
				gui->highlightWindow->updateHighlightNodes(&clientState->highlightData,
					clientState->activeGraph,
					clientState->activePid);
			}
		}
}

void maingraph_render_thread::rendering_thread()
{
	thread_graph_data *activeGraph;
	while (true)
	{
		if (die) break;
		activeGraph = clientState->activeGraph;
		if (!activeGraph) {
			Sleep(5); continue;
		}

		performMainGraphRendering(activeGraph);
	}


}

maingraph_render_thread::maingraph_render_thread()
{
}


maingraph_render_thread::~maingraph_render_thread()
{
}
