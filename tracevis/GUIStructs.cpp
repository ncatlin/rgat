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
Client state functions
*/
#include "stdafx.h"
#include "GUIStructs.h"
#include "plotted_graph.h"
#include "rendering.h"
#include "preview_pane.h"
#include "GUIManagement.h"

void VISSTATE::set_activeGraph(void *graph)
{
	if (activeGraph)
	{
		plotted_graph *oldGraph = (plotted_graph *)activeGraph;
		oldGraph->decrease_thread_references();
	}
	((plotted_graph *)graph)->increase_thread_references();
	activeGraph = graph;
}

void VISSTATE::change_mode(eUIEventCode mode)
{
	switch (mode)
	{
	case EV_BTN_WIREFRAME:
		modes.wireframe = !modes.wireframe;
		break;

	case EV_BTN_CONDITION:

		modes.conditional = !modes.conditional;
		if (modes.conditional)
		{
			modes.nodes = true;
			modes.heatmap = false;
			backgroundColour = config->conditional.background;
		}
		else
			backgroundColour = config->mainBackground;

		break;

	case EV_BTN_HEATMAP:

		modes.heatmap = !modes.heatmap;
		modes.nodes = !modes.heatmap;
		if (modes.heatmap) modes.conditional = false;
		break;

	case EV_BTN_PREVIEW:
	{
		al_destroy_bitmap(mainGraphBMP);
		modes.preview = !modes.preview;

		TraceVisGUI *mywidgets = (TraceVisGUI *)widgets;
		if (modes.preview)
		{
			mywidgets->setScrollbarVisible(true);
			mainGraphBMP = al_create_bitmap(mainFrameSize.width, mainFrameSize.height);
		}
		else
		{
			mywidgets->setScrollbarVisible(false);
			mainGraphBMP = al_create_bitmap(displaySize.width, mainFrameSize.height);
		}

		break;
	}
	case EV_BTN_DIFF:
		modes.heatmap = false;
		modes.conditional = false;
		break;

	case EV_BTN_NODES:
		modes.nodes = !modes.nodes;
		break;

	case EV_BTN_EDGES:
		modes.edges = !modes.edges;
		break;
	}
}


void VISSTATE::draw_display_diff(ALLEGRO_FONT *font, void **diffRenderer)
{
	diff_plotter *diffRendererPtr = *(diff_plotter **)diffRenderer;

	if (modes.diff == DIFF_STARTED) //diff graph built, display it
	{
		plotted_graph *graph1 = diffRendererPtr->get_graph(1);
		proto_graph *protoGraph1 = graph1->get_protoGraph();

		node_data *diffnode = 0;
		if (diffRendererPtr->wasDivergenceFound())
			diffnode = protoGraph1->safe_get_node(diffRendererPtr->get_diff_node());
		
		display_graph_diff(this, diffRendererPtr, diffnode);
	}

	else if (modes.diff == DIFF_SELECTED)//diff button clicked, build the graph first
	{
		change_mode(EV_BTN_DIFF);
		modes.diff = DIFF_STARTED;
		TraceVisGUI *mywidgets = (TraceVisGUI *)widgets;
		mywidgets->showHideDiffFrame();

		plotted_graph *graph1 = mywidgets->diffWindow->get_graph(1);
		plotted_graph *graph2 = mywidgets->diffWindow->get_graph(2);

		diff_plotter **diffRenderPtrPtr = (diff_plotter **)diffRenderer;
		*diffRenderPtrPtr = new diff_plotter(graph1, graph2, this);
		((diff_plotter*)*diffRenderPtrPtr)->render();
		diffRendererPtr = *(diff_plotter **)diffRenderer;
	}

	diffRendererPtr->display_diff_summary(20, LAYOUT_ICONS_Y + LAYOUT_ICONS_H, font, this);
}


/*
performs actions that need to be done quite often, but not every frame
this includes checking the locations of the screen edge on the sphere and
drawing new highlights for things that match the active filter
*/
void VISSTATE::performIrregularActions()
{
	SCREEN_EDGE_PIX TBRG;
	//update where camera is pointing on sphere, used to choose which node text to draw
	edge_picking_colours(this, &TBRG, true);

	leftcolumn = (int)floor(ADIVISIONS * TBRG.leftgreen) - 1;
	rightcolumn = (int)floor(ADIVISIONS * TBRG.rightgreen) - 1;

	plotted_graph * graph = (plotted_graph *)activeGraph;
	HIGHLIGHT_DATA *highlightData = &graph->highlightData;
	if (highlightData->highlightState && graph->get_protoGraph()->active)
	{
		((TraceVisGUI *)widgets)->highlightWindow->updateHighlightNodes(highlightData, graph->get_protoGraph(), activePid);
	}
}

void VISSTATE::initWireframeBufs()
{
	//wireframe drawn using glMultiDrawArrays which takes a list of vert starts/sizes
	wireframeStarts = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	wireframeSizes = (GLint *)malloc(WIREFRAMELOOPS * sizeof(GLint));
	for (int i = 0; i < WIREFRAMELOOPS; ++i)
	{
		wireframeStarts[i] = i*WF_POINTSPERLINE;
		wireframeSizes[i] = WF_POINTSPERLINE;
	}
}

void VISSTATE::displayActiveGraph()
{
	plotted_graph *thisActiveGraph = (plotted_graph *)activeGraph;
	if (!activeGraph) return;

	al_set_target_bitmap(mainGraphBMP);
	frame_gl_setup(this);

	al_clear_to_color(backgroundColour);

	//set to true if displaying the colour picking sphere
	if (!al_is_event_queue_empty(low_frequency_timer_queue))
	{
		al_flush_event_queue(low_frequency_timer_queue);
		performIrregularActions();
	}

	if (modes.wireframe)
		thisActiveGraph->maintain_draw_wireframe(this, wireframeStarts, wireframeSizes);

	if (modes.diff)
		draw_display_diff(PIDFont, &diffRenderer);

	if (!modes.diff) //not an else for clarity
		thisActiveGraph->performMainGraphDrawing(this);

	frame_gl_teardown();

	if (animFinished)
	{
		animFinished = false;
		((TraceVisGUI*)widgets)->controlWindow->notifyAnimFinished();
	}


	al_set_target_backbuffer(maindisplay);
	if (modes.preview)
	{
		if (previewRenderFrame++ % (TARGET_FPS / config->preview.FPS))
		{
			//update and draw preview graphs onto the previewpane bitmap
			redrawPreviewGraphs(this, &graphPositions);
			previewRenderFrame = 0;
		}
		//draw previews on the screen
		al_draw_bitmap(previewPaneBMP, mainFrameSize.width, MAIN_FRAME_Y, 0);
	}
	//draw the main big graph bitmap on the screen
	al_draw_bitmap(mainGraphBMP, 0, 0, 0);

	display_activeGraph_summary(20, 10, PIDFont, this);
}