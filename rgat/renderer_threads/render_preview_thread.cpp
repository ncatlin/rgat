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
The thread that performs low (ie:periodic) performance rendering of all graphs for the preview pane
*/

#include <stdafx.h>
#include "render_preview_thread.h"
#include "graphplots/plotted_graph.h"
#include "traceMisc.h"
#include "previewPlotGLWidget.h"
#include "ui_rgat.h"

//thread handler to build graph for each thread
//allows display in thumbnail style format
//also gathers some statistics and logs for the graph (like external calls)
void preview_renderer::main_loop()
{
	alive = true;


	vector<plotted_graph *> graphlist;


	int dietimer = -1;
	bool moreRenderingNeeded = false;

	while (!clientState->rgatIsExiting() && (dietimer != 0))
	{
		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly
		runRecord->getPlottedGraphs(&graphlist);

		size_t graphsToRender = graphlist.size();
		float targetFPS = (float)clientState->config.preview.FPS;
		int outerDelay = clientState->config.preview.processDelay; //about 100
		int innerDelay = clientState->config.preview.threadDelay;  //about 20

		vector<plotted_graph *>::iterator graphlistIt = graphlist.begin();

		moreRenderingNeeded = false;
		while (graphlistIt != graphlist.end())
		{
			//check for trace data that hasn't been rendered yet
			plotted_graph *graph = *graphlistIt;
			proto_graph *protoGraph = graph->get_protoGraph();
			if ((graph->previewnodes->get_numVerts() < protoGraph->get_num_nodes()) ||
				(graph->previewlines->get_renderedEdges() < protoGraph->get_num_edges()))
			{
				moreRenderingNeeded = true;
				graph->render_preview_graph();
			}
			
			if (die) break;
			Sleep(innerDelay);
			++graphlistIt;
		}
		
		for (auto graph : graphlist)
		{
			graph->decrease_thread_references(1288);
		}
		graphlist.clear();

		int waitForNextIt = 0;
		while (waitForNextIt < outerDelay && !die)
		{
			Sleep(50);
			waitForNextIt += 50;
		}

		if (dietimer < 0 && !moreRenderingNeeded && !runRecord->is_running())
			dietimer = 60;
		else if (dietimer > 0)
			dietimer--;

	}
	alive = false;
}

