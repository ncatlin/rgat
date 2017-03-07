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
The thread that performs low (ie:periodic) performance rendering of all graphs for the preview pane
*/

#include <stdafx.h>
#include "render_preview_thread.h"
#include "plotted_graph.h"
#include "traceMisc.h"
#include "rendering.h"

//thread handler to build graph for each thread
//allows display in thumbnail style format
void preview_renderer::main_loop()
{
	alive = true;

	while ((!piddata || piddata->plottedGraphs.empty()) && !die)
		Sleep(200);

	const int outerDelay = clientState->config->preview.processDelay;
	const int innerDelay = clientState->config->preview.threadDelay;
	vector<plotted_graph *> graphlist;
	map <PID_TID, void *>::iterator graphIt;

	int dietimer = -1;
	
	while (!clientState->die && dietimer != 0)
	{
		//if this closes with the process then previews are left unrendered
		if (dietimer == 0) break;
		if (die && dietimer-- < 0)
			dietimer = 120;

		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly

		obtainMutex(piddata->graphsListMutex, 9011);
		graphIt = piddata->plottedGraphs.begin();
		for (; graphIt != piddata->plottedGraphs.end(); graphIt++)
		{
			plotted_graph *g = (plotted_graph *)graphIt->second;
			if (g->increase_thread_references(261))
				graphlist.push_back(g);
		}
		dropMutex(piddata->graphsListMutex);

		vector<plotted_graph *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			//check for trace data that hasn't been rendered yet
			plotted_graph *graph = *graphlistIt;
			proto_graph *protoGraph = graph->get_protoGraph();
			if ((graph->previewnodes->get_numVerts() < protoGraph->get_num_nodes()) ||
				(graph->previewlines->get_renderedEdges() < protoGraph->get_num_edges()))
				graph->render_preview_graph(clientState);
			
			if (die) break;
			Sleep(innerDelay);
			++graphlistIt;
		}
		
		for (graphlistIt = graphlist.begin(); graphlistIt != graphlist.end(); graphlistIt++)
			((plotted_graph *)*graphlistIt)->decrease_thread_references(261);

		graphlist.clear();

		int waitForNextIt = 0;
		while (waitForNextIt < outerDelay && !die)
		{
			Sleep(50);
			waitForNextIt += 50;
		}
	}
	alive = false;
}

