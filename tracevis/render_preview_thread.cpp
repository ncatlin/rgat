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
#include "thread_graph_data.h"
#include "traceMisc.h"
#include "rendering.h"

void __stdcall preview_renderer::ThreadEntry(void* pUserData) {
	return ((preview_renderer*)pUserData)->rendering_thread();
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void preview_renderer::rendering_thread()
{
	thread_graph_data *activeGraph = 0;

	while (!piddata || piddata->graphs.empty())
	{
		Sleep(200);
		continue;
	}

	const int outerDelay = clientState->config->preview.processDelay;
	const int innerDelay = clientState->config->preview.threadDelay;
	vector<thread_graph_data *> graphlist;
	map <int, void *>::iterator graphIt;
	while (true)
	{
		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly

		if (!obtainMutex(piddata->graphsListMutex, 2000)) return;
		
		graphIt = piddata->graphs.begin();
		for (; graphIt != piddata->graphs.end(); graphIt++)
			graphlist.push_back((thread_graph_data *)graphIt->second);

		dropMutex(piddata->graphsListMutex);

		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			thread_graph_data *graph = *graphlistIt;
			if ((graph->previewnodes->get_numVerts() < graph->get_num_nodes()) ||
				(graph->previewlines->get_renderedEdges() < graph->get_num_edges()))
				render_preview_graph(graph, clientState);

			Sleep(innerDelay);
			++graphlistIt;
		}
		graphlist.clear();
		Sleep(outerDelay);
	}
}

