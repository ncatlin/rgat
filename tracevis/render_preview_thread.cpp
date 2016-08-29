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

	while (true)
	{
		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly

		if (!obtainMutex(piddata->graphsListMutex, "Render Preview Thread")) return;
		vector<thread_graph_data *> graphlist;
		map <int, void *>::iterator graphit = piddata->graphs.begin();
		for (; graphit != piddata->graphs.end(); graphit++)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex, "Render Preview Thread glm");

		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			thread_graph_data *graph = *graphlistIt;
			if ((graph->previewnodes->get_numVerts() < graph->get_num_nodes()) ||
				(graph->previewlines->get_renderedEdges() < graph->get_num_edges()))
				render_preview_graph(graph, false, clientState);
			Sleep(innerDelay);
			graphlistIt++;
		}
		
		Sleep(outerDelay);
	}
}

