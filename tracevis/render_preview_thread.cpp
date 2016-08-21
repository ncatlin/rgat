#include <stdafx.h>
#include "render_preview_thread.h"
#include "thread_graph_data.h"
#include "traceMisc.h"
#include "rendering.h"

void __stdcall graph_renderer::ThreadEntry(void* pUserData) {
	return ((graph_renderer*)pUserData)->rendering_thread();
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void graph_renderer::rendering_thread()
{
	thread_graph_data *activeGraph = 0;

	while (!piddata || piddata->graphs.empty())
	{
		Sleep(200);
		continue;
	}

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
			if ((graph->previewverts->get_numVerts() < graph->get_num_verts()) ||
				(graph->previewlines->get_renderedEdges() < graph->edgeList.size()))
				render_preview_graph(graph, false, clientState);
			Sleep(80);
			graphlistIt++;
		}
		
		Sleep(PREVIEW_UPDATE_DELAY_MS);
	}
}

