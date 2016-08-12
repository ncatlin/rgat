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

	while (true)
	{
		
		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly

		//todo: change to work on all pids
		if (!piddata || piddata->graphs.empty())
		{
			Sleep(200);
			continue;
		}

		if (!obtainMutex(piddata->graphsListMutex, "Render Preview Thread")) return;

		map <int, void *>::iterator graphit = piddata->graphs.begin();
		while (graphit != piddata->graphs.end())
		{
			thread_graph_data *graph = (thread_graph_data *)graphit->second;
			if ((graph->previewverts->get_numVerts() < graph->get_num_verts()) ||
				(graph->previewlines->get_renderedEdges() < graph->edgeList.size()))
				render_preview_graph(graph, false, clientState);

			graphit++;
		}
		
		ReleaseMutex(piddata->graphsListMutex);
		Sleep(PREVIEW_UPDATE_DELAY_MS);
	}
}

