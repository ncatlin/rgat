#include "stdafx.h"
#include "render_conditional_thread.h"
#include "traceMisc.h"

void __stdcall conditional_renderer::ThreadEntry(void* pUserData) {
	return ((conditional_renderer*)pUserData)->conditional_thread();
}

bool conditional_renderer::render_graph_conditional(thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	if (!linedata || !linedata->get_numVerts()) return false;
	if (!obtainMutex(graph->edMutex, "Render Graph Conditional")) return false;
	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainverts();

	map<unsigned int, node_data>::iterator vertit = graph->get_vertStart();
	map<unsigned int, node_data>::iterator vertEnd = graph->get_vertEnd();
	if (vertit == vertEnd) return 0;
	if (graph->conditionalverts->get_numVerts() != vertsdata->get_numVerts())
	{
		std::advance(vertit, graph->conditionalverts->get_numVerts());
		if (vertit == vertEnd) return 0;

		GLfloat *vcol = graph->conditionalverts->acquire_col("1f");
		for (; vertit != vertEnd; vertit++)
		{
			int arraypos = vertit->second.index * COLELEMS;
			if (!vertit->second.ins || vertit->second.ins->conditional == false)
			{
				vcol[arraypos] = 0;
				vcol[arraypos + 1] = 0;
				vcol[arraypos + 2] = 0;
				vcol[arraypos + 3] = 0;
				continue;
			}

			//jump only seen to succeed
			if ((vertit->second.conditional & CONDTAKEN) && !(vertit->second.conditional & CONDNOTTAKEN))
			{
				vcol[arraypos] =  0;
				vcol[arraypos + 1] = 0;
				vcol[arraypos + 2] = 1;
				vcol[arraypos + 3] = 1;
				continue;
			}

			//jump only seen to fail
			if (!(vertit->second.conditional & CONDTAKEN) && (vertit->second.conditional & CONDNOTTAKEN))
			{
				vcol[arraypos] = 1;
				vcol[arraypos + 1] = 0;
				vcol[arraypos + 2] = 0;
				vcol[arraypos + 3] = 1;
				continue;
			}

			//jump seen to both fail and succeed
			if ((vertit->second.conditional & CONDTAKEN) && (vertit->second.conditional & CONDNOTTAKEN))
			{
				vcol[arraypos] = 1;
				vcol[arraypos + 1] = 0.5;
				vcol[arraypos + 2] = 0.3;
				vcol[arraypos + 3] = 1;
				continue;
			}
		}

		graph->conditionalverts->set_numVerts(vertsdata->get_numVerts());
	}
	graph->conditionalverts->release_col();

	int newDrawn = 0;
	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeit = graph->edgeDict.begin();

	unsigned int newsize = linedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
	if (graph->conditionallines->col_size() < newsize)
		graph->conditionallines->expand(newsize * 2);

	GLfloat *vcol = graph->conditionallines->acquire_col("3a");
	
	for (edgeit != graph->edgeDict.end(); edgeit != graph->edgeDict.end(); edgeit++)
	{
		if (!edgeit->second.vertSize) break;
		edge_data *e = &edgeit->second;
		
		unsigned int vidx = 0;
		for (; vidx < e->vertSize; vidx++)
		{
			vcol[e->arraypos + (vidx*4)] = 0.2;
			vcol[e->arraypos + (vidx * 4) + 1] = 0.2;
			vcol[e->arraypos + (vidx * 4) + 2] = 0.2;
			vcol[e->arraypos + (vidx * 4) + 3] = 1.0;
		}
		newDrawn++;
	}
	graph->conditionallines->set_numVerts(graph->get_mainlines()->get_numVerts());
	graph->conditionallines->release_col();
	if (newDrawn) graph->needVBOReload_conditional = true;
	dropMutex(graph->edMutex, "render graph conditional end");
	return 1;
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void conditional_renderer::conditional_thread()
{
	while (true)
	{
		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly
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
			if (clientState->activeGraph == graph)
				render_graph_conditional(graph);

			graphit++;
		}

		dropMutex(piddata->graphsListMutex, "Render Preview Thread");
		Sleep(CONDITIONAL_DELAY_MS);
	}
}

