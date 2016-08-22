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
			if (vertit->second.ins && vertit->second.ins->conditional)
				printf("iscon\n");
			int arraypos = vertit->second.index * COLELEMS;

			if (!vertit->second.ins || vertit->second.ins->conditional == false)
			{
				vcol[arraypos] = 0;
				vcol[arraypos + 1] = 0;
				vcol[arraypos + 2] = 0;
				vcol[arraypos + 3] = 0;
				continue;
			}

			bool jumpTaken = vertit->second.conditional & CONDTAKEN;
			bool jumpMissed = vertit->second.conditional & CONDNOTTAKEN;
			//jump only seen to succeed
			if (jumpTaken && !jumpMissed)
			{
				vcol[arraypos] =  0;
				vcol[arraypos + 1] = 0;
				vcol[arraypos + 2] = 1;
				vcol[arraypos + 3] = 1;
				continue;
			}

			//jump seen to both fail and succeed
			if (jumpTaken && jumpMissed)
			{
				vcol[arraypos] = 1;
				vcol[arraypos + 1] = 0.5;
				vcol[arraypos + 2] = 0.3;
				vcol[arraypos + 3] = 1;
				continue;
			}

			//no notifications, assume failed
			vcol[arraypos] = 1;
			vcol[arraypos + 1] = 0;
			vcol[arraypos + 2] = 0;
			vcol[arraypos + 3] = 1;
			continue;
		}

		graph->conditionalverts->set_numVerts(vertsdata->get_numVerts());
	}
	graph->conditionalverts->release_col();

	int newDrawn = 0;
	

	unsigned int newColSize = linedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
	unsigned int newPosSize = linedata->get_numVerts() * POSELEMS * sizeof(GLfloat);
	if (graph->conditionallines->col_size() < newColSize || graph->conditionallines->pos_size() < newPosSize)
		graph->conditionallines->expand(max(newColSize,newPosSize) * 2);

	
	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeit;
	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeEnd;

	GLfloat *vcol = graph->conditionallines->acquire_col("3a");
	graph->start_edgeD_iteration(&edgeit, &edgeEnd);
	for (; edgeit != edgeEnd; edgeit++)
	{
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
	graph->stop_edgeD_iteration();
	graph->conditionallines->set_numVerts(graph->get_mainlines()->get_numVerts());
	graph->conditionallines->release_col();

	if (newDrawn) graph->needVBOReload_conditional = true;
	return 1;
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void conditional_renderer::conditional_thread()
{
	while (!piddata || piddata->graphs.empty())
	{
		Sleep(200);
		continue;
	}

	vector<thread_graph_data *> graphlist;
	map <int, void *>::iterator graphit;
	while (true)
	{
		if (!obtainMutex(piddata->graphsListMutex, "conditional Thread glm")) return;
		for (graphit = piddata->graphs.begin(); graphit != piddata->graphs.end(); graphit++)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex, "conditional Thread glm");
		
		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			thread_graph_data *graph = *graphlistIt;
			render_graph_conditional(graph);
			graphlistIt++;
			Sleep(80);
		}
		graphlist.clear();
		Sleep(CONDITIONAL_DELAY_MS);
	}
}

