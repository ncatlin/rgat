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

	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();
	GRAPH_DISPLAY_DATA *conditionalNodes = graph->conditionalnodes;

	map<unsigned int, node_data>::iterator vertit = graph->get_nodeStart();
	map<unsigned int, node_data>::iterator vertEnd = graph->get_nodeEnd();
	if (vertit == vertEnd) return 0;
	if (conditionalNodes->get_numVerts() != vertsdata->get_numVerts())
	{
		std::advance(vertit, conditionalNodes->get_numVerts());
		if (vertit == vertEnd) return 0;

		const ALLEGRO_COLOR succeedOnly = clientState->config->conditional.cond_succeed;
		const ALLEGRO_COLOR failOnly = clientState->config->conditional.cond_fail;
		const ALLEGRO_COLOR bothPaths = clientState->config->conditional.cond_both;

		GLfloat *vcol = conditionalNodes->acquire_col("1f");
		for (; vertit != vertEnd; vertit++)
		{
			int arraypos = vertit->second.index * COLELEMS;
			if (!vertit->second.ins || vertit->second.ins->conditional == false)
			{
				vcol[arraypos + AOFF] = 0;
				continue;
			}

			bool jumpTaken = vertit->second.conditional & CONDTAKEN;
			bool jumpMissed = vertit->second.conditional & CONDNOTTAKEN;
			//jump only seen to succeed
			if (jumpTaken && !jumpMissed)
			{
				vcol[arraypos + ROFF] = succeedOnly.r;
				vcol[arraypos + GOFF] = succeedOnly.g;
				vcol[arraypos + BOFF] = succeedOnly.b;
				vcol[arraypos + AOFF] = succeedOnly.a;
				continue;
			}

			//jump seen to both fail and succeed
			if (jumpTaken && jumpMissed)
			{
				vcol[arraypos + ROFF] = bothPaths.r;
				vcol[arraypos + GOFF] = bothPaths.g;
				vcol[arraypos + BOFF] = bothPaths.b;
				vcol[arraypos + AOFF] = bothPaths.a;
				continue;
			}

			//no notifications, assume failed
			vcol[arraypos + ROFF] = failOnly.r;
			vcol[arraypos + GOFF] = failOnly.g;
			vcol[arraypos + BOFF] = failOnly.b;
			vcol[arraypos + AOFF] = failOnly.a;
			continue;
		}

		conditionalNodes->set_numVerts(vertsdata->get_numVerts());
	}
	conditionalNodes->release_col();

	int newDrawn = 0;
	

	unsigned int newColSize = linedata->get_numVerts() * COLELEMS * sizeof(GLfloat);
	unsigned int newPosSize = linedata->get_numVerts() * POSELEMS * sizeof(GLfloat);
	if (graph->conditionallines->col_size() < newColSize || graph->conditionallines->pos_size() < newPosSize)
		graph->conditionallines->expand(max(newColSize,newPosSize) * 2);

	map<NODEPAIR, edge_data>::iterator edgeit;
	map<NODEPAIR, edge_data>::iterator edgeEnd;

	const ALLEGRO_COLOR edgeColour = clientState->config->conditional.edgeColor;
	GLfloat *vcol = graph->conditionallines->acquire_col("3a");
	graph->start_edgeD_iteration(&edgeit, &edgeEnd);
	for (; edgeit != edgeEnd; edgeit++)
	{
		edge_data *e = &edgeit->second;
		unsigned int vidx = 0;
		for (; vidx < e->vertSize; vidx++)
		{
			vcol[e->arraypos + (vidx * COLELEMS) + ROFF] = edgeColour.r;
			vcol[e->arraypos + (vidx * COLELEMS) + GOFF] = edgeColour.g;
			vcol[e->arraypos + (vidx * COLELEMS) + BOFF] = edgeColour.b;
			vcol[e->arraypos + (vidx * COLELEMS) + AOFF] = edgeColour.a;
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
		Sleep(updateDelayMS);
	}
}

