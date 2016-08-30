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

		GLfloat *nodeCol = conditionalNodes->acquire_col("1f");
		for (; vertit != vertEnd; vertit++)
		{
			int arraypos = vertit->second.index * COLELEMS;
			if (!vertit->second.ins || vertit->second.ins->conditional == false)
			{
				nodeCol[arraypos + AOFF] = 0;
				continue;
			}

			bool jumpTaken = vertit->second.conditional & CONDTAKEN;
			bool jumpMissed = vertit->second.conditional & CONDNOTTAKEN;
			//jump only seen to succeed
			if (jumpTaken && !jumpMissed)
			{
				nodeCol[arraypos + ROFF] = succeedOnly.r;
				nodeCol[arraypos + GOFF] = succeedOnly.g;
				nodeCol[arraypos + BOFF] = succeedOnly.b;
				nodeCol[arraypos + AOFF] = succeedOnly.a;
				continue;
			}

			//jump seen to both fail and succeed
			if (jumpTaken && jumpMissed)
			{
				nodeCol[arraypos + ROFF] = bothPaths.r;
				nodeCol[arraypos + GOFF] = bothPaths.g;
				nodeCol[arraypos + BOFF] = bothPaths.b;
				nodeCol[arraypos + AOFF] = bothPaths.a;
				continue;
			}

			//no notifications, assume failed
			nodeCol[arraypos + ROFF] = failOnly.r;
			nodeCol[arraypos + GOFF] = failOnly.g;
			nodeCol[arraypos + BOFF] = failOnly.b;
			nodeCol[arraypos + AOFF] = failOnly.a;
			continue;
		}

		conditionalNodes->set_numVerts(vertsdata->get_numVerts());
	}
	conditionalNodes->release_col();

	int newDrawn = 0;
	
	map<NODEPAIR, edge_data>::iterator edgeit;
	map<NODEPAIR, edge_data>::iterator edgeEnd;

	int targetNumVerts = graph->get_mainlines()->get_numVerts();
	graph->conditionallines->set_numVerts(targetNumVerts);

	const ALLEGRO_COLOR edgeColour = clientState->config->conditional.edgeColor;
	GLfloat *edgecol = graph->conditionallines->acquire_col("3a");
	graph->start_edgeD_iteration(&edgeit, &edgeEnd);
	unsigned int bufsize = graph->conditionallines->col_size() - 1000;
	for (; edgeit != edgeEnd; edgeit++)
	{
		edge_data *e = &edgeit->second;
		unsigned int vidx = 0;
		for (; vidx < e->vertSize; vidx++)
		{
			int arraypos = e->arraypos;
			edgecol[arraypos + (vidx * COLELEMS) + ROFF] = edgeColour.r;
			edgecol[arraypos + (vidx * COLELEMS) + GOFF] = edgeColour.g;
			edgecol[arraypos + (vidx * COLELEMS) + BOFF] = edgeColour.b;
			edgecol[arraypos + (vidx * COLELEMS) + AOFF] = edgeColour.a;
			newDrawn += 4;
			
			if(newDrawn >= targetNumVerts) break;
			assert(newDrawn < graph->conditionallines->col_size());
		}
		
	}
	graph->stop_edgeD_iteration();
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

	map<thread_graph_data *,bool> finishedGraphs;
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
			graphlistIt++;

			if (graph->active)
				render_graph_conditional(graph);
			else if (!finishedGraphs[graph])
			{
				finishedGraphs[graph] = true;
				render_graph_conditional(graph);
			}
			Sleep(80);
		}
		graphlist.clear();
		Sleep(updateDelayMS);
	}
}

