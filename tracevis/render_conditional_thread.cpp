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
	int newDrawn = 0;
	int nodeIdx = 0;
	int nodeEnd = graph->get_mainnodes()->get_numVerts();
	conditionalNodes->reset();
	if (nodeEnd)
	{
		const ALLEGRO_COLOR succeedOnly = clientState->config->conditional.cond_succeed;
		const ALLEGRO_COLOR failOnly = clientState->config->conditional.cond_fail;
		const ALLEGRO_COLOR bothPaths = clientState->config->conditional.cond_both;
		float invisibleNode[4] = { 0,0,0,0 };
		float failOnlyNode[4] = { failOnly.r,failOnly.g,failOnly.b,failOnly.a };
		float succeedOnlyNode[4] = { succeedOnly.r,succeedOnly.g,succeedOnly.b,succeedOnly.a };
		float bothPathsNode[4] = { bothPaths.r,bothPaths.g,bothPaths.b,bothPaths.a };

		vector<float> *nodeCol = conditionalNodes->acquire_col("1f");
		while (nodeIdx < nodeEnd)
		{
			newDrawn++;
			conditionalNodes->set_numVerts(conditionalNodes->get_numVerts() + 1);

			node_data *n = graph->get_node(nodeIdx++);
			if (!n->ins || n->ins->conditional == false)
			{
				nodeCol->insert(nodeCol->end(), invisibleNode, end(invisibleNode));
				continue;
			}

			bool jumpTaken = n->conditional & CONDTAKEN;
			bool jumpMissed = n->conditional & CONDNOTTAKEN;
			//jump only seen to succeed
			if (jumpTaken && !jumpMissed)
				nodeCol->insert(nodeCol->end(), succeedOnlyNode, end(succeedOnlyNode));

			//jump seen to both fail and succeed
			else if (jumpTaken && jumpMissed)
				nodeCol->insert(nodeCol->end(), bothPathsNode, end(bothPathsNode));

			//no notifications, assume failed
			else 
				nodeCol->insert(nodeCol->end(), failOnlyNode, end(failOnlyNode));

			continue;
			
		}
	}
	conditionalNodes->release_col();

	int condLineverts = graph->conditionallines->get_numVerts();
	int mainLineverts = graph->get_mainlines()->get_numVerts();
	if (mainLineverts > condLineverts)
	{
		//tempted to make rgba all the same and just call resize
		const ALLEGRO_COLOR *edgeColour = &clientState->config->conditional.edgeColor;
		float edgeColArr[4] = { edgeColour->r, edgeColour->g, edgeColour->b, edgeColour->a };

		vector<float> *edgecol = graph->conditionallines->acquire_col("1f");
		
		while (condLineverts++ < mainLineverts)
			edgecol->insert(edgecol->end(), edgeColArr, end(edgeColArr));

		graph->conditionallines->set_numVerts(condLineverts);
		graph->conditionallines->release_col();

	}
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

