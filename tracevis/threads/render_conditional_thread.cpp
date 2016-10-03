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
Header for the thread that renders graph conditional data
*/
#include "stdafx.h"
#include "render_conditional_thread.h"
#include "traceMisc.h"

bool conditional_renderer::render_graph_conditional(thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	if (!linedata || !linedata->get_numVerts()) return false;

	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();
	GRAPH_DISPLAY_DATA *conditionalNodes = graph->conditionalnodes;
	bool newDrawn = false;
	int nodeIdx = 0;
	int nodeEnd = graph->get_mainnodes()->get_numVerts();
	conditionalNodes->reset();
	if (nodeEnd)
	{
		vector<float> *nodeCol = conditionalNodes->acquire_col();
		if (nodeIdx < nodeEnd) newDrawn = true;
		graph->condCounts = make_pair(0,0);
		while (nodeIdx < nodeEnd)
		{
			conditionalNodes->set_numVerts(conditionalNodes->get_numVerts() + 1);

			int condStatus = graph->get_node(nodeIdx++)->conditional;
			if (!condStatus)
			{
				nodeCol->insert(nodeCol->end(), invisibleCol, end(invisibleCol));
				continue;
			}

			//jump only seen to succeed
			if (condStatus & CONDTAKEN)
			{
				nodeCol->insert(nodeCol->end(), succeedOnlyCol, end(succeedOnlyCol));
				++graph->condCounts.first;
			}

			//jump only seen to fail
			else if (condStatus & CONDFELLTHROUGH)
			{
				nodeCol->insert(nodeCol->end(), failOnlyCol, end(failOnlyCol));
				++graph->condCounts.second;
			}

			//jump seen to both fail and succeed. added for completeness sake.
			else if (condStatus == CONDCOMPLETE)
				nodeCol->insert(nodeCol->end(), bothPathsCol, end(bothPathsCol));

			//ignore CONDPENDING for this iteration, not worth dealing with
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

		vector<float> *edgecol = graph->conditionallines->acquire_col();
		
		while (condLineverts++ < mainLineverts)
			edgecol->insert(edgecol->end(), edgeColArr, end(edgeColArr));

		graph->conditionallines->set_numVerts(condLineverts);
		graph->conditionallines->release_col();

	}
	if (newDrawn) graph->needVBOReload_conditional = true;
	return true;
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void conditional_renderer::main_loop()
{
	alive = true;
	invisibleCol[0] = 0;
	invisibleCol[1] = 0;
	invisibleCol[2] = 0;
	invisibleCol[3] = 0;

	ALLEGRO_COLOR *failOnly = &clientState->config->conditional.cond_fail;
	failOnlyCol[0] = failOnly->r;
	failOnlyCol[1] = failOnly->g;
	failOnlyCol[2] = failOnly->b;
	failOnlyCol[3] = failOnly->a;

	ALLEGRO_COLOR *succeedOnly = &clientState->config->conditional.cond_succeed;
	succeedOnlyCol[0] = succeedOnly->r;
	succeedOnlyCol[1] = succeedOnly->g;
	succeedOnlyCol[2] = succeedOnly->b;
	succeedOnlyCol[3] = succeedOnly->a;

	ALLEGRO_COLOR *bothPaths = &clientState->config->conditional.cond_both;
	bothPathsCol[0] = bothPaths->r;
	bothPathsCol[1] = bothPaths->g;
	bothPathsCol[2] = bothPaths->b;
	bothPathsCol[3] = bothPaths->a;

	while ((!piddata || piddata->graphs.empty()) && !die)
	{
		Sleep(100);
		continue;
	}

	map<thread_graph_data *,bool> finishedGraphs;
	vector<thread_graph_data *> graphlist;
	map <PID_TID, void *>::iterator graphit;
	int dietimer = -1;

	while (!clientState->die && dietimer != 0)
	{
		if (dietimer == 0) break;
		if ((die || piddata->should_die()) && dietimer-- < 0)
			dietimer = 3;

		obtainMutex(piddata->graphsListMutex, 1053);
		for (graphit = piddata->graphs.begin(); graphit != piddata->graphs.end(); graphit++)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex);
		
		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end() && !die)
		{
			thread_graph_data *graph = *graphlistIt++;

			if (graph->active || graph->get_num_edges() > graph->conditionallines->get_renderedEdges())
				render_graph_conditional(graph);
			else if (!finishedGraphs[graph])
				finishedGraphs[graph] = render_graph_conditional(graph);

			Sleep(80);
		}
		graphlist.clear();
		int waitForNextIt = 0;
		while (waitForNextIt < updateDelayMS && !die)
		{
			Sleep(50);
			waitForNextIt += 50;
		}
	}
	alive = false;
}

