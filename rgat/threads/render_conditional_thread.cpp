/*
Copyright 2016-2017 Nia Catlin

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

bool conditional_renderer::render_graph_conditional(plotted_graph *graph)
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
		vector<float> *nodeCol = conditionalNodes->acquire_col_write();
		if (nodeIdx < nodeEnd) newDrawn = true;
		graph->condCounts = make_pair(0,0);
		while (nodeIdx < nodeEnd)
		{
			conditionalNodes->set_numVerts(conditionalNodes->get_numVerts() + 1);

			int condStatus = graph->get_protoGraph()->safe_get_node(nodeIdx++)->conditional;
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
	conditionalNodes->release_col_write();

	int condLineverts = graph->conditionallines->get_numVerts();
	int mainLineverts = graph->get_mainlines()->get_numVerts();
	if (mainLineverts > condLineverts)
	{
		//tempted to make rgba all the same and just call resize
		const QColor *edgeColour = &clientState->config.conditional.edgeColor;
		float edgeColArr[4] = { (float)edgeColour->redF(), (float)edgeColour->greenF(), (float)edgeColour->blueF(), (float)edgeColour->alphaF() };

		vector<float> *edgecol = graph->conditionallines->acquire_col_write();
		
		while (condLineverts++ < mainLineverts)
			edgecol->insert(edgecol->end(), edgeColArr, end(edgeColArr));

		graph->conditionallines->set_numVerts(condLineverts);
		graph->conditionallines->release_col_write();

	}
	if (newDrawn) graph->needVBOReload_conditional = true;

	if (graph->get_mainlines()->get_numVerts() <= graph->conditionallines->get_numVerts())
		return true;
	else
		return false;
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

	QColor *failOnly = &clientState->config.conditional.cond_fail;
	failOnlyCol[0] = failOnly->redF();
	failOnlyCol[1] = failOnly->greenF();
	failOnlyCol[2] = failOnly->blueF();
	failOnlyCol[3] = failOnly->alphaF();

	QColor *succeedOnly = &clientState->config.conditional.cond_succeed;
	succeedOnlyCol[0] = succeedOnly->redF();
	succeedOnlyCol[1] = succeedOnly->greenF();
	succeedOnlyCol[2] = succeedOnly->blueF();
	succeedOnlyCol[3] = succeedOnly->alphaF();

	QColor *bothPaths = &clientState->config.conditional.cond_both;
	bothPathsCol[0] = bothPaths->redF();
	bothPathsCol[1] = bothPaths->greenF();
	bothPathsCol[2] = bothPaths->blueF();
	bothPathsCol[3] = bothPaths->alphaF();

	while ((runRecord->plottedGraphs.empty()) && !die)
	{
		Sleep(100);
		continue;
	}

	map<plotted_graph *,bool> finishedGraphs;
	vector<plotted_graph *> graphlist;
	map <PID_TID, void *>::iterator graphIt;
	PROCESS_DATA *piddata = runRecord->get_piddata();

	while (!clientState->rgatIsExiting())
	{

		if (!tryObtainMutex(&runRecord->graphsListCritsec, 50))
		{
			Sleep(20); continue;
		}

		
		for (graphIt = runRecord->plottedGraphs.begin(); graphIt != runRecord->plottedGraphs.end(); ++graphIt)
		{
			plotted_graph *g = (plotted_graph *)graphIt->second;
			if (g->increase_thread_references())
			{
				graphlist.push_back(g);
			}
		}
		dropMutex(&runRecord->graphsListCritsec);
		
		//process terminated, all graphs fully rendered, now can head off to valhalla
		if (!piddata->is_running() && (finishedGraphs.size() == graphlist.size()))
		{
			for (auto graph : graphlist)
				graph->decrease_thread_references();
			break;
		}

		vector<plotted_graph *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end() && !die)
		{
			plotted_graph *graph = *graphlistIt++;

			if (graph->get_protoGraph()->active)
				render_graph_conditional(graph);
			else if (!finishedGraphs[graph])
			{
				bool renderSuccess = render_graph_conditional(graph);
				//if this fails then the static vert data hasn't been created yet
				//the heatmap thread should do it, but if that thread is disabled then this will fail
				if (renderSuccess || !graph->get_protoGraph()->get_num_nodes())
					finishedGraphs[graph] = true;
				else
					finishedGraphs.erase(graph);
			}
			Sleep(20);
		}

		for (auto graph : graphlist)
		{
			graph->decrease_thread_references();
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

