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
The thread that performs low (ie:periodic) performance rendering of all graphs for the preview pane
*/
#include <stdafx.h>
#include "render_heatmap_thread.h"
#include "traceMisc.h"
#include "rendering.h"

bool heatmap_renderer::render_graph_heatmap(thread_graph_data *graph)
{
	if (!graph->get_num_edges()) return false;

	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	unsigned int numLineVerts;
	if (linedata)
	{
		numLineVerts = linedata->get_numVerts();

		//graph never been rendered so we cant get the edge vertex data to colourise it
		if (!numLineVerts)
			if (!graph->active)
				render_static_graph(graph, clientState); //got final data so may as well force rendering
			else
				return false;
	} 
	else return false; 

	DWORD this_run_marker = GetTickCount();

	//build set of all heat values
	std::set<unsigned long> heatValues;
	EDGEMAP::iterator edgeDit, edgeDEnd;

	vector<pair<pair<node_data*,node_data*>,edge_data *>> unfinishedEdgeList;
	vector<edge_data *> finishedEdgeList;

	graph->start_edgeD_iteration(&edgeDit, &edgeDEnd);
	for (; edgeDit != edgeDEnd; ++edgeDit)
	{
		node_data *snode = graph->get_node(edgeDit->first.first);
		node_data *tnode = graph->get_node(edgeDit->first.second);
		edge_data *edge = &edgeDit->second;

		//initialise temporary counters
		if (snode->heat_run_marker != this_run_marker)
		{
			snode->chain_remaining_in = snode->executionCount;
			snode->chain_remaining_out = snode->executionCount;
			snode->heat_run_marker = this_run_marker;
		}
		if (tnode->heat_run_marker != this_run_marker)
		{
			tnode->chain_remaining_in = tnode->executionCount;
			tnode->chain_remaining_out = tnode->executionCount;
			tnode->heat_run_marker = this_run_marker;
		}

		//the easiest edges to work out are the most numerous
		if (snode->outgoingNeighbours.size() == 1)
		{
			edge->chainedWeight = snode->executionCount;
			snode->chain_remaining_out = 0;
			tnode->chain_remaining_in -= snode->executionCount;
			finishedEdgeList.push_back(edge);
		}
		else if (tnode->incomingNeighbours.size() == 1)
		{
			edge->chainedWeight = tnode->executionCount;
			tnode->chain_remaining_in = 0;
			snode->chain_remaining_out -= tnode->executionCount;
			finishedEdgeList.push_back(edge);
		}
		else
		{
			edge->chainedWeight = 0;
			unfinishedEdgeList.push_back(make_pair(make_pair(snode,tnode), edge));
		}
	}
	graph->stop_edgeD_iteration();

	printf("starting solver with %d unsolved\n", unfinishedEdgeList.size());

	int itlimit = 10;
	vector<pair<pair<node_data*, node_data*>, edge_data *>>::iterator unfinishedIt;
	while (true)
	{
		unfinishedIt = unfinishedEdgeList.begin();
		for (; unfinishedIt != unfinishedEdgeList.end(); ++unfinishedIt)
		{
			node_data *snode = unfinishedIt->first.first;
			node_data *tnode = unfinishedIt->first.second;
			edge_data *edge = unfinishedIt->second;

			//see if targets other inputs have remaining output
			unsigned long targOtherNeighboursOut = 0;
			set<unsigned int>::iterator targincomingIt = tnode->incomingNeighbours.begin();
			for (; targincomingIt != tnode->incomingNeighbours.end(); targincomingIt++)
			{
				unsigned int idx = *targincomingIt;
				if (idx == snode->index) continue;
				node_data *neib = graph->get_node(idx);
				targOtherNeighboursOut += neib->chain_remaining_out;
			}

			//no? only source node giving input. complete edge and subtract from source output 
			if (targOtherNeighboursOut == 0)
			{
				edge->chainedWeight = tnode->chain_remaining_in;
				tnode->chain_remaining_in = 0;
				snode->chain_remaining_out -= edge->chainedWeight;
				finishedEdgeList.push_back(edge);
				unfinishedIt = unfinishedEdgeList.erase(unfinishedIt);
				itlimit++;
				break;
			}

			//see if other source outputs need input
			unsigned long sourceOtherNeighboursIn = 0;
			set<unsigned int>::iterator sourceoutgoingIt = snode->outgoingNeighbours.begin();
			for (; sourceoutgoingIt != snode->outgoingNeighbours.end(); sourceoutgoingIt++)
			{
				unsigned int idx = *sourceoutgoingIt;
				if (idx == tnode->index) continue;
				node_data *neib = graph->get_node(idx);
				sourceOtherNeighboursIn += neib->chain_remaining_in;
			}

			//no? only targ edge taking input. complete edge and subtract from targ input 
			if (sourceOtherNeighboursIn == 0)
			{
				edge->chainedWeight = snode->chain_remaining_out;
				snode->chain_remaining_out = 0;
				tnode->chain_remaining_in -= edge->chainedWeight;
				finishedEdgeList.push_back(edge);
				unfinishedIt = unfinishedEdgeList.erase(unfinishedIt);
				itlimit++;
				break;
			}	

		}

		if (--itlimit <= 0)
		{ 
			//printf("[rgat]Heatmap Failure: ending solver with %d unsolved\n", unfinishedEdgeList.size()); 
			break; 
		}
		if (unfinishedEdgeList.empty())
		{
			//printf("[rgat]Heatmap Success: ending solver with %d unsolved\n", unfinishedEdgeList.size());
			break;
		}
	}


	//for all in finsihed map, heatValues.insert(edgeDit->second.weight);
	vector<edge_data *>::iterator finishedEdgeIt;
	for (finishedEdgeIt = finishedEdgeList.begin(); finishedEdgeIt != finishedEdgeList.end(); ++finishedEdgeIt)
	{
		edge_data *thisedge = *finishedEdgeIt;
		heatValues.insert(thisedge->chainedWeight);
	}

	int heatrange = heatValues.size();

	//create map of distances of each value in set
	map<unsigned long, int> heatDistances;
	set<unsigned long>::iterator setit;
	int distance = 0;
	for (setit = heatValues.begin(); setit != heatValues.end(); ++setit)
		heatDistances[*setit] = distance++;
	graph->heatExtremes = make_pair(*heatValues.begin(),*heatValues.rbegin());


	int maxDist = heatDistances.size();
	map<unsigned long, int>::iterator distit = heatDistances.begin();
	map<unsigned long, COLSTRUCT> heatColours;
	
	//create blue->red value for each numerical 'heat'
	int numColours = colourRange.size();
	heatColours[heatDistances.begin()->first] = *colourRange.begin();
	if (maxDist > 1)
	{
		for (std::advance(distit, 1); distit != heatDistances.end(); distit++)
		{
			float distratio = (float)distit->second / (float)maxDist;
			int colourIndex = min(numColours-1, floor(numColours*distratio));
			heatColours[distit->first] = colourRange.at(colourIndex);
		}
	}

	unsigned long lastColour = heatDistances.rbegin()->first;
	if (heatColours.size() > 1)
		heatColours[lastColour] = *colourRange.rbegin();
	
	graph->heatmaplines->reset();

	//finally build a colours buffer using the heat/colour map entry for each edge weight
	vector <float> *lineVector = graph->heatmaplines->acquire_col();
	unsigned int edgeindex = 0;
	unsigned int edgeEnd = graph->get_mainlines()->get_renderedEdges();
	EDGELIST* edgelist = graph->edgeLptr();

	COLSTRUCT debuggingUnfin;
	debuggingUnfin.a = 1;
	debuggingUnfin.b = 0;
	debuggingUnfin.g = 1;
	debuggingUnfin.r = 0;

	for (; edgeindex != edgeEnd; ++edgeindex)
	{
		edge_data *edge = graph->get_edge(edgeindex);
		if (!edge) {
			cerr << "[rgat]WARNING: Heatmap2 edge skip"<<endl;
			continue;
		}

		COLSTRUCT *edgeColour = 0;
		//map<unsigned long, COLSTRUCT>::iterator foundHeatColour = heatColours.find(edge->weight);
		map<unsigned long, COLSTRUCT>::iterator foundHeatColour = heatColours.find(edge->chainedWeight);

		//this edge has a new value since we recalculated the heats, this finds the nearest
		if (foundHeatColour == heatColours.end())
		{

			edgeColour = &debuggingUnfin;
			/*
			unsigned long searchWeight = edge->weight;
			map<unsigned long, COLSTRUCT>::iterator previousHeatColour = foundHeatColour;
			for (foundHeatColour = heatColours.begin(); foundHeatColour != heatColours.end(); ++foundHeatColour)
			{
				if (foundHeatColour->first > searchWeight && previousHeatColour->first < searchWeight)
				{
					edgeColour = &foundHeatColour->second;
					break;
				}
				previousHeatColour = foundHeatColour;
			}
			if (foundHeatColour == heatColours.end())
				edgeColour = &heatColours.rbegin()->second;
			//record it so any others with this weight are found
			heatColours[searchWeight] = *edgeColour;
			*/
		}
		else
			edgeColour = &foundHeatColour->second;

		float edgeColArr[4] = { edgeColour->r, edgeColour->g, edgeColour->b, 1};

		unsigned int vertIdx = 0;
		assert(edge->vertSize);
		for (; vertIdx < edge->vertSize; vertIdx++)
			lineVector->insert(lineVector->end(), edgeColArr, end(edgeColArr));

		graph->heatmaplines->inc_edgesRendered();
		graph->heatmaplines->set_numVerts(graph->heatmaplines->get_numVerts() + vertIdx);
	}

	graph->heatmaplines->release_col();
	graph->needVBOReload_heatmap = true;
	
	return true;
}

//convert 0-255 rgb to 0-1
inline float fcol(int value)
{
	return (float)value / 255.0;
}

//allegro_color kept breaking here and driving me insane - hence own stupidly redundant implementation
COLSTRUCT *col_to_colstruct(ALLEGRO_COLOR *c)
{
	COLSTRUCT *cs = new COLSTRUCT;
	cs->r = c->r;
	cs->g = c->g;
	cs->b = c->b;
	cs->a = c->a;
	return cs;
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void heatmap_renderer::main_loop()
{
	alive = true;
	//add our heatmap colours to a vector for lookup in render thread
	for (int i = 0; i < 10; i++)
		colourRange.insert(colourRange.begin(), *col_to_colstruct(&clientState->config->heatmap.edgeFrequencyCol[i]));

	while ((!piddata || piddata->graphs.empty()) && !die)
		Sleep(200);

	map<thread_graph_data *, bool> finishedGraphs;
	while (!clientState->die)
	{
		obtainMutex(piddata->graphsListMutex, 1054);

		vector<thread_graph_data *> graphlist;
		map <PID_TID, void *>::iterator graphit = piddata->graphs.begin();
		for (; graphit != piddata->graphs.end(); ++graphit)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex);

		//process terminated, all graphs fully rendered, now can head off to valhalla
		if (!piddata->is_running() && (finishedGraphs.size() == graphlist.size())) 
				break; 

		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end() && !die)
		{
			thread_graph_data *graph = *graphlistIt++;
			//always rerender an active graph (edge executions may have increased without adding new edges)
			//render saved graphs if there are new edges
			if (graph->active || graph->get_num_edges() > graph->heatmaplines->get_renderedEdges())
			{
				render_graph_heatmap(graph);
				graph->dirtyHeatmap = false;
			}
			else //last mop-up rendering of a recently finished graph
				if (!finishedGraphs[graph])
				{
					finishedGraphs[graph] = true;
					render_graph_heatmap(graph);
				}

			Sleep(20); //pause between graphs so other things don't struggle for mutex time
		}
		
		int waitForNextIt = 0;
		while (waitForNextIt < updateDelayMS && !die)
		{
			Sleep(50);
			waitForNextIt += 50;
		}
	}

	alive = false;
}

