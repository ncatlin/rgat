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

void __stdcall heatmap_renderer::ThreadEntry(void* pUserData) {
	return ((heatmap_renderer*)pUserData)->heatmap_thread();
}


bool heatmap_renderer::render_graph_heatmap(thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	unsigned int numLineVerts;
	if (linedata)
	{
		numLineVerts = linedata->get_numVerts();
		if(!numLineVerts)  return false;
	} 
	else return false; 

	//build set of all heat values
	std::set<unsigned long> heatValues;
	EDGEMAP::iterator edgeDit, edgeDEnd;
	
	graph->start_edgeD_iteration(&edgeDit, &edgeDEnd);
	for (; edgeDit != edgeDEnd; edgeDit++)
		heatValues.insert(edgeDit->second.weight);
	graph->stop_edgeD_iteration();

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
			int colourIndex = floor(numColours*distratio);
			heatColours[distit->first] = colourRange[colourIndex];
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

	for (; edgeindex != edgeEnd; ++edgeindex)
	{
		edge_data *edge = graph->get_edge(edgelist->at(edgeindex));
		COLSTRUCT *edgecol = &heatColours[edge->weight];
		float edgeColArr[4] = { edgecol->r, edgecol->g, edgecol->b, 1};

		unsigned int vertIdx = 0;
		assert(edge->vertSize);
		for (; vertIdx < edge->vertSize; vertIdx++)
			lineVector->insert(lineVector->end(), edgeColArr, end(edgeColArr));

		graph->heatmaplines->inc_edgesRendered();
		graph->heatmaplines->set_numVerts(graph->heatmaplines->get_numVerts() + vertIdx);
		unsigned int htv = graph->heatmaplines->get_numVerts();
		unsigned int mv = graph->get_mainlines()->get_numVerts();
		if (htv > mv) printf("WARNING heatmapverts:%d, mainverts:%d\n", htv, mv);
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
void heatmap_renderer::heatmap_thread()
{
	
	//add our heatmap colours to a vector for lookup in render thread
	for (int i = 0; i < 10; i++)
		colourRange.insert(colourRange.begin(), *col_to_colstruct(&clientState->config->heatmap.edgeFrequencyCol[i]));

	while (!piddata || piddata->graphs.empty())
		Sleep(200);

	map<thread_graph_data *, bool> finishedGraphs;

	while (!clientState->die)
	{
		if (!obtainMutex(piddata->graphsListMutex, 5000)) return;

		vector<thread_graph_data *> graphlist;
		map <int, void *>::iterator graphit = piddata->graphs.begin();
		for (; graphit != piddata->graphs.end(); graphit++)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex);

		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			if (die || clientState->die) break;
			thread_graph_data *graph = *graphlistIt;
			graphlistIt++;
			int i1 = graph->get_num_edges();
			int i2 = graph->heatmaplines->get_renderedEdges();
			if (graph->active || graph->get_num_edges() > graph->heatmaplines->get_renderedEdges())
			{
				render_graph_heatmap(graph);
				graph->dirtyHeatmap = false;
			}
			else 
				if (!finishedGraphs[graph])
				{
					finishedGraphs[graph] = true;
					render_graph_heatmap(graph);
				}
			Sleep(80);
		}
		
		Sleep(updateDelayMS);
	}
}

