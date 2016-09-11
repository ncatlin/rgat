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
	std::set<long> heatValues;
	EDGEMAP::iterator edgeDit, edgeDEnd;
	
	graph->start_edgeD_iteration(&edgeDit, &edgeDEnd);
	for (; edgeDit != edgeDEnd; edgeDit++)
		heatValues.insert(edgeDit->second.weight);
	graph->stop_edgeD_iteration();

	int heatrange = heatValues.size();

	//create map of distances of each value in set, creating blue->red range
	map<long, int> heatDistances;
	set<long>::iterator setit;
	int distance = 0;
	for (setit = heatValues.begin(); setit != heatValues.end(); setit++)
	{
		heatDistances[*setit] = distance++;
	}

	int maxDist = heatDistances.size();
	map<long, int>::iterator distit = heatDistances.begin();
	map<long, COLSTRUCT> heatColours;
	
	int numColours = colourRange.size();
	heatColours[heatDistances.begin()->first] = *colourRange.begin();
	if (maxDist > 2)
	{
		for (std::advance(distit, 1); distit != heatDistances.end(); distit++)
		{
			float distratio = (float)distit->second / (float)maxDist;
			int colourIndex = floor(numColours*distratio);
			heatColours[distit->first] = colourRange[colourIndex];
		}
	}

	long lastColour = heatDistances.rbegin()->first;
	if (heatColours.size() > 1)
		heatColours[lastColour] = *colourRange.rbegin();

	
	graph->heatmaplines->reset();

	vector <float> *lineVector = graph->heatmaplines->acquire_col("3b");
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
		//assert(htv <= mv);
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

//thread handler to build graph for each thread
//allows display in thumbnail style format
void heatmap_renderer::heatmap_thread()
{
	//allegro_color kept breaking here and driving me insane
	//hence own implementation
	colourRange.insert(colourRange.begin(), COLSTRUCT{ 0, 0, fcol(255) });
	colourRange.insert(colourRange.begin() + 1, COLSTRUCT{ fcol(105), 0,  fcol(255) });
	colourRange.insert(colourRange.begin() + 2, COLSTRUCT{ fcol(182), 0,  fcol(255) });
	colourRange.insert(colourRange.begin() + 3, COLSTRUCT{ fcol(255), 0, 0 });
	colourRange.insert(colourRange.begin() + 4, COLSTRUCT{ fcol(255), fcol(58), 0 });
	colourRange.insert(colourRange.begin() + 5, COLSTRUCT{ fcol(255), fcol(93), 0 });
	colourRange.insert(colourRange.begin() + 6, COLSTRUCT{ fcol(255), fcol(124), 0 });
	colourRange.insert(colourRange.begin() + 7, COLSTRUCT{ fcol(255), fcol(163), 0 });
	colourRange.insert(colourRange.begin() + 8, COLSTRUCT{ fcol(255), fcol(182), 0 });
	colourRange.insert(colourRange.begin() + 9, COLSTRUCT{ fcol(255), fcol(228 ), fcol(167)});

	while (!piddata || piddata->graphs.empty())
		Sleep(200);

	map<thread_graph_data *, bool> finishedGraphs;

	while (true)
	{
		if (!obtainMutex(piddata->graphsListMutex, "Heatmap Thread glm")) return;

		vector<thread_graph_data *> graphlist;
		map <int, void *>::iterator graphit = piddata->graphs.begin();
		for (; graphit != piddata->graphs.end(); graphit++)
			graphlist.push_back((thread_graph_data *)graphit->second);
		dropMutex(piddata->graphsListMutex, "Heatmap Thread glm");

		vector<thread_graph_data *>::iterator graphlistIt = graphlist.begin();
		while (graphlistIt != graphlist.end())
		{
			if (die) break;
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

