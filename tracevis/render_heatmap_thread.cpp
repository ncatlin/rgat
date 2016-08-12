#include <stdafx.h>
#include "render_heatmap_thread.h"
#include "traceMisc.h"

bool heatmap_renderer::render_graph_heatmap(thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	if (!linedata || !linedata->get_numVerts())  return false;
	if (!obtainMutex(graph->edMutex, "Render Graph Heatmap")) return false;

	map<std::pair<unsigned int, unsigned int>, edge_data>::iterator edgeit;

	//would be quicker to track dirty edges instead of rescanning all the edges again
	//build set of all heat values
	std::set<long> heatValues;
	for (edgeit = graph->edgeDict.begin(); edgeit != graph->edgeDict.end(); edgeit++)
		heatValues.insert(edgeit->second.weight);
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

	unsigned int newsize = linedata->get_numVerts() * COLELEMS * sizeof(GLfloat) * 2;
	if (graph->heatmaplines->col_size() < newsize)
		graph->heatmaplines->expand(newsize * 2);

	GLfloat *vcol = graph->heatmaplines->acquire_col();
	for (size_t i = 0; i < linedata->get_numVerts(); ++i) 
		vcol[i] = 1.0;

	int newDrawn = 0;
	for (edgeit = graph->edgeDict.begin(); edgeit != graph->edgeDict.end(); edgeit++)
	{
		if (!edgeit->second.vertSize)
		{
			printf("WARNING : uninit edge\n");
			break;
		}

		COLSTRUCT *edgecol = &heatColours[edgeit->second.weight];
		unsigned int vidx = 0;
		unsigned int vidxpos = 0;
		for (; vidx < edgeit->second.vertSize; vidx++)
		{
			vidxpos = vidx * 4;
			vcol[edgeit->second.arraypos + vidxpos] = edgecol->r;
			vcol[edgeit->second.arraypos + vidxpos + 1] = edgecol->g;
			vcol[edgeit->second.arraypos + vidxpos + 2] = edgecol->b;
			vcol[edgeit->second.arraypos + vidxpos + 3] = (float)1;
		}
		newDrawn++;
	}
	
	if (newDrawn)
	{
		graph->heatmaplines->set_numVerts(linedata->get_numVerts());
		graph->needVBOReload_heatmap = true;
	}
	graph->heatmaplines->release_col();
	ReleaseMutex(graph->edMutex);
	return true;
}

void __stdcall heatmap_renderer::ThreadEntry(void* pUserData) {
	return ((heatmap_renderer*)pUserData)->heatmap_thread();
}

float fcol(int value)
{
	return (float)value / 255.0;
}
//thread handler to build graph for each thread
//allows display in thumbnail style format
void heatmap_renderer::heatmap_thread()
{
	//allegro color keeps breaking here and driving me insane
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

	while (true)
	{

		//only write we are protecting against happens while creating new threads
		//so not important to release this quickly
		if (!piddata || piddata->graphs.empty())
		{
			Sleep(200);
			continue;
		}

		if (!obtainMutex(piddata->graphsListMutex, "Heatmap Thread")) return;

		map <int, void *>::iterator graphit = piddata->graphs.begin();
		while (graphit != piddata->graphs.end())
		{
			thread_graph_data *graph = (thread_graph_data *)graphit->second;
			if (clientState->activeGraph == graph)
				render_graph_heatmap(graph);

			graphit++;
		}

		ReleaseMutex(piddata->graphsListMutex);
		Sleep(HEATMAP_DELAY_MS);
	}
}

