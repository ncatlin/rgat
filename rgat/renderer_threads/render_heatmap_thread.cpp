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
Bodies for the thread that periodically recalculates/renders the graph heat map
*/
#include <stdafx.h>
#include "render_heatmap_thread.h"

//basic checks to ensure there are edges to render
//returns the graphs protograph if yet, null pointer otherwise
proto_graph * check_graph_ready(plotted_graph *graph, rgatState* clientState)
{
	proto_graph *protoGraph = graph->get_protoGraph();
	if (!protoGraph->get_num_edges()) return NULL;

	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	unsigned int numLineVerts;
	if (linedata)
	{
		numLineVerts = linedata->get_numVerts();

		//graph never been rendered so we cant get the edge vertex data to colourise it
		if (!numLineVerts)
				return NULL;
	}
	else
		return NULL;

	return protoGraph;
}

//initialises counters, solves the trivial edges, returns number of errors
unsigned int heatmap_renderer::initialise_solver(proto_graph *protoGraph, bool lastRun, vector<pair<NODEPAIR, edge_data *>> *unfinishedEdgeList, 
	vector<edge_data *> *finishedEdgeList, map <NODEINDEX, bool> *errorNodes)
{
	DWORD this_run_marker = GetTickCount();
	EDGEMAP::iterator edgeDit, edgeDEnd;
	unsigned int solverErrors = 0;
	
	protoGraph->start_edgeD_iteration(&edgeDit, &edgeDEnd);
	for (; edgeDit != edgeDEnd; ++edgeDit)
	{
		node_data *snode = protoGraph->safe_get_node(edgeDit->first.first);
		node_data *tnode = protoGraph->safe_get_node(edgeDit->first.second);
		edge_data *edge = &edgeDit->second;

		//initialise indegree and outdegree counters for both nodes in edge
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

		//first we solve the easy and most numerous edges - connecting nodes with indegree <= 1 and outdegree <= 1

		//source node of this edge has outdegree 1 therefore edge weight is that nodes execution count
		if (snode->outgoingNeighbours.size() == 1)
		{
			edge->chainedWeight = snode->executionCount;
			
			//does instruction execute more times than the only instruction that follows it?
			if (snode->executionCount > tnode->chain_remaining_in)
			{
				//ignore if the instruction was the last in the thread and the difference is 1
				if ((snode->index != protoGraph->finalNodeID) && (snode->executionCount != (tnode->chain_remaining_in + 1)))
				{				
					++solverErrors;
					
					if (lastRun && errorNodes->count(snode->index) == 0) //only change the node execution count when its done running
					{
#ifdef DEBUG
						cerr << "solver error 1 at [source " << snode->index << "] [targ " << tnode->index << "]" << endl;
#endif
						//we estimate that the unresolved executions flow to this external node
						if (tnode->external)
						{
							snode->chain_remaining_out -= tnode->chain_remaining_in;
							tnode->executionCount += snode->chain_remaining_out;
							//edge->chainedWeight += snode->chain_remaining_out;
							tnode->unreliableCount = true;
							solverErrors--;
						}
						else
						{
#ifdef DEBUG
							cerr << "[rgat]Heat solver warning 1: (TID" << dec << protoGraph->get_TID() << "): Sourcenode:" << snode->index <<
								" (only 1 target) has " << snode->executionCount << " output but targnode " << tnode->index <<
								" only needs " << tnode->chain_remaining_in << endl;
#endif
							errorNodes->emplace(make_pair(snode->index, true));
						}
						
					}
				}
			}
			snode->chain_remaining_out = 0;
			tnode->chain_remaining_in -= snode->executionCount;
			finishedEdgeList->push_back(edge);
		}
		else //target node of this edge has indegree 1 therefore edge weight is that nodes execution count
			if (tnode->incomingNeighbours.size() == 1)
		{
			edge->chainedWeight = tnode->executionCount;
			
			//this instruction executed more than the only instruction that leads to it?
			if (tnode->executionCount > snode->chain_remaining_out)
			{
				++solverErrors;
				if (lastRun && errorNodes->count(tnode->index) == 0)
				{		
					//we estimate that the unresolved out journeys are to this external
					if (snode->external)
					{
						/*
						tnode->chain_remaining_in -= snode->chain_remaining_out;
						cout << "increasing node " << snode->index << " executions from " << snode->executionCount;
						snode->executionCount += tnode->chain_remaining_in;
						cout << " to " << snode->executionCount << endl;
						edge->chainedWeight += tnode->chain_remaining_in;
						snode->unreliableCount = true;
						solverErrors--;
						*/
					}

#ifdef DEBUG
					cerr << "solver error 2 at s " << snode->index << " t " << tnode->index << endl;
					cerr << "[rgat]Heat solver warning 2: (TID" << dec << protoGraph->get_TID() << "): Targnode:" << tnode->index
						<< " (only only 1 caller) needs " << tnode->executionCount << " in but sourcenode ("
						<< snode->index << ") only provides " << snode->chain_remaining_out << " out" << endl;
#endif
					errorNodes->emplace(make_pair(tnode->index, true));
				}
			}
			tnode->chain_remaining_in = 0;
			snode->chain_remaining_out -= tnode->executionCount;
			finishedEdgeList->push_back(edge);
		}
		else
		{
			edge->chainedWeight = 0;
			unfinishedEdgeList->push_back(make_pair(edgeDit->first, &edgeDit->second));
		}
	}
	protoGraph->stop_edgeD_iteration();
	return solverErrors;
}


unsigned int heatmap_renderer::count_remaining_other_input(proto_graph *protoGraph, node_data *targnode, NODEINDEX ignoreNode)
{
	unsigned int otherNeighboursOut = 0;
	set<NODEINDEX>::iterator targincomingIt = targnode->incomingNeighbours.begin();
	for (; targincomingIt != targnode->incomingNeighbours.end(); targincomingIt++)
	{
		NODEINDEX idx = *targincomingIt;
		if (idx == ignoreNode) continue;
		node_data *otherNeighbour = protoGraph->unsafe_get_node(idx);
		otherNeighboursOut += otherNeighbour->chain_remaining_out;
	}
	return otherNeighboursOut;
}

unsigned int heatmap_renderer::count_remaining_other_output(proto_graph *protoGraph, node_data *sourcenode, NODEINDEX ignoreNode)
{
	unsigned int otherNeighboursIn = 0;
	set<NODEINDEX>::iterator sourceoutgoingIt = sourcenode->outgoingNeighbours.begin();
	for (; sourceoutgoingIt != sourcenode->outgoingNeighbours.end(); sourceoutgoingIt++)
	{
		NODEINDEX idx = *sourceoutgoingIt;
		if (idx == ignoreNode) continue;
		node_data *neib = protoGraph->unsafe_get_node(idx);
		otherNeighboursIn += neib->chain_remaining_in;
	}
	return otherNeighboursIn;
}

unsigned int heatmap_renderer::heatmap_solver(proto_graph *protoGraph, bool lastRun, 
	vector<pair<NODEPAIR, edge_data *>> *unfinishedEdgeList, 
	vector<edge_data *> *finishedEdgeList, 
	map <NODEINDEX, bool> *errorNodes)
{
	unsigned int solverErrors = 0;

	//this won't work until nodes have correct values
	//it's a great way of detecting errors in a complete graph but in a running graph there are always going
	//to be discrepancies. still want to have a vaguely accurate heatmap in realtime though
	int attemptLimit = 5;
	vector<pair<NODEPAIR, edge_data *>>::iterator unfinishedIt;

	while (!unfinishedEdgeList->empty() && attemptLimit--)
	{
		unfinishedIt = unfinishedEdgeList->begin();
		for (; unfinishedIt != unfinishedEdgeList->end(); ++unfinishedIt)
		{
			NODEINDEX srcNodeIdx = unfinishedIt->first.first;
			NODEINDEX targNodeIdx = unfinishedIt->first.second;

			protoGraph->acquireNodeReadLock();
			node_data *tnode = protoGraph->unsafe_get_node(targNodeIdx);
			node_data *snode = protoGraph->unsafe_get_node(srcNodeIdx);

			//first see if edge's target node has other neighbours with input to give
			unsigned long targOtherNeighboursOut = count_remaining_other_input(protoGraph, tnode, srcNodeIdx);

			//no? then this is the only source node sending output into target node. 
			if (targOtherNeighboursOut == 0)
			{
				//only node with executions remaining has less executions than this node?
				if (tnode->chain_remaining_in <= snode->chain_remaining_out)
				{
					edge_data *edge = unfinishedIt->second;
					edge->chainedWeight = tnode->chain_remaining_in;
					tnode->chain_remaining_in = 0;
					snode->chain_remaining_out -= edge->chainedWeight;

					finishedEdgeList->push_back(edge);
					unfinishedIt = unfinishedEdgeList->erase(unfinishedIt);
					attemptLimit++;

					protoGraph->releaseNodeReadLock();
					break;
				}
				else
				{
					++solverErrors;
					if (lastRun && errorNodes->count(tnode->index) == 0)
					{
#ifdef DEBUG
						cerr << "[rgat]Heat solver warning 3: (TID" << dec << protoGraph->get_TID() << "): Targnode  " << tnode->index <<
							" has only one adjacent providing output, but needs more (" << tnode->chain_remaining_in << ") than snode ("
							<< snode->index << ") provides (" << snode->chain_remaining_out << ")" << endl;
#endif
						errorNodes->emplace(make_pair(tnode->index, true));
					}
				}
			}

			//see if sources other targets need input
			unsigned long sourceOtherNeighboursIn = count_remaining_other_output(protoGraph, snode, targNodeIdx);

			protoGraph->releaseNodeReadLock();

			//no? only targ edge taking input. complete edge and subtract from targ input 
			if (sourceOtherNeighboursIn == 0)
			{
				//only remaining follower node executed less than this node did
				if (snode->chain_remaining_out > tnode->chain_remaining_in)
				{
					++solverErrors;
					if (lastRun && errorNodes->count(snode->index) == 0)
					{
#ifdef DEBUG
						cerr << "[rgat]Heat solver warning 4: (TID" << dec << protoGraph->get_TID() << ") : Sourcenode " << snode->index
							<< " has one adjacent taking input, but has more (" << snode->chain_remaining_out << ") than the targnode ("
							<< tnode->index << ") needs (" << tnode->chain_remaining_in << ")" << endl;
#endif
						errorNodes->emplace(make_pair(snode->index, true));
					}
				}
				else
				{
					edge_data *edge = unfinishedIt->second;
					edge->chainedWeight = snode->chain_remaining_out;
					snode->chain_remaining_out = 0;
					tnode->chain_remaining_in -= edge->chainedWeight;

					finishedEdgeList->push_back(edge);
					unfinishedIt = unfinishedEdgeList->erase(unfinishedIt);
					++attemptLimit;
					break;
				}
			}
		}
	}
	return solverErrors;
}

void heatmap_renderer::build_colour_mapping(vector<edge_data *> *finishedEdgeList, std::set<unsigned long> *heatValues, map<unsigned long, COLSTRUCT> *heatColours)
{
	//build set of all heat values
	vector<edge_data *>::iterator finishedEdgeIt;
	for (finishedEdgeIt = finishedEdgeList->begin(); finishedEdgeIt != finishedEdgeList->end(); ++finishedEdgeIt)
	heatValues->insert(((edge_data *)*finishedEdgeIt)->chainedWeight);

	//create map of distances of each value in set
	map<unsigned long, int> heatDistances;
	set<unsigned long>::iterator setit;
	int distance = 0;
	for (setit = heatValues->begin(); setit != heatValues->end(); ++setit)
	heatDistances[*setit] = distance++;


	size_t maxDist = heatDistances.size();
	map<unsigned long, int>::iterator distit = heatDistances.begin();
	

	//create blue->red value for each numerical 'heat'
	int numColours = (int)colourRange.size();
	heatColours->emplace(make_pair(heatDistances.begin()->first, *colourRange.begin()));
	if (maxDist > 1)
	{
		for (std::advance(distit, 1); distit != heatDistances.end(); distit++)
		{
			float distratio = (float)distit->second / (float)maxDist;
			int colourIndex = min(numColours - 1, (int)floor(numColours*distratio));
			heatColours->emplace(make_pair(distit->first, colourRange.at(colourIndex)));
		}
	}

	unsigned long lastColour = heatDistances.rbegin()->first;
	if (heatColours->size() > 1)
		heatColours->emplace(make_pair(lastColour,*colourRange.rbegin()));
}

//when tracing a large program this is roughly %30 of rgats execution time (mainly the solver)
bool heatmap_renderer::render_graph_heatmap(plotted_graph *graph, bool lastRun)
{

	proto_graph *protoGraph = check_graph_ready(graph, clientState);
	if (!protoGraph) 
		return false;

	map <NODEINDEX, bool> errorNodes;
	vector<pair<NODEPAIR, edge_data *>> unfinishedEdgeList;
	vector<edge_data *> finishedEdgeList;

	unsigned int solverErrors = initialise_solver(protoGraph, lastRun, &unfinishedEdgeList, &finishedEdgeList, &errorNodes);
	solverErrors += heatmap_solver(protoGraph, lastRun, &unfinishedEdgeList, &finishedEdgeList, &errorNodes);

#ifdef DEBUG
	if (lastRun)
	{
		if (!unfinishedEdgeList.empty() || solverErrors)
		{

			cout << "-----Heatmap complete-----" << endl;
			cout << unfinishedEdgeList.size() << " unsolved edges: ";
			protoGraph->acquireNodeReadLock();
			vector<pair<NODEPAIR, edge_data *>>::iterator unfinishedIt = unfinishedEdgeList.begin();
			for (; unfinishedIt != unfinishedEdgeList.end(); unfinishedIt++)
			{
				NODEINDEX src = unfinishedIt->first.first;
				NODEINDEX targ = unfinishedIt->first.second;

				cout << "(" << dec << src << "->" << dec << targ << ") " << endl;
			}
			protoGraph->dropNodeReadLock();
			cout << "[rgat]Heatmap for for thread " << dec << protoGraph->get_TID() << " partially incomplete: Ending solver with " <<
				unfinishedEdgeList.size() << " unsolved / " << dec << solverErrors <<
				" errors. Trace may have errors (eg: due to ungraceful trace termination) or a cycle in the graph that confused the solver." << endl;
		}
	}
#endif

	std::set<unsigned long> heatValues;
	map<unsigned long, COLSTRUCT> heatColours;

	build_colour_mapping(&finishedEdgeList, &heatValues, &heatColours);
	graph->heatExtremes = make_pair(*heatValues.begin(), *heatValues.rbegin());

	graph->heatmaplines->reset();

	//finally build a colours buffer using the heat/colour map entry for each edge weight
	vector <float> *lineVector = graph->heatmaplines->acquire_col_write();
	unsigned int edgeindex = 0;
	unsigned int edgeEnd = graph->get_mainlines()->get_renderedEdges();

	COLSTRUCT badHeatColour;
	badHeatColour.a = 1;
	badHeatColour.b = 0;
	badHeatColour.g = 1;
	badHeatColour.r = 0;

	//draw the heatmap
	for (; edgeindex < edgeEnd; ++edgeindex)
	{
		edge_data *edge = protoGraph->get_edge(edgeindex);
		
		if (!edge) {
			cerr << "[rgat]WARNING: Heatmap2 edge skip"<<endl;
			continue;
		}

		COLSTRUCT *edgeColour = 0;
		//map<unsigned long, COLSTRUCT>::iterator foundHeatColour = heatColours.find(edge->weight);
		map<unsigned long, COLSTRUCT>::iterator foundHeatColour = heatColours.find(edge->chainedWeight);

		//this edge has an unreliable value due to a solver failure (likely a cycle or an ungraceful drgat termination)
		if (foundHeatColour != heatColours.end())
			edgeColour = &foundHeatColour->second;
		else
			edgeColour = &badHeatColour;

		float edgeColArr[4] = { edgeColour->r, edgeColour->g, edgeColour->b, edgeColour->a};

		NODEINDEX vertIdx = 0;
		assert(edge->vertSize);
		for (; vertIdx < edge->vertSize; ++vertIdx)
			lineVector->insert(lineVector->end(), edgeColArr, end(edgeColArr));

		graph->heatmaplines->inc_edgesRendered();
		graph->heatmaplines->set_numVerts(graph->heatmaplines->get_numVerts() + vertIdx);
	}

	graph->heatmaplines->release_col_write();
	graph->needVBOReload_heatmap = true;
	
	return true;
}

//convert 0-255 rgb to 0-1
inline float fcol(int value)
{
	return (float)value / 255.0;
}


//allegro_color kept breaking here and driving me insane - hence own stupidly redundant implementation
COLSTRUCT *col_to_colstruct(QColor *c)
{
	COLSTRUCT *cs = new COLSTRUCT;
	cs->r = c->redF();
	cs->g = c->greenF();
	cs->b = c->blueF();
	cs->a = c->alphaF();
	return cs;
}

void heatmap_renderer::gather_graphlist(vector<plotted_graph *> &graphlist)
{
	runRecord->graphListLock.lock();

	map <PID_TID, void *>::iterator graphIt = runRecord->plottedGraphs.begin();
	for (; graphIt != runRecord->plottedGraphs.end(); ++graphIt)
	{
		plotted_graph *g = (plotted_graph *)graphIt->second;
		if (g->increase_thread_references(3))
		{
			graphlist.push_back(g);
		}
	}
	runRecord->graphListLock.unlock();
}

void heatmap_renderer::render_graphlist(vector<plotted_graph *> &graphlist, map<plotted_graph *, bool> &finishedGraphs)
{
	vector<plotted_graph *>::iterator graphlistIt = graphlist.begin();
	while (graphlistIt != graphlist.end() && !die)
	{
		plotted_graph *graph = *graphlistIt++;
		proto_graph * protoGraphEnd = graph->get_protoGraph();
		//always rerender an active graph (edge executions may have increased without adding new edges)
		//render saved graphs if there are new edges
		size_t rendered_heat_edges = graph->heatmaplines->get_renderedEdges();
		if (protoGraphEnd->active || protoGraphEnd->get_num_edges() > graph->heatmaplines->get_renderedEdges())
		{
			if (rendered_heat_edges == 0)
			{
				//add our heatmap colours to a vector for quick lookup in render thread
				//may have changed in settings so do it every time graph is created from scratch
				colourRange.clear();
				for (int i = 0; i < 10; i++)
				{
					COLSTRUCT customColour = *col_to_colstruct(&clientState->config.heatmap.edgeFrequencyCol[i]);
					colourRange.insert(colourRange.begin(), customColour);
				}
			}
			render_graph_heatmap(graph, false);
		}
		else //last mop-up rendering of a recently finished graph
		{
			if (!finishedGraphs[graph])
			{
				finishedGraphs[graph] = true;
				render_graph_heatmap(graph, true);
			}
		}
		Sleep(20); //pause between graphs so other things don't struggle for mutex time
	}
}

void heatmap_renderer::release_graphlist_references(vector<plotted_graph *> &graphlist)
{
	for (auto graph : graphlist)
	{
		graph->decrease_thread_references(3);
	}
	graphlist.clear();
}

//thread handler to build graph for each thread
//allows display in thumbnail style format
void heatmap_renderer::main_loop()
{
	alive = true;

	PROCESS_DATA *piddata = runRecord->get_piddata();
	while ((!piddata || runRecord->plottedGraphs.empty()) && !die)
		Sleep(100);
	Sleep(500);

	vector<plotted_graph *> graphlist;
	map<plotted_graph *, bool> finishedGraphs;
	while (!clientState->rgatIsExiting())
	{
		gather_graphlist(graphlist);
		
		if (!runRecord->is_running() && (finishedGraphs.size() == graphlist.size()))
		{
			//process terminated, all graphs fully rendered, now head off to valhalla
			for (auto graph : graphlist)
				graph->decrease_thread_references(3);
			break;
		}

		render_graphlist(graphlist, finishedGraphs);

		release_graphlist_references(graphlist);

		int waitForNextIt = 0;
		while (waitForNextIt < updateDelayMS && !die)
		{
			Sleep(50);
			waitForNextIt += 50;
		}
	}

	alive = false;
}

