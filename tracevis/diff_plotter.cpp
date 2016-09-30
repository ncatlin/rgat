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
Class for the code that plots graph divergence
*/
#include "stdafx.h"
#include "diff_plotter.h"
#include "rendering.h"
#include "thread_graph_data.h"

diff_plotter::diff_plotter(thread_graph_data *g1, thread_graph_data *g2, VISSTATE *state)
{
	graph1 = g1;
	graph2 = g2;
	diffgraph = new thread_graph_data(state->glob_piddata_map.at(g1->pid),0);
	diffgraph->m_scalefactors = graph1->m_scalefactors;
	diffgraph->needVBOReload_main = true;
	glGenBuffers(4, diffgraph->graphVBOs);
	clientState = state;
}

thread_graph_data *diff_plotter::get_graph(int idx) {
	if (idx == 1) return graph1;
	return graph2;
}

void diff_plotter::display_diff_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState)
{
	stringstream infotxt1, infotxt2, infotxt3;

	infotxt1 << "Green (PID: " << graph2->pid << " TID: " << graph2->tid <<
		") Path: " << graph2->modPath << " (" << divergenceIdx << " common edges)";
	infotxt2 << "Red+Green (PID:" << graph1->pid << " TID:" << graph1->tid <<
		") Path: " << graph1->modPath << " (" << graph1->get_num_edges() - divergenceIdx << " edges total)";

	int textVSep = font->height + 5;
	al_draw_text(font, al_col_white, x, y, ALLEGRO_ALIGN_LEFT, infotxt1.str().c_str());
	al_draw_text(font, al_col_white, x, y + textVSep, ALLEGRO_ALIGN_LEFT, infotxt2.str().c_str());
}

//first edge pair in graph 1 that is different in graphs 1 and 2
unsigned long diff_plotter::first_divering_edge()
{
	EDGELIST::iterator edgeSeqItG1, edgeSeqEndG1, nextEdgeG1;
	graph1->start_edgeL_iteration(&edgeSeqItG1, &edgeSeqEndG1);

	EDGELIST::iterator edgeSeqItG2, edgeSeqEndG2,nextEdgeG2;
	graph2->start_edgeL_iteration(&edgeSeqItG2, &edgeSeqEndG2);

	node_data *g1targNode = graph1->get_node(0);
	node_data *g2targNode = graph2->get_node(0);
	node_data *sourceNode = 0;

	unsigned long seqIndex = 0;
	for (; edgeSeqItG1 != edgeSeqEndG1; )
	{
		int target1 = edgeSeqItG1->second;
		int target2 = edgeSeqItG2->second;

		if (target1 != target2) break;

		g1targNode = graph1->get_node(target1);
		g2targNode = graph2->get_node(target2);

		if (g1targNode->external || g2targNode->external)
		{
			if (!g1targNode->external || !g2targNode->external) break;

			int modnum1 = g2targNode->nodeMod;
			if (g1targNode->address != g2targNode->address) break;
		}
		else
		{
			//different instruction is clear cut trace divergence
			if (g1targNode->ins->mnemonic != g2targNode->ins->mnemonic)
			{
				cout << "[rgat]Divergence at nodes " << g1targNode->index << " Graph1 instruction " << g1targNode->ins->ins_text <<
					" different to Graph 2 instruction " << g2targNode->ins->ins_text << endl;
				break;
			}

			//comparing target addresses not much use with aslr
			//can possibly measure distance between addresses?, but won't help with jumps to different memory regions
			//for now: only compare register operands

			nextEdgeG1 = edgeSeqItG1 + 1;
			nextEdgeG2 = edgeSeqItG2 + 1;
			//if (n1targ->ins->m && n1targ->ins->conditional) break;


			
			if (g1targNode->ins->op_str != g2targNode->ins->op_str)
			{
				cout << "[rgat]Divergence at nodes " << g1targNode->index << " Graph1 op_str " << g1targNode->ins->op_str <<
					" different to Graph 2 op_str " << g2targNode->ins->op_str << endl;
				break;
			}
		}

		++seqIndex;
		++edgeSeqItG1;
		++edgeSeqItG2;
		sourceNode = g1targNode;
	}
	graph1->stop_edgeL_iteration();
	graph2->stop_edgeL_iteration();

	diffNode = sourceNode;

	if (edgeSeqItG1 != edgeSeqEndG1)
		return seqIndex;
	else
		return graph1->get_num_edges()-1;
}

void diff_plotter::render() 
{
	EDGELIST::iterator edgeSeqItG1;
	EDGELIST::iterator edgeSeqEndG1;
	
	divergenceIdx = first_divering_edge();
	unsigned long renderIdx = 0;

	GRAPH_DISPLAY_DATA *linedata = diffgraph->get_mainlines();
	ALLEGRO_COLOR *edgeColour = &al_col_green;

	graph1->start_edgeL_iteration(&edgeSeqItG1, &edgeSeqEndG1);
	for (; edgeSeqItG1 != edgeSeqEndG1; ++edgeSeqItG1)
	{
		if (renderIdx++ == divergenceIdx) edgeColour = &al_col_red;
		graph1->render_edge(*edgeSeqItG1, linedata, NULL, edgeColour);
	}
	graph1->stop_edgeL_iteration();
	diffgraph->needVBOReload_main = true;
}