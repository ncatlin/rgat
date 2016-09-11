#include "stdafx.h"
#include "diff_plotter.h"
#include "rendering.h"
#include "thread_graph_data.h"

diff_plotter::diff_plotter(thread_graph_data *g1, thread_graph_data *g2, VISSTATE *state)
{
	graph1 = g1;
	graph2 = g2;
	diffgraph = new thread_graph_data(0,0);
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
	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqItG1;
	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqEndG1;
	graph1->start_edgeL_iteration(&edgeSeqItG1, &edgeSeqEndG1);

	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqItG2;
	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqEndG2;
	graph2->start_edgeL_iteration(&edgeSeqItG2, &edgeSeqEndG2);

	unsigned long seqIndex = 0;
	for (; edgeSeqItG1 != edgeSeqEndG1; )
	{
		int target1 = edgeSeqItG1->second;
		int target2 = edgeSeqItG2->second;

		if (target1 != target2) break;

		node_data *n1targ = graph1->get_node(target1);
		node_data *n2targ = graph2->get_node(target2);

		if (n1targ->external || n2targ->external)
		{
			if (!n1targ->external || !n2targ->external) break;
			if (n1targ->address != n2targ->address) break;
		}
		else
		{
			if (n1targ->ins->mnemonic != n2targ->ins->mnemonic) break;
			if (n1targ->ins->op_str != n2targ->ins->op_str) break;
		}

		seqIndex++;
		edgeSeqItG1++;
		edgeSeqItG2++;
	}
	graph1->stop_edgeL_iteration();
	graph2->stop_edgeL_iteration();

	if (edgeSeqItG1 != edgeSeqEndG1)
		return seqIndex;
	else
		return graph1->get_num_edges()-1;
}

void diff_plotter::render() 
{
	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqItG1;
	vector<pair<unsigned int, unsigned int>>::iterator edgeSeqEndG1;
	
	divergenceIdx = first_divering_edge();
	unsigned long renderIdx = 0;

	GRAPH_DISPLAY_DATA *linedata = diffgraph->get_mainlines();
	ALLEGRO_COLOR *edgeColour = &al_col_green;

	graph1->start_edgeL_iteration(&edgeSeqItG1, &edgeSeqEndG1);
	for (; edgeSeqItG1 != edgeSeqEndG1; edgeSeqItG1++)
	{
		if (renderIdx++ == divergenceIdx) edgeColour = &al_col_red;
		graph1->render_edge(*edgeSeqItG1, linedata, NULL, edgeColour);
	}
	graph1->stop_edgeL_iteration();
	diffgraph->needVBOReload_main = true;
}