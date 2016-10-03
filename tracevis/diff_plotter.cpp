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

	unsigned long maxBBs = max(graph1->bbsequence.size(), graph2->bbsequence.size());
	infotxt1 << "Green (PID: " << graph2->pid << " TID: " << graph2->tid <<
		") Path: " << graph2->modPath << " (" << animIndex << " common block executions)";
	infotxt2 << "Red+Green (PID:" << graph1->pid << " TID:" << graph1->tid <<
		") Path: " << graph1->modPath << " (" << maxBBs - divergenceIdx << " blocks executed)";

	int textVSep = font->height + 5;
	al_draw_text(font, al_col_white, x, y, ALLEGRO_ALIGN_LEFT, infotxt1.str().c_str());
	al_draw_text(font, al_col_white, x, y + textVSep, ALLEGRO_ALIGN_LEFT, infotxt2.str().c_str());
}

bool diff_plotter::get_sequence_node(node_data **n1, node_data **n2)
{
	bool ignore = false;
	pair<MEM_ADDRESS, int> targBlock_Size1 = graph1->bbsequence.at(animIndex);
	BLOCK_IDENTIFIER blockID1 = graph1->mutationSequence.at(animIndex);
	MEM_ADDRESS blockAddr1 = targBlock_Size1.first;
	int numInstructions1 = targBlock_Size1.second;

	pair<MEM_ADDRESS, int> targBlock_Size2 = graph1->bbsequence.at(animIndex);
	BLOCK_IDENTIFIER blockID2 = graph2->mutationSequence.at(animIndex);
	MEM_ADDRESS blockAddr2 = targBlock_Size2.first;
	int numInstructions2 = targBlock_Size2.second;

	if (numInstructions1 != numInstructions2)
	{
		cout << "Graphs diverges after node " << last_node1->index << endl;
		return false;
	}

	if (blockIdx == numInstructions1)
	{
		blockIdx = 0;
		++animIndex;
		if (animIndex == graph1->bbsequence.size() || animIndex == graph2->bbsequence.size())
		{
			if (animIndex == graph1->bbsequence.size() && animIndex == graph2->bbsequence.size())
				doneFlag = true;

			return false;
		}
		targBlock_Size1 = graph1->bbsequence.at(animIndex);
		blockID1 = graph1->mutationSequence.at(animIndex);
		blockAddr1 = targBlock_Size1.first;
		targBlock_Size2 = graph2->bbsequence.at(animIndex);
		blockID2 = graph2->mutationSequence.at(animIndex);
		blockAddr2 = targBlock_Size2.first;
	}

	INSLIST *block1 = getDisassemblyBlock(blockAddr1, blockID1, g1ProcessData, &ignore);
	INS_DATA *ins1 = block1->at(blockIdx);
	int idx1 = ins1->threadvertIdx.at(graph1->tid);
	*n1 = graph1->get_node(idx1);

	INSLIST *block2 = getDisassemblyBlock(blockAddr2, blockID2, g2ProcessData, &ignore);
	INS_DATA *ins2 = block2->at(blockIdx);
	int idx2 = ins2->threadvertIdx.at(graph2->tid);
	*n2 = graph2->get_node(idx2);

	blockIdx++;
	return true;
}

//first edge pair in graph 1 that is different in graphs 1 and 2
unsigned long diff_plotter::first_divering_edge()
{
	obtainMutex(graph1->animationListsMutex, 9932);
	obtainMutex(graph2->animationListsMutex, 9932);
	g1ProcessData = clientState->glob_piddata_map.at(graph1->pid);
	g2ProcessData = clientState->glob_piddata_map.at(graph2->pid);

	unsigned long compareIndex = 0;

	node_data *g1Node;
	node_data *g2Node;
	node_data *sourceNode = 0;

	bool ignore = false;
	unsigned long animPosition = 0;
	unsigned int prevVertIdx = 0;
	while ((animPosition < graph1->bbsequence.size()) && (animPosition < graph2->bbsequence.size()))
	{

		if (!get_sequence_node(&g1Node, &g2Node)) break;
		int g1Index = g1Node->index;
		int g2Index = g2Node->index;
		if (g1Index != g2Index)
		{
			cout << "Divergence after vert index " << prevVertIdx << endl;
			cout << "graph1 goes to idx " << g1Index << ", graph2 goes to idx " << g2Index << endl;
			break;
		}

		if (g1Node->external || g2Node->external)
		{
			if (!g1Node->external || !g2Node->external) break;

			int modnum1 = g1Node->nodeMod;
			if (g1Node->address != g2Node->address) break;
		}
		else
		{
			//different instruction is clear cut trace divergence
			if (g1Node->ins->mnemonic != g2Node->ins->mnemonic)
			{
				cout << "[rgat]Divergence at nodes " << g1Index << " Graph1 instruction " << g1Node->ins->ins_text <<
					" different to Graph 2 instruction " << g2Node->ins->ins_text << endl;
				break;
			}

			//comparing target addresses not much use with aslr
			//can possibly measure distance between addresses?, but won't help with jumps to different memory regions
			//for now: only compare register operands
			
			if (g1Node->ins->op_str != g2Node->ins->op_str)
			{
				cout << "[rgat]Divergence at nodes " << g1Index << " Graph1 op_str " << g1Node->ins->op_str <<
					" different to Graph 2 op_str " << g2Node->ins->op_str << endl;
				break;
			}
		}

		if (g1Node->index > 0)
			matchingEdgeList[make_pair(sourceNode->index, g1Index)] = true;
		sourceNode = g1Node;
	}

	diffNode = sourceNode;

	dropMutex(graph1->animationListsMutex);
	dropMutex(graph2->animationListsMutex);
	return animIndex;

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
		if (matchingEdgeList.count(*edgeSeqItG1)) 
			graph1->render_edge(*edgeSeqItG1, linedata, NULL, &al_col_green);
		else
			graph1->render_edge(*edgeSeqItG1, linedata, NULL, &al_col_red);
	}
	graph1->stop_edgeL_iteration();
	diffgraph->needVBOReload_main = true;
}