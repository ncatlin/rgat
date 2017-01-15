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
#pragma once
#include "stdafx.h"
#include "proto_graph.h"
#include "sphere_graph.h"
#include "GUIStructs.h"



class diff_plotter {
public:
	plotted_graph *get_diff_graph() { return diffgraph; }
	diff_plotter(plotted_graph *graph1, plotted_graph *graph2, VISSTATE *state);
	//void display_diff_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState);

	void render();
	plotted_graph *get_graph(int idx);
	//return first node different between the two graphs
	NODEINDEX get_diff_node() { return diffNode; }

private:
	NODEPAIR firstLastNode(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, PROCESS_DATA *pd, PID_TID thread);
	void mark_divergence();

	plotted_graph *graph1;
	plotted_graph *graph2;
	plotted_graph *diffgraph;
	VISSTATE *clientState;
	unsigned long divergenceIdx = 0;
	NODEINDEX diffNode = 0;
	NODEINDEX lastNode = 0;
	bool divergenceFound = false;

	ALLEGRO_COLOR edgeColour;
	ALLEGRO_COLOR matchingEdgeColour;
	ALLEGRO_COLOR divergingEdgeColour;

	PROCESS_DATA *g1ProcessData, *g2ProcessData;
	unsigned long animIndex = 0;
	unsigned int blockIdx = 0;

	bool doneFlag = false;

	unordered_map <NODEPAIR, bool> matchingEdgeList;
};
