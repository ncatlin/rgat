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
#include "thread_graph_data.h"
#include "GUIStructs.h"

class diff_plotter {
public:
	thread_graph_data *get_diff_graph() { return diffgraph; }
	diff_plotter(thread_graph_data *graph1, thread_graph_data *graph2, VISSTATE *state);
	void display_diff_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState);
	unsigned long first_divering_edge();
	void render();
	thread_graph_data *get_graph(int idx);
	//return first node different between the two graphs
	node_data *get_diff_node() { return diffNode; }

private:
	bool diff_plotter::get_sequence_node(node_data **n1, node_data **n2);
	thread_graph_data *graph1;
	thread_graph_data *graph2;
	thread_graph_data *diffgraph;
	VISSTATE *clientState;
	unsigned long divergenceIdx = 0;
	node_data *diffNode = 0;

	PROCESS_DATA *g1ProcessData, *g2ProcessData;
	unsigned long animIndex = 0;
	unsigned int blockIdx = 0;

	node_data *last_node1, last_node2;
	bool doneFlag = false;

	unordered_map <NODEPAIR, bool> matchingEdgeList;
};
