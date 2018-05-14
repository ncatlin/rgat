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
Class for the code that plots graph divergence
*/
#pragma once
#include "stdafx.h"
#include "graphplots/plotted_graph.h"
#include "graphGLWidget.h"

class diff_plotter 
{
public:

	diff_plotter(graphGLWidget *plotwindow, plotted_graph *graph1, plotted_graph *graph2, QFont *displayfont );
	~diff_plotter();

	void display_diff_summary(int x, int y);
	plotted_graph *get_diff_graph() { return diffgraph; }
	void render(graphGLWidget &gltarget);
	plotted_graph *get_graph(int idx);
	//return first node different between the two graphs
	NODEINDEX get_diff_node() { return diffNode; }
	NODEINDEX get_divergence_index() { return divergenceIdx;}
	bool wasDivergenceFound() {	return divergenceFound;	}

private:
	NODEPAIR firstLastNode(MEM_ADDRESS blockAddr, BLOCK_IDENTIFIER blockID, PROCESS_DATA *pd, PID_TID thread);
	void mark_divergence(NODEINDEX instructionIndex);

	PID_TID graph1pid, graph1tid, graph2pid, graph2tid;
	plotted_graph *graph1 = NULL;
	plotted_graph *graph2 = NULL;
	plotted_graph *diffgraph = NULL;
	graphGLWidget *window = NULL;

	NODEINDEX divergenceIdx = 0;
	NODEINDEX diffNode = 0;
	NODEINDEX lastNode = 0;
	NODEINDEX prevLastNode = 0;
	
	QColor edgeColour;
	QColor matchingEdgeColour;
	QColor divergingEdgeColour;
	QFont *diffont;

	PROCESS_DATA *g1ProcessData = NULL, *g2ProcessData = NULL;
	unsigned long animIndex = 0;
	unsigned int blockIdx = 0;

	bool doneFlag = false;
	bool divergenceFound = false;

	unordered_map <NODEPAIR, bool> matchingEdgeList;

};
