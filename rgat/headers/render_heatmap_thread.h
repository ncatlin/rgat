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
#pragma once
#include <stdafx.h>
#include <set>

#include "traceStructs.h"
#include "graphplots/plotted_graph.h"
#include "base_thread.h"
#include "binaryTarget.h"

struct COLSTRUCT {
	float r;
	float g;
	float b;
	float a;
};

class heatmap_renderer : public base_thread
{
public:
	heatmap_renderer(traceRecord* runRecordptr)
		:base_thread() {
		runRecord = runRecordptr; binary = (binaryTarget *)runRecord->get_binaryPtr();
		setUpdateDelay(clientState->config.heatmap.delay);
	};

	void setUpdateDelay(int delay) { updateDelayMS = delay; }

private:
	binaryTarget *binary;
	traceRecord* runRecord;

	void main_loop();
	int updateDelayMS = 200;
	plotted_graph *thisgraph;
	bool render_graph_heatmap(plotted_graph *graph, bool verbose = false);
	unsigned int initialise_solver(proto_graph *protoGraph, bool verbose, vector<pair<NODEPAIR, edge_data *>> *unfinishedEdgeList, vector<edge_data *> *finishedEdgeList, map <NODEINDEX, bool> *errorNodes);
	inline unsigned int count_remaining_other_input(proto_graph *protoGraph, node_data *targnode, NODEINDEX ignoreNode);
	inline unsigned int count_remaining_other_output(proto_graph *protoGraph, node_data *sourcenode, NODEINDEX ignoreNode);
	unsigned int heatmap_solver(proto_graph *protoGraph, bool lastRun, vector<pair<NODEPAIR, edge_data *>> *unfinishedEdgeList, vector<edge_data *> *finishedEdgeList, map <NODEINDEX, bool> *errorNodes);
	void build_colour_mapping(vector<edge_data *> *finishedEdgeList, std::set<unsigned long> *heatValues, map<unsigned long, COLSTRUCT> *heatColours);
	vector<COLSTRUCT> colourRange;

};
