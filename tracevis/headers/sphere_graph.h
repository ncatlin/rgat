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
Monsterous class that handles the bulk of graph management 
*/

#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "plotted_graph.h"
#include "traceMisc.h"

class sphere_graph : public plotted_graph
{

public:
	sphere_graph(PROCESS_DATA* processdata, unsigned int threadID, proto_graph *protoGraph): plotted_graph(protoGraph) {};
	~sphere_graph() {};

	void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes);
	void plot_wireframe(VISSTATE *clientState);
	void performMainGraphDrawing(VISSTATE *clientState, map <PID_TID, vector<EXTTEXT>> *externFloatingText);
	void draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);
	void show_symbol_labels(VISSTATE *clientState, PROJECTDATA *pd);
	void render_static_graph(VISSTATE *clientState);
	void drawHighlight(NODEINDEX nodeIndex, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier);
	bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate);

protected:
	int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		MULTIPLIERS *dimensions, map<int, ALLEGRO_COLOR> *nodeColours);
	void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);
	void draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata);
	FCOORD nodeIndexToXYZ(NODEINDEX index, MULTIPLIERS *dimensions, float diamModifier);

private:
	void write_rising_externs(ALLEGRO_FONT *font, bool nearOnly, int left, int right, int height, PROJECTDATA *pd);
	void display_graph(VISSTATE *clientState, PROJECTDATA *pd);
	void positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode);
	bool get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);

	vector<VCOORD> node_coords;
	vector<pair<MEM_ADDRESS, NODEINDEX>> callStack;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <NODEINDEX, bool> activeNodeMap;

	VCOORD *get_node_coord(NODEINDEX idx) {
		if (idx >= node_coords.size()) return 0;
		return &node_coords.at(idx); //mutex?
	}
};

