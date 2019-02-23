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
Describes the position of each vertex in the tree graph
performs functions that are specific to the tree shape
*/

#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "plotted_graph.h"
#include "traceMisc.h"
#include "graphicsMaths.h"


class tree_graph : public plotted_graph
{

public:
	tree_graph(unsigned int threadID, proto_graph *protoGraph, vector<QColor> *coloursPtr)
		: plotted_graph(protoGraph, coloursPtr) {
		initialise();
	};
	~tree_graph();

	void performMainGraphDrawing(graphGLWidget &gltarget);
	void render_static_graph();
	bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, QColor *colourOverride, bool preview, bool noUpdate);

	void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
	void drawHighlight(GENERIC_COORD& nodeCoord, GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);

	bool get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo, graphGLWidget &gltarget);
	TREECOORD *get_node_coord(NODEINDEX idx);

	void orient_to_user_view();
	void initialiseDefaultDimensions();

	unsigned int get_graph_size() { return 10; };

	pair<void *, float> get_diffgraph_nodes() { return make_pair(&node_coords, maxB); }
	void set_diffgraph_nodes(pair<void *, float> diffData) { node_coords = (vector <TREECOORD>*)diffData.first; maxB = diffData.second; }

protected:
	void add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, 
		GRAPH_DISPLAY_DATA *animvertdata,
		GRAPH_SCALE *dimensions);

	FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier);

private:
	void initialise();

	void display_graph(PROJECTDATA *pd, graphGLWidget &gltarget);
	int drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD &startC, FCOORD &endC,
		QColor &colour, int edgeType, GRAPH_SCALE *dimensions, long *arraypos);
	void write_rising_externs(PROJECTDATA *pd, graphGLWidget &gltarget);

	void positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode);
	bool get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);
	void treeCoord(long ia, long b, long c, FCOORD *coord, GRAPH_SCALE *dimensions);
	void treeAB(FCOORD &coord, GRAPH_SCALE *mults, long *a, long *b, long *c);

private:
	vector<TREECOORD> node_coords_storage;
	vector<TREECOORD> *node_coords = &node_coords_storage;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <NODEINDEX, bool> activeNodeMap;
	
};

