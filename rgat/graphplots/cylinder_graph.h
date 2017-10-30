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
Describes the position of each vertex in the cylinder
performs functions that are specific to the cylinder shape
*/

#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "plotted_graph.h"
#include "traceMisc.h"

#define CYLINDER_PIXELS_PER_ROW 3000

class cylinder_graph : public plotted_graph
{

public:
	cylinder_graph(unsigned int threadID, proto_graph *protoGraph, vector<QColor> *coloursPtr)
		: plotted_graph(protoGraph, coloursPtr) {
		layout = eCylinderLayout;
	};
	~cylinder_graph();

	void maintain_draw_wireframe(graphGLWidget *gltarget);
	void plot_wireframe(graphGLWidget *gltarget);

	void performMainGraphDrawing(graphGLWidget *gltarget);
	void render_static_graph();
	bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, QColor *forceColour, bool preview, bool noUpdate);

	void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, QColor *colour, int lengthModifier, graphGLWidget *gltarget);
	void drawHighlight(void* graphCoord, GRAPH_SCALE *scale, QColor *colour, int lengthModifier, graphGLWidget *gltarget);

	bool get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo, graphGLWidget *gltarget);

	pair<void *, float> get_diffgraph_nodes() { return make_pair(&node_coords,maxB); }
	void set_diffgraph_nodes(pair<void *, float> diffData) { node_coords = (vector <CYLINDERCOORD>*)diffData.first; maxB = diffData.second; }
	unsigned int get_graph_size() { return main_scalefactors->plotSize; };

	void orient_to_user_view();
	void initialiseDefaultDimensions(); 
	void initialiseCustomDimensions(GRAPH_SCALE scale);

	float previewZoom() { return -2550; }
	int prevScrollYPosition() { return 580; }

	int getNearestNode(QPoint screenPos, graphGLWidget *gltarget, node_data **node);

protected:
	int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		GRAPH_SCALE *dimensions);
	FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier);

private:
	void initialise();
	int needed_wireframe_loops();
	void draw_wireframe(graphGLWidget *gltarget);
	void regenerate_wireframe_if_needed();
	void regen_wireframe_buffers(graphGLWidget *gltarget);

	void display_graph(PROJECTDATA *pd, graphGLWidget *gltarget);
	int drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD *startC, FCOORD *endC,
		QColor *colour, int edgeType, GRAPH_SCALE *dimensions, long *arraypos);
	void write_rising_externs(PROJECTDATA *pd, graphGLWidget *gltarget);
	
	void positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode);
	CYLINDERCOORD *get_node_coord(NODEINDEX idx);
	bool get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);
	bool a_coord_on_screen(int a, float hedgesep);
	void cylinderCoord(CYLINDERCOORD *sc, FCOORD *c, GRAPH_SCALE *dimensions, float diamModifier = 0);
	void cylinderCoord(float a, float b, FCOORD *c, GRAPH_SCALE *dimensions, float diamModifier);
	void cylinderAB(FCOORD *c, float *a, float *b, GRAPH_SCALE *dimensions);
	void cylinderAB(DCOORD *c, float *a, float *b, GRAPH_SCALE *dimensions);

	void add_to_callstack(bool isPreview, MEM_ADDRESS address, NODEINDEX idx);

private:
	int wireframe_loop_count = 0;
	GRAPH_DISPLAY_DATA *wireframe_data = NULL;
	GLuint wireframeVBOs[2];
	bool remakeWireframe = false;
	bool wireframeBuffersCreated = false;
	vector<GLint> wireframeStarts, wireframeSizes;

	vector<CYLINDERCOORD> node_coords_storage;
	vector<CYLINDERCOORD> *node_coords = &node_coords_storage;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <NODEINDEX, bool> activeNodeMap;
};

