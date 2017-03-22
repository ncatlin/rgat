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
Describes the position of each vertex in the sphere
performs functions that are specific to the sphere shape
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
	cylinder_graph(PROCESS_DATA* processdata, unsigned int threadID, proto_graph *protoGraph, vector<ALLEGRO_COLOR> *coloursPtr)
		: plotted_graph(protoGraph, coloursPtr) {
		initialise();
	};
	~cylinder_graph() {
		free(wireframeStarts);
		free(wireframeSizes);
	};

	void maintain_draw_wireframe(VISSTATE *clientState);
	void plot_wireframe(VISSTATE *clientState);
	void performMainGraphDrawing(VISSTATE *clientState);
	bool get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo);
	void render_static_graph(VISSTATE *clientState);
	void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier);
	void drawHighlight(void* graphCoord, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier);

	bool render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate);
	unsigned int get_graph_size() { return main_scalefactors->size; };
	SPHERECOORD *get_node_coord(NODEINDEX idx);

	void orient_to_user_view(int xshift, int yshift, long zoom);
	void initialiseDefaultDimensions();

	void adjust_A_edgeSep(float delta);
	void adjust_B_edgeSep(float delta);
	void reset_edgeSep();
	bool pending_rescale() { return rescale; }

protected:
	int add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		GRAPH_SCALE *dimensions);
	FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier);

private:
	void initialise();
	void write_rising_externs(ALLEGRO_FONT *font, bool nearOnly, int height, PROJECTDATA *pd);
	void display_graph(VISSTATE *clientState, PROJECTDATA *pd);
	void positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode);
	bool get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);
	int drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD *startC, FCOORD *endC,
		ALLEGRO_COLOR *colour, int edgeType, GRAPH_SCALE *dimensions, int *arraypos);
	bool a_coord_on_screen(int a, float hedgesep);
	void cylinderCoord(SPHERECOORD *sc, FCOORD *c, GRAPH_SCALE *dimensions, float diamModifier = 0);
	void cylinderCoord(float a, float b, FCOORD *c, GRAPH_SCALE *dimensions, float diamModifier);
	void cylinderAB(FCOORD *c, float *a, float *b, GRAPH_SCALE *dimensions);
	void cylinderAB(DCOORD *c, float *a, float *b, GRAPH_SCALE *dimensions);
	int needed_wireframe_loops();
	void draw_wireframe();
	void regenerate_wireframe_if_needed();
	void regen_wireframe_buffers();

	int wireframe_loop_count = 0;
	GRAPH_DISPLAY_DATA *wireframe_data;
	GLuint wireframeVBOs[2];
	bool remakeWireframe = false;
	bool wireframeBuffersCreated = false;
	GLint *wireframeStarts, *wireframeSizes;

	vector<SPHERECOORD> node_coords;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <NODEINDEX, bool> activeNodeMap;

	int pix_per_A, pix_per_B;
	bool rescale = false;


};

