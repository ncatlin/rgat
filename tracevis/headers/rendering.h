#pragma once
#include "stdafx.h"
#include "GUIStructs.h"
#include "opengl_operations.h"
#include "graphicsMaths.h"
#include "node_data.h"
#include "edge_data.h"
#include "traceMisc.h"
#include "diff_plotter.h"

int drawCurve(GRAPH_DISPLAY_DATA *vertdata, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, int edgetype, MULTIPLIERS *dimensions, int *arraypos);

void plot_wireframe(VISSTATE *clientstate);

int add_vert(node_data *n, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata, MULTIPLIERS *dimensions);
//int add_edge(edge_data *e, node_data *sourceNode, node_data *targetNode,
//	GRAPH_DISPLAY_DATA *edgedata, MULTIPLIERS *dimensions, VISSTATE *clientstate, ALLEGRO_COLOR *forceColour = 0);

int draw_new_verts(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata);
void resize_verts(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata);

int render_main_graph(VISSTATE *clientstate);
int render_preview_graph(thread_graph_data *activeGraph, bool *rescale, VISSTATE *clientState);
void display_graph(VISSTATE *clientstate, thread_graph_data *graph, PROJECTDATA *pd);
void display_big_heatmap(VISSTATE *clientstate);
void display_big_conditional(VISSTATE *clientstate);
void display_graph_diff(VISSTATE *clientstate, diff_plotter *diffRenderer);

void draw_anim_line(node_data *node, thread_graph_data *graph);
void show_extern_labels(VISSTATE *clientstate, PROJECTDATA *pd, thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata);