#pragma once
#include "stdafx.h"
#include "GUIStructs.h"
#include "opengl_operations.h"
#include "graphicsMaths.h"
#include "node_data.h"
#include "edge_data.h"
#include "traceMisc.h"
#include "diff_plotter.h"

//takes the vertex data structure vertdata, start and end coordinate, colour, type, scaling factors and places resulting array position in arraypos
//not a nice call
int drawCurve(GRAPH_DISPLAY_DATA *vertdata, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, int edgetype, MULTIPLIERS *dimensions, int *arraypos);

//wireframe starts/sizes are the opengl vertex array positions/offsets
void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes);
void plot_wireframe(VISSTATE *clientstate);
void performMainGraphDrawing(VISSTATE *clientState, map <int, vector<EXTTEXT>> *externFloatingText);

int add_node(node_data *n, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata, MULTIPLIERS *dimensions, map<int, ALLEGRO_COLOR> *nodeColours);
int draw_new_nodes(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata, map<int, ALLEGRO_COLOR> *nodeColours);
void rescale_nodes(thread_graph_data *graph, bool isPreview);

void render_main_graph(VISSTATE *clientstate);
int render_preview_graph(thread_graph_data *activeGraph, VISSTATE *clientState);
void display_graph(VISSTATE *clientstate, thread_graph_data *graph, PROJECTDATA *pd);
void display_big_heatmap(VISSTATE *clientstate);
void display_big_conditional(VISSTATE *clientstate);
void display_graph_diff(VISSTATE *clientstate, diff_plotter *diffRenderer);

void drawHighlight(VCOORD *coord, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier);
void show_extern_labels(VISSTATE *clientstate, PROJECTDATA *pd, thread_graph_data *graph);
void draw_heatmap_key(VISSTATE *clientState);
void draw_conditional_key(VISSTATE *clientState);