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
Miscellaneous graphics routines that don't fit into the graph class
*/

#pragma once
#include "stdafx.h"

#include "GUIStructs.h"
#include "opengl_operations.h"
#include "graphicsMaths.h"
#include "node_data.h"
#include "edge_data.h"
#include "traceMisc.h"

#include "diff_plotter.h"

void display_graph_diff(VISSTATE *clientState, diff_plotter *diffRenderer);

//takes the vertex data structure vertdata, start and end coordinate, colour, type, scaling factors and places resulting array position in arraypos
//not a nice call
int drawCurve(GRAPH_DISPLAY_DATA *vertdata, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, int edgetype, MULTIPLIERS *dimensions, int *arraypos);

void draw_heatmap_key(VISSTATE *clientState);
void draw_conditional_key(VISSTATE *clientState);

void draw_internal_symbol(VISSTATE *clientState, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n);
void draw_func_args(VISSTATE *clientState, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n);
