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
Most of the OpenGL functions are here
*/
#pragma once
#include "stdafx.h"

//void handle_resize(VISSTATE *clientstate);

void initial_gl_setup(VISSTATE *clientstate);
void frame_gl_setup(VISSTATE* clientstate);
void frame_gl_teardown();

void load_VBO(int index, GLuint *VBOs, int bufsize, float *data);
void load_edge_VBOS(GLuint *VBOs, GRAPH_DISPLAY_DATA *lines);
void loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *verts, GRAPH_DISPLAY_DATA *lines);
void gen_graph_VBOs(thread_graph_data *graph);

void array_render(int prim, int POSVBO, int COLVBO, GLuint *buffers, int quantity);

void rotate_to_user_view(VISSTATE *clientstate);

void edge_picking_colours(VISSTATE *clientstate, SCREEN_EDGE_PIX *TBRG, bool doClear = true);
void array_render_points(int POSVBO, int COLVBO, GLuint *buffers, int quantity);
void array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, int quantity);
void draw_wireframe(VISSTATE *clientstate, GLint *starts, GLint *sizes);
void plot_colourpick_sphere(VISSTATE *clientstate);

void drawHighlightLine(FCOORD endPt, ALLEGRO_COLOR *colour);
void gather_projection_data(PROJECTDATA *pd);