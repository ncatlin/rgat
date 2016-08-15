#pragma once
#include "stdafx.h"

void handle_resize(VISSTATE *clientstate);

void initial_gl_setup(VISSTATE *clientstate);
void frame_gl_setup(VISSTATE* clientstate);
void frame_gl_teardown();

void load_VBO(int index, GLuint *VBOs, int bufsize, float *data);
void load_edge_VBOS(GLuint *VBOs, GRAPH_DISPLAY_DATA *lines);
void loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *verts, GRAPH_DISPLAY_DATA *lines);

//DCOORD get_node_screen_pos(node_data *n, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd);
void array_render(int prim, int POSVBO, int COLVBO, GLuint *buffers, int quantity);

//int draw_colourpick_sphere(float diam);

void rotate_to_user_view(VISSTATE *clientstate);

void edge_picking_colours(VISSTATE *clientstate, SCREEN_EDGE_PIX *TBRG, bool doClear = true);
void array_render_points(int POSVBO, int COLVBO, GLuint *buffers, int quantity);
void array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, int quantity);
void draw_wireframe(VISSTATE *clientstate, GLint *starts, GLint *sizes);
int plot_colourpick_sphere(VISSTATE *clientstate);

void drawRedLine(FCOORD p1, FCOORD p2);
void gather_projection_data(PROJECTDATA *pd);