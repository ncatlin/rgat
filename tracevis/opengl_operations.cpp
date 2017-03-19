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
#include "stdafx.h"

#include "rendering.h"
#include "plotted_graph.h"

//this call is a bit sensitive and will give odd results if called in the wrong place
void gather_projection_data(PROJECTDATA *pd) 
{
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glGetDoublev(GL_MODELVIEW_MATRIX, pd->model_view);
	glGetDoublev(GL_PROJECTION_MATRIX, pd->projection);
	glGetIntegerv(GL_VIEWPORT, pd->viewport);
}

void frame_gl_setup(VISSTATE* clientState)
{
	glMatrixMode(GL_PROJECTION);
	glPushMatrix();

	glLoadIdentity();

	plotted_graph *activeGraph = (plotted_graph *)clientState->activeGraph;

	bool zoomedIn = false;
	if (activeGraph)
	{
		float zmul = zoomFactor(clientState->cameraZoomlevel, activeGraph->main_scalefactors->size);
		if (zmul < INSTEXT_VISIBLE_ZOOMFACTOR)
			zoomedIn = true;
	
		if (zoomedIn || clientState->modes.nearSide)
			gluPerspective(45, clientState->mainFrameSize.width / clientState->mainFrameSize.height, 500,
				clientState->cameraZoomlevel);
		else
			gluPerspective(45, clientState->mainFrameSize.width / clientState->mainFrameSize.height, 500, 
				clientState->cameraZoomlevel + activeGraph->main_scalefactors->size);
	}
	else
		gluPerspective(45, clientState->mainFrameSize.width / clientState->mainFrameSize.height, 500,
			clientState->cameraZoomlevel);


	glMatrixMode(GL_MODELVIEW);
	glPushMatrix();

	activeGraph->orient_to_user_view(clientState->view_shift_x, clientState->view_shift_y, clientState->cameraZoomlevel);

	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glEnable(GL_ALPHA);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
}



void frame_gl_teardown()
{
	glDisableClientState(GL_VERTEX_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);
	glPopMatrix();
	glPopMatrix();
}

void load_VBO(int index, GLuint *VBOs, int bufsize, float *data)
{
	glBindBuffer(GL_ARRAY_BUFFER, VBOs[index]);
	glBufferData(GL_ARRAY_BUFFER, bufsize, data, GL_DYNAMIC_DRAW);
}

void load_edge_VBOS(GLuint *VBOs, GRAPH_DISPLAY_DATA *lines)
{
	int posbufsize = lines->get_numVerts() * POSELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_POS, VBOs, posbufsize, lines->readonly_pos());

	int linebufsize = lines->get_numVerts() * COLELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_COL, VBOs, linebufsize, lines->readonly_col());
}

void loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *verts, GRAPH_DISPLAY_DATA *lines)
{
	load_VBO(VBO_NODE_POS, VBOs, verts->pos_size(), verts->readonly_pos());
	load_VBO(VBO_NODE_COL, VBOs, verts->col_size(), verts->readonly_col());
	load_edge_VBOS(VBOs, lines);
}

void array_render(int prim, int POSVBO, int COLVBO, GLuint *buffers, int quantity)
{
	glBindBuffer(GL_ARRAY_BUFFER, buffers[POSVBO]);
	glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, buffers[COLVBO]);
	glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

	//Check VBOs have been loaded if crashing here
	glDrawArrays(prim, 0, quantity);
	glBindBuffer(GL_ARRAY_BUFFER, 0);

}

void initial_gl_setup(VISSTATE *clientState)
{
	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glEnable(GL_ALPHA);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_DEPTH);
	glEnable(GL_DEPTH_TEST);
	glDepthFunc(GL_ALWAYS);

	glMatrixMode(GL_MODELVIEW);
	glPointSize(DEFAULTPOINTSIZE);
	glClearColor(0, 0, 0, 1.0);
}

void array_render_points(int POSVBO, int COLVBO, GLuint *buffers, int quantity) 
{
	array_render(GL_POINTS, POSVBO, COLVBO, buffers, quantity);
}

void array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, int quantity) 
{
	array_render(GL_LINES, POSVBO, COLVBO, buffers, quantity);
}


void drawHighlightLine(FCOORD lineEndPt, ALLEGRO_COLOR *colour) {
	glColor4f(colour->r, colour->g, colour->b, colour->a);
	glBegin(GL_LINES);
	glVertex3f(0, 0, 0);
	glVertex3f(lineEndPt.x, lineEndPt.y, lineEndPt.z);
	glEnd();
}
