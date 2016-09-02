#include "stdafx.h"
#include "GUIStructs.h"
#include "rendering.h"

void gather_projection_data(PROJECTDATA *pd) {
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glGetDoublev(GL_MODELVIEW_MATRIX, pd->model_view);
	glGetDoublev(GL_PROJECTION_MATRIX, pd->projection);
	glGetIntegerv(GL_VIEWPORT, pd->viewport);
}

void handle_resize(VISSTATE *clientstate) {
	glViewport(0, 0, clientstate->size.width, clientstate->size.height);
}

void frame_gl_setup(VISSTATE* clientstate)
{
	glMatrixMode(GL_PROJECTION);
	glPushMatrix();

	glLoadIdentity();
	gluPerspective(45, clientstate->size.width / clientstate->size.height, 500, 
		clientstate->zoomlevel + clientstate->activeGraph->m_scalefactors->radius);

	glMatrixMode(GL_MODELVIEW);
	glPushMatrix();

	rotate_to_user_view(clientstate);

	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glEnable(GL_ALPHA);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
}

void gen_graph_VBOs(thread_graph_data *graph)
{
	glGenBuffers(4, graph->graphVBOs);
	glGenBuffers(4, graph->previewVBOs);
	glGenBuffers(1, graph->heatmapEdgeVBO);
	glGenBuffers(2, graph->conditionalVBOs);
	glGenBuffers(4, graph->activeVBOs);
	graph->VBOsGenned = true;
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

void initial_gl_setup(VISSTATE *clientstate)
{
	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glEnable(GL_ALPHA);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_DEPTH);
	glEnable(GL_DEPTH_TEST);
	glDepthFunc(GL_ALWAYS);

	glMatrixMode(GL_MODELVIEW);
	glPointSize(DEFAULTPOINTSIZE);
	glClearColor(0, 0, 0, 1.0);
	gluPerspective(45, clientstate->size.width / clientstate->size.height, 50, clientstate->zoomlevel + 60000);
}

//draw a segmented sphere with row gradiented red, cols green
int plot_colourpick_sphere(VISSTATE *clientstate)
{
	GRAPH_DISPLAY_DATA *spheredata = clientstate->col_pick_sphere;
	if (spheredata)
		delete spheredata;

	spheredata = new GRAPH_DISPLAY_DATA(COL_SPHERE_BUFSIZE);
	clientstate->col_pick_sphere = spheredata;

	int diam = clientstate->activeGraph->m_scalefactors->radius;

	int rowi, coli;
	float tlx, tlz, trx, ytop, trz;
	float ybase, brx, brz, blz, blx;
	int dr = 0;

	int rowAngle = (int)(360 / BDIVISIONS);
	int quads = 0;
	int bufpos = 0;

	vector<GLfloat> *spherepos = spheredata->acquire_pos("1a");
	vector<GLfloat> *spherecol = spheredata->acquire_col("1a");
	for (rowi = 180; rowi >= 0; rowi -= rowAngle) {
		float colb = (float)rowi / 180;
		float ringSizeTop, ringSizeBase, anglel, angler;
		for (coli = 0; coli < ADIVISIONS; ++coli) {

			float cola = 1 - ((float)coli / ADIVISIONS);

			float iitop = rowi;
			float iibase = rowi + rowAngle;

			anglel = (2 * M_PI * coli) / ADIVISIONS;
			angler = (2 * M_PI * (coli + 1)) / ADIVISIONS;

			ringSizeTop = diam * sin((iitop*M_PI) / 180);
			ytop = diam * cos((iitop*M_PI) / 180);
			tlx = ringSizeTop * cos(anglel);
			trx = ringSizeTop * cos(angler);
			tlz = ringSizeTop * sin(anglel);
			trz = ringSizeTop * sin(angler);

			ringSizeBase = diam * sin((iibase*M_PI) / 180);
			ybase = diam * cos((iibase*M_PI) / 180);
			blx = ringSizeBase * cos(anglel);
			blz = ringSizeBase * sin(anglel);
			brx = ringSizeBase * cos(angler);
			brz = ringSizeBase * sin(angler);

			int i;
			for (i = 0; i < 4; ++i)
			{
				spherecol->push_back(colb);
				spherecol->push_back(cola);
				spherecol->push_back(0);
			}

			spherepos->push_back(tlx);
			spherepos->push_back(ytop);
			spherepos->push_back(tlz);
			spherepos->push_back(trx);
			spherepos->push_back(ytop);
			spherepos->push_back(trz);
			spherepos->push_back(brx);
			spherepos->push_back(ybase);
			spherepos->push_back(brz);
			spherepos->push_back(blx);
			spherepos->push_back(ybase);
			spherepos->push_back(blz);
			quads += 4;
		}
	}

	load_VBO(VBO_SPHERE_POS, clientstate->colSphereVBOs, COL_SPHERE_BUFSIZE, &spherepos->at(0));
	load_VBO(VBO_SPHERE_COL, clientstate->colSphereVBOs, COL_SPHERE_BUFSIZE, &spherecol->at(0));
	spheredata->release_col();
	spheredata->release_pos();
	return 0;
}

void rotate_to_user_view(VISSTATE *clientstate)
{

	glTranslatef(0, 0, -clientstate->zoomlevel);
	glRotatef(-clientstate->yturn, 1, 0, 0);
	glRotatef(-clientstate->xturn, 0, 1, 0);
}

//draw a colourful gradiented sphere on the screen
//read colours on edge so we can see where window is on sphere
//reset back to state before the call
//return colours in passed S_E_P struct
//pass doclear false if you want to see it, just for debugging
void edge_picking_colours(VISSTATE *clientstate, SCREEN_EDGE_PIX *TBRG, bool doClear)
{
	
	if (!clientstate->col_pick_sphere)
		plot_colourpick_sphere(clientstate);
	glPushMatrix();
	gluPerspective(45, clientstate->size.width / clientstate->size.height, 500, clientstate->zoomlevel);
	glLoadIdentity();

	rotate_to_user_view(clientstate);

	glBindBuffer(GL_ARRAY_BUFFER, clientstate->colSphereVBOs[0]);
	glVertexPointer(3, GL_FLOAT, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, clientstate->colSphereVBOs[1]);
	glColorPointer(3, GL_FLOAT, 0, 0);
	glDrawArrays(GL_QUADS, 0, COL_SPHERE_VERTS);

	GLfloat pixelRGB[3];
	
	//no idea why this ajustment needed, found by trial and error
	int height = clientstate->size.height - 20;
	int width = al_get_bitmap_width(clientstate->mainGraphBMP);
	int halfheight = height / 2;
	int halfwidth = width / 2;

	//TODO think we might not use top and bottom
	glReadPixels(0, halfheight, 1, 1, GL_RGB, GL_FLOAT, pixelRGB);
	TBRG->leftgreen = pixelRGB[1];
	glReadPixels(width - 1, halfheight, 1, 1, GL_RGB, GL_FLOAT, pixelRGB);
	TBRG->rightgreen = pixelRGB[1];
	glReadPixels(halfwidth, height - 1, 1, 1, GL_RGB, GL_FLOAT, pixelRGB);
	TBRG->topred = pixelRGB[0];
	glReadPixels(halfwidth, 3, 1, 1, GL_RGB, GL_FLOAT, pixelRGB);
	TBRG->bottomred = pixelRGB[0];

	glPopMatrix();

	if (doClear)
		glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

	return;
}

void array_render_points(int POSVBO, int COLVBO, GLuint *buffers, int quantity) {
	array_render(GL_POINTS, POSVBO, COLVBO, buffers, quantity);
}

void array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, int quantity) {
	array_render(GL_LINES, POSVBO, COLVBO, buffers, quantity);
}

//todo: see if we can have this done in a single array call by using one big loop,
//link them together with alpha 0 edges to give same appearance
//then can ditch the starts/sizes
void draw_wireframe(VISSTATE *clientstate, GLint *starts, GLint *sizes)
{
	glBindBuffer(GL_ARRAY_BUFFER, clientstate->wireframeVBOs[VBO_SPHERE_POS]);
	glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, clientstate->wireframeVBOs[VBO_SPHERE_COL]);
	glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

	glMultiDrawArrays(GL_LINE_LOOP, starts, sizes, WIREFRAMELOOPS);
}

void drawHighlightLine(FCOORD p1, FCOORD p2, ALLEGRO_COLOR *colour) {
	glColor4f(colour->r, colour->g, colour->b, colour->a);
	glBegin(GL_LINES);
	glVertex3f(p1.x, p1.y, p1.z);
	glVertex3f(p2.x, p2.y, p2.z);
	glEnd();
}
