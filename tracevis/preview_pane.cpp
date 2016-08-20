#include <stdafx.h>
#include "GUIStructs.h"
#include "opengl_operations.h"
#include "traceMisc.h"
#include "GUIManagement.h"


void write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label)
{
	al_draw_text(font, textcol, x, y, ALLEGRO_ALIGN_LEFT, label);
}

void write_tid_text(VISSTATE* clientState, int threadid, thread_graph_data *graph, int x, int y)
{
	stringstream infotxt;
	ALLEGRO_COLOR textcol;

	infotxt << "THREAD: " << threadid;

	if (graph->active)
	{
		textcol = al_col_green;
		infotxt << " (Running)";
	}
	else
	{
		textcol = al_col_white;
		infotxt << " (Finished)";
	}
	write_text(clientState->standardFont, textcol, x+3, y+2, infotxt.str().c_str());
}


void uploadPreviewGraph(thread_graph_data *previewgraph) {
	GLuint *VBOs = previewgraph->previewVBOs;
	glGenBuffers(4, VBOs);
	load_VBO(VBO_NODE_POS, VBOs, previewgraph->previewverts->pos_size(), previewgraph->previewverts->readonly_pos());
	load_VBO(VBO_NODE_COL, VBOs, previewgraph->previewverts->col_size(), previewgraph->previewverts->readonly_col());

	int posbufsize = previewgraph->previewlines->get_numVerts() * POSELEMS * sizeof(GLfloat);
	int linebufsize = previewgraph->previewlines->get_numVerts() * COLELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_POS, VBOs, posbufsize, previewgraph->previewlines->readonly_pos());
	load_VBO(VBO_LINE_COL, VBOs, linebufsize, previewgraph->previewlines->readonly_col());

	previewgraph->needVBOReload_preview = false;
}


void drawGraphBitmap(thread_graph_data *previewgraph, VISSTATE *clientState) {
	if (previewgraph->previewBMP == 0)
	{
		al_set_new_bitmap_flags(ALLEGRO_VIDEO_BITMAP);
		previewgraph->previewBMP = al_create_bitmap(PREVIEW_GRAPH_WIDTH, PREVIEW_GRAPH_HEIGHT);
	}


	if (previewgraph->needVBOReload_preview)
		uploadPreviewGraph(previewgraph);

	ALLEGRO_BITMAP *prevBmp = al_get_target_bitmap();

	al_set_target_bitmap(previewgraph->previewBMP);
	ALLEGRO_COLOR preview_gcol;
	if (previewgraph->active)
		preview_gcol = al_map_rgb(0, 20, 0);
	else
		preview_gcol = al_map_rgb(20, 0, 0);
	al_clear_to_color(preview_gcol);

	//draw white box around it
	if (clientState->activeGraph == previewgraph)
	{
		glColor3f(1, 1, 1);
		glBegin(GL_LINE_LOOP);

		glVertex3f(1, 1, 0);
		glVertex3f(PREVIEW_GRAPH_WIDTH-1, 1, 0);
		glVertex3f(PREVIEW_GRAPH_WIDTH-1, PREVIEW_GRAPH_HEIGHT-1, 0);
		glVertex3f(1, PREVIEW_GRAPH_HEIGHT - 1, 0);
		glVertex3f(1, 1, 0);
		glEnd();

	}

	write_tid_text(clientState, previewgraph->tid, previewgraph, 0, 0);


	glPushMatrix();

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	double aspect = PREVIEW_GRAPH_WIDTH / PREVIEW_GRAPH_HEIGHT;
	gluPerspective(45, aspect, 1, 3000);
	glMatrixMode(GL_MODELVIEW);

	glTranslatef(0, -20, 0);
	glTranslatef(0, 0, -550);

	glRotatef(30, 1, 0, 0);
	glRotatef(clientState->previewYAngle, 0, 1, 0);
	glRotatef(90 / 1.0, 0, 1, 0);

	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	array_render_points(VBO_NODE_POS, VBO_NODE_COL, previewgraph->previewVBOs, previewgraph->previewverts->get_numVerts());
	array_render_lines(VBO_LINE_POS, VBO_LINE_COL, previewgraph->previewVBOs, previewgraph->previewlines->get_numVerts());
	glPopMatrix();

	glDisableClientState(GL_VERTEX_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);

	al_set_target_bitmap(prevBmp);
}


bool find_mouseover_thread(VISSTATE *clientState, int mousex, int mousey, int *PID, int* TID)
{
	int graphsX = (clientState->size.width - PREVIEW_PANE_WIDTH) + PREV_THREAD_X_PAD;
	if (mousex >= graphsX && mousex <= clientState->size.width)
	{
		map <int, pair<int, int>>::iterator graphPosIt = clientState->graphPositions.begin();
		while (graphPosIt != clientState->graphPositions.end())
		{
			if (mousey >= graphPosIt->first && mousey <= (graphPosIt->first + 200))
			{
				*PID = graphPosIt->second.first;
				*TID = graphPosIt->second.second;
				return true;
			}
			graphPosIt++;
		}

	}
	*PID = -1;
	*TID = -1;
	return false;
}

void display_preview_mouseover()
{
	printf("x");
	return;
}


void drawPreviewGraphs(VISSTATE *clientState, map <int, pair<int, int>> *graphPositions) {

	if (clientState->glob_piddata_map.empty() || !clientState->activeGraph) {
		printf("pid map empty, exiting ...\n");
		return;
	}
	ALLEGRO_BITMAP *prevBmp = al_get_target_bitmap();
	bool spinGraphs = true;

	glPointSize(5);

	ALLEGRO_COLOR preview_bgcol = al_map_rgb(0, 0, 0);
	ALLEGRO_COLOR red = al_col_red;
	ALLEGRO_COLOR white = al_col_white;
	int first = 0;

	if (!obtainMutex(clientState->pidMapMutex, "Preview Pane")) return;

	//std::map<int, PID_DATA *>::iterator pidit = clientState->glob_piddata_map.begin();
	std::map<int, void *>::iterator threadit;

	thread_graph_data *previewGraph = 0;

	int windowHeight = al_get_display_height(clientState->maindisplay);
	int windowWidth = 400;
	int bitmapWidth = (windowWidth - PREV_THREAD_X_PAD) - PREV_SCROLLBAR_WIDTH;

#define Y_MULTIPLIER (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_Y_OFFSET)
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	int graphy = 50 - Y_MULTIPLIER*widgets->getScroll();
	int numGraphs = 0;
	int graphsHeight = 0; 

	al_set_target_bitmap(clientState->previewPaneBMP);
	al_clear_to_color(preview_bgcol);

	glLoadIdentity();
	glPushMatrix();

	threadit = clientState->activePid->graphs.begin();
	while (threadit != clientState->activePid->graphs.end())
	{
		previewGraph = (thread_graph_data *)threadit->second;
		int TID = threadit->first;
		if (previewGraph && previewGraph->previewverts->get_numVerts())
		{
			if (clientState->previewSpin || previewGraph->needVBOReload_preview)
				drawGraphBitmap(previewGraph, clientState);

			al_set_target_bitmap(clientState->previewPaneBMP);
			al_draw_bitmap(previewGraph->previewBMP, PREV_THREAD_X_PAD, graphy, 0);

			clientState->graphPositions[graphy] = make_pair(clientState->activePid->PID, TID);
			graphy += Y_MULTIPLIER;
			graphsHeight += Y_MULTIPLIER;
			numGraphs++;
		}
		
		threadit++;
	}

	glPopMatrix();
	dropMutex(clientState->pidMapMutex, "Preview Pane");
	al_set_target_bitmap(prevBmp);

	int scrollDiff = graphsHeight - clientState->size.height;
	if (scrollDiff < 0) widgets->setScrollbarMax(0);
	else
		widgets->setScrollbarMax(numGraphs - clientState->size.height/ Y_MULTIPLIER);

	if (clientState->previewSpin)
	{
		clientState->previewYAngle -= PREVIEW_SPIN_PER_FRAME;
		if (clientState->previewYAngle < -360) clientState->previewYAngle = 0;
	}
}
