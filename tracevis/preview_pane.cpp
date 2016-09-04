#include <stdafx.h>
#include "GUIStructs.h"
#include "opengl_operations.h"
#include "traceMisc.h"
#include "GUIManagement.h"
#include "preview_pane.h"

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


void uploadPreviewGraph(thread_graph_data *previewgraph) 
{
	GLuint *VBOs = previewgraph->previewVBOs;
	load_VBO(VBO_NODE_POS, VBOs, previewgraph->previewnodes->pos_size(), previewgraph->previewnodes->readonly_pos());
	load_VBO(VBO_NODE_COL, VBOs, previewgraph->previewnodes->col_size(), previewgraph->previewnodes->readonly_col());

	int posbufsize = previewgraph->previewlines->get_numVerts() * POSELEMS * sizeof(GLfloat);
	int linebufsize = previewgraph->previewlines->get_numVerts() * COLELEMS * sizeof(GLfloat);
	if (!posbufsize || !linebufsize) return;
	load_VBO(VBO_LINE_POS, VBOs, posbufsize, previewgraph->previewlines->readonly_pos());
	load_VBO(VBO_LINE_COL, VBOs, linebufsize, previewgraph->previewlines->readonly_col());

	previewgraph->needVBOReload_preview = false;
}


void drawGraphBitmap(thread_graph_data *previewgraph, VISSTATE *clientState) 
{

	if (!previewgraph->previewBMP)
	{
		al_set_new_bitmap_flags(ALLEGRO_VIDEO_BITMAP);
		previewgraph->previewBMP = al_create_bitmap(PREVIEW_GRAPH_WIDTH, PREVIEW_GRAPH_HEIGHT);
	}

	if (previewgraph->needVBOReload_preview)
		uploadPreviewGraph(previewgraph);

	ALLEGRO_BITMAP *previousBmp = al_get_target_bitmap();

	al_set_target_bitmap(previewgraph->previewBMP);
	ALLEGRO_COLOR preview_gcol;
	if (previewgraph->active)
		preview_gcol = clientState->config->preview.activeHighlight;
	else
		preview_gcol = clientState->config->preview.inactiveHighlight;
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

	array_render_points(VBO_NODE_POS, VBO_NODE_COL, previewgraph->previewVBOs, previewgraph->previewnodes->get_numVerts());
	array_render_lines(VBO_LINE_POS, VBO_LINE_COL, previewgraph->previewVBOs, previewgraph->previewlines->get_numVerts());
	glPopMatrix();

	glDisableClientState(GL_VERTEX_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);

	al_set_target_bitmap(previousBmp);
}


bool find_mouseover_thread(VISSTATE *clientState, int mousex, int mousey, int *PID, int* TID)
{
	if (mousex >= clientState->mainFrameSize.width && mousex <= clientState->displaySize.width)
	{
		map <int, NODEPAIR>::iterator graphPosIt = clientState->graphPositions.begin();
		for (; graphPosIt != clientState->graphPositions.end(); graphPosIt++)
		{
			const int graphTop = graphPosIt->first;
			if (mousey >= graphTop && mousey <= (graphTop + PREVIEW_GRAPH_HEIGHT))
			{
				*PID = graphPosIt->second.first;
				*TID = graphPosIt->second.second;
				return true;
			}
		}
	}

	*PID = -1;
	*TID = -1;
	return false;
}

void drawPreviewGraphs(VISSTATE *clientState, map <int, NODEPAIR> *graphPositions) 
{

	if (clientState->glob_piddata_map.empty() || !clientState->activeGraph) {
		printf("pid map empty, exiting ...\n");
		return;
	}
	ALLEGRO_BITMAP *previousBmp = al_get_target_bitmap();
	bool spinGraphs = true;

	glPointSize(5);

	ALLEGRO_COLOR preview_bgcol = clientState->config->preview.background;
	int first = 0;

	if (!obtainMutex(clientState->pidMapMutex, "Preview Pane")) return;

	thread_graph_data *previewGraph = 0;

	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	int graphy = -1*PREV_Y_MULTIPLIER*widgets->getScroll();
	int numGraphs = 0;
	int graphsHeight = 0; 
	const float spinPerFrame = clientState->config->preview.spinPerFrame;

	al_set_target_bitmap(clientState->previewPaneBMP);
	al_clear_to_color(preview_bgcol);

	glLoadIdentity();
	glPushMatrix();

	map<int, void *>::iterator threadit = clientState->activePid->graphs.begin();
	for (;threadit != clientState->activePid->graphs.end(); threadit++)
	{
		previewGraph = (thread_graph_data *)threadit->second;
		
		if (!previewGraph || !previewGraph->previewnodes->get_numVerts()) continue;

		if (!previewGraph->VBOsGenned) 
			gen_graph_VBOs(previewGraph);

		if (spinPerFrame || previewGraph->needVBOReload_preview)
			drawGraphBitmap(previewGraph, clientState);

		al_set_target_bitmap(clientState->previewPaneBMP);
		al_draw_bitmap(previewGraph->previewBMP, PREV_GRAPH_PADDING, graphy, 0);

		int TID = threadit->first;
		clientState->graphPositions[50+graphy] = make_pair(clientState->activePid->PID, TID);
		graphy += PREV_Y_MULTIPLIER;
		graphsHeight += PREV_Y_MULTIPLIER;
		numGraphs++;

	}

	glPopMatrix();
	dropMutex(clientState->pidMapMutex, "Preview Pane");
	al_set_target_bitmap(previousBmp);

	int scrollDiff = graphsHeight - clientState->displaySize.height;
	if (scrollDiff < 0) 
		widgets->setScrollbarMax(0);
	else
		widgets->setScrollbarMax(numGraphs - clientState->displaySize.height / PREV_Y_MULTIPLIER);

	if (spinPerFrame)
	{
		clientState->previewYAngle -= spinPerFrame;
		if (clientState->previewYAngle < -360) clientState->previewYAngle = 0;
	}
}
