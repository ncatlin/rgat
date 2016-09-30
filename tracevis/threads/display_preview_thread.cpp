#include "stdafx.h"
#include "display_preview_thread.h"
#include "GUIConstants.h"
#include <sstream>

/*
void preview_display_thread::write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label)
{
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	al_draw_text(font, textcol, x, y, ALLEGRO_ALIGN_LEFT, label);
}

void preview_display_thread::uploadPreviewGraph(THREADGRAPH *previewgraph) {
	GLuint *VBOs = previewgraph->previewVBOs;
	glGenBuffers(4, VBOs);
	load_VBO(VBO_VERTEX_POS, VBOs, previewgraph->previewverts->vpsize, previewgraph->previewverts->vposarray);
	load_VBO(VBO_VERTEX_COL, VBOs, previewgraph->previewverts->vcsize, previewgraph->previewverts->vcolarray);

	int posbufsize = previewgraph->previewlines->numVerts * POSELEMS * sizeof(GLfloat);
	int linebufsize = previewgraph->previewlines->numVerts * COLELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_POS, VBOs, posbufsize, previewgraph->previewlines->vposarray);
	load_VBO(VBO_LINE_COL, VBOs, linebufsize, previewgraph->previewlines->vcolarray);

	previewgraph->needVBOReload_preview = false;
}


void preview_display_thread::drawGraphBitmap(THREADGRAPH *previewgraph, VISSTATE *clientstate, ALLEGRO_BITMAP* bitmap) {
	if (previewgraph->needVBOReload_preview)
		uploadPreviewGraph(previewgraph);

	al_set_target_bitmap(bitmap);

	glClearColor(0.4, 0, 0, 1);
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

	write_tid_text(previewgraph->thread, previewgraph, 0, 0);

	glPushMatrix();

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	double aspect = bitmapWidth / PREV_BITMAP_HEIGHT;
	gluPerspective(45, aspect, 1, 3000);
	glMatrixMode(GL_MODELVIEW);

	glTranslatef(0, -20, 0);
	glTranslatef(0, 0, -550);

	glRotatef(30, 1, 0, 0);
	glRotatef(-yrotate / 1.0, 0, 1, 0);

	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	array_render_points(VBO_VERTEX_POS, VBO_VERTEX_COL, previewgraph->previewVBOs, previewgraph->previewverts->numVerts);
	array_render_lines(VBO_LINE_POS, VBO_LINE_COL, previewgraph->previewVBOs, previewgraph->previewlines->numVerts);
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glPopMatrix();

	al_set_target_bitmap(clientState->previewPaneBMP);

}

void preview_display_thread::write_tid_text(int threadid, THREADGRAPH *graph, int x, int y)
{
	stringstream infotxt;
	ALLEGRO_COLOR textcol;

	infotxt << "THREAD: " << threadid;

	if (clientState->activeGraph && threadid == clientState->activeGraph->thread)
		textcol = al_col_green;
	else
	{
		if (graph->active)
			textcol = al_col_white;
		else
			textcol = al_col_red;
	}
	write_text(font, textcol, x, y, infotxt.str().c_str());
}

void preview_display_thread::write_pid_text(int pid, PID_DATA *piddata, int x, int y)
{
	stringstream infotxt;
	ALLEGRO_COLOR textcol;
	infotxt << "PID: " << pid;
	if (piddata->active)
		textcol = al_col_white;
	else
		textcol = al_col_red;

	write_text(font, textcol, x, y, infotxt.str().c_str());
}

bool preview_display_thread::find_mouseover_thread(int *PID, int* TID)
{
	mousex -= PREV_THREAD_X_PAD;
	if (mousex >= 0 && mousex <= bitmapWidth)
	{
		map <int, pair<int, int>>::iterator graphPosIt = graphPositions.begin();
		while (graphPosIt != graphPositions.end())
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

void preview_display_thread::display_mouseover()
{
	printf("x");
	return;
}

void __stdcall preview_display_thread::ThreadEntry(void* pUserData) {
	return ((preview_display_thread*)pUserData)->previewThread();
}

void preview_display_thread::previewThread() {

	//if (!al_init()) {
	//	fprintf(stderr, "failed to initialize allegro!\n");
	//	return;
	//}
	
	int startx, starty;
	//al_get_window_position(clientState->maindisplay, &startx, &starty);
	//startx += al_get_display_width(clientState->maindisplay)+ 11;
	//starty += 33;
	//al_set_new_window_position(startx, starty);
	//al_set_new_display_flags(ALLEGRO_OPENGL | ALLEGRO_WINDOWED | ALLEGRO_RESIZABLE);
	//display = al_create_display(400, 800);
	//al_set_window_title(display, "Thread Select");
	font = al_create_builtin_font();

	bool spinGraphs = true;

	glPointSize(5);
	glClearColor(.0, .2, .2, 1);
	ALLEGRO_COLOR preview_bgcol = al_map_rgb(0, 0, 0);
	ALLEGRO_COLOR red = al_col_red;
	ALLEGRO_COLOR white = al_col_white;
	int first = 0;

	while (!clientState->activeGraph)
		al_rest(0.01);

	clientState->previewPaneBMP = al_create_bitmap(400, clientState->size.height);

	WaitForSingleObject(clientState->displayMutex, 500);
	al_set_target_bitmap(clientState->previewPaneBMP);
	while (true)
	{
		al_clear_to_color(preview_bgcol);
		glLoadIdentity();
		glPushMatrix();

		DWORD waitresult = WaitForSingleObject(clientState->pidMapMutex, 2000);
		if (waitresult == WAIT_TIMEOUT) {
			printf("\n\n[preview]ERROR! pidMapMutex HELD LONG TIME in create thread! ERROR!\n");
			return;
		}

		if (clientState->glob_piddata_map.empty()) {
			printf("pid map empty, exiting ...\n");
			break;
		}
		std::map<int, PID_DATA *>::iterator pidit = clientState->glob_piddata_map.begin();
		std::map<int, THREADGRAPH>::iterator threadit;

		THREADGRAPH *previewGraph = 0;
		ALLEGRO_BITMAP *previewBitmap = 0;

		windowHeight = al_get_display_height(clientState->maindisplay);
		windowWidth = 400;
		bitmapWidth = (windowWidth - PREV_THREAD_X_PAD) - PREV_SCROLLBAR_WIDTH;
		int texty = 15;
		int graphy = 15;

		while (pidit != clientState->glob_piddata_map.end())
		{
			int PID = pidit->first;
			write_pid_text(PID, pidit->second, 0, texty);
			texty += 15;
			graphy += 15;

			if (graphBmps.count(PID) == 0)
			{
				map<int, ALLEGRO_BITMAP *> threadBitmaps;
				graphBmps[PID] = threadBitmaps;
			}

			threadit = pidit->second->graphs.begin();
			while (threadit != pidit->second->graphs.end())
			{
				previewGraph = &threadit->second;
				int TID = threadit->first;

				if (graphBmps[PID].count(TID) == 0)
				{
					map<int, ALLEGRO_BITMAP*> *threadBitmaps = &graphBmps[PID];
					ALLEGRO_BITMAP *threadBitmap = al_create_bitmap(bitmapWidth, PREV_BITMAP_HEIGHT);
					graphBmps[PID][TID] = threadBitmap;
				}

				if (previewGraph && previewGraph->previewverts->numVerts)
				{
					previewBitmap = graphBmps[PID][TID];
					if (spinGraphs || previewGraph->needVBOReload_preview)
						drawGraphBitmap(previewGraph, clientState, previewBitmap);
					al_draw_bitmap(previewBitmap, PREV_THREAD_X_PAD, graphy, 0);
					graphPositions[graphy] = make_pair(PID, TID);
					graphy += (PREV_BITMAP_HEIGHT + 20);
					texty += (PREV_BITMAP_HEIGHT + 20);
				}
				else
				{
					graphy += 12;
					texty += font->height + 12;
				}

				threadit++;
			}
			pidit++;
		}
		ReleaseMutex(clientState->pidMapMutex);
		ReleaseMutex(clientState->displayMutex);

		if (spinGraphs)
		{
			yrotate++;
			if (yrotate > 360) yrotate = 0;
		}



		int mouseTID, mousePID;
		if (find_mouseover_thread(&mousePID, &mouseTID))
		{
			display_mouseover();
			//insert mouseover here
		}

		if (clicked && mousePID > -1)
		{
			printf("Setting PID:%d, TID:%d graph to active\n", mousePID, mouseTID);
			//send selection to main thread
			clientState->newActiveGraph = &clientState->glob_piddata_map[mousePID]->graphs[mouseTID];
			clicked = false;
		}
		graphPositions.clear();

		al_rest(0.02);
	}
}
*/