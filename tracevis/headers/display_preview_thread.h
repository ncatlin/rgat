#pragma once
#include "traceStructs.h"
#include "GUIStructs.h"
#include "GUIConstants.h"


class preview_display_thread
{
public:
	thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	VISSTATE *clientState;
	int mousex = 0;
	int mousey = 0;
	bool clicked = false;

protected:
	unsigned int focusedThread = -1;
	ALLEGRO_FONT *font = 0;
	map<int, map<int, ALLEGRO_BITMAP *>> graphBmps;
	int yrotate = 110;
	int windowHeight;
	int windowWidth;
	int bitmapWidth;
	map <int, pair<int, int>> graphPositions;

private:
	void previewThread();
	void write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label);
	void uploadPreviewGraph(THREADGRAPH *previewgraph);
	void drawGraphBitmap(THREADGRAPH *previewgraph, VISSTATE *clientstate, ALLEGRO_BITMAP *threadBitmap);
	void write_pid_text(int pid, PID_DATA *piddata, int x, int y);
	void write_tid_text(int threadid, THREADGRAPH *graph, int x, int y);
	bool find_mouseover_thread(int *PID, int* TID);
	void display_mouseover();
	
};