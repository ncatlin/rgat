#pragma once
#include <stdafx.h>

void write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label);
void write_tid_text(VISSTATE* clientState, int threadid, thread_graph_data *graph, int x, int y);

void uploadPreviewGraph(thread_graph_data *previewgraph);
void drawGraphBitmap(thread_graph_data *previewgraph, VISSTATE *clientState);
bool find_mouseover_thread(VISSTATE *clientState, int mousex, int mousey, int *PID, int* TID);
void display_preview_mouseover();
void drawPreviewGraphs(VISSTATE *clientState, map <int, NODEPAIR> *graphPositions);