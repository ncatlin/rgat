#pragma once
#include <stdafx.h>

#define PREV_Y_MULTIPLIER (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_Y_OFFSET)

void write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label);
void write_tid_text(VISSTATE* clientState, thread_graph_data *graph, int x, int y);

void uploadPreviewGraph(thread_graph_data *previewgraph);
void drawGraphBitmap(thread_graph_data *previewgraph, VISSTATE *clientState);
bool find_mouseover_thread(VISSTATE *clientState, int mousex, int mousey, int *PID, int* TID);
void drawPreviewGraphs(VISSTATE *clientState, map <int, NODEPAIR> *graphPositions);