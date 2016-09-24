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
Header for the preview pane, with previews of each graph in a scrolling vertical bar
*/
#pragma once
#include <stdafx.h>

#define PREV_Y_MULTIPLIER (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_Y_OFFSET)

void write_text(ALLEGRO_FONT* font, ALLEGRO_COLOR textcol, int x, int y, const char *label);

void uploadPreviewGraph(thread_graph_data *previewgraph);
void drawGraphBitmap(thread_graph_data *previewgraph, VISSTATE *clientState);
bool find_mouseover_thread(VISSTATE *clientState, int mousex, int mousey, int *PID, int* TID);
void drawPreviewGraphs(VISSTATE *clientState, map <int, NODEPAIR> *graphPositions);