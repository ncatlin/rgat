#pragma once
#include "stdafx.h"
#include "thread_graph_data.h"
#include "GUIStructs.h"

class diff_plotter {
public:
	thread_graph_data *get_diff_graph() { return diffgraph; }
	diff_plotter(thread_graph_data *graph1, thread_graph_data *graph2, VISSTATE *state);
	void display_diff_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState);
	unsigned long first_divering_edge();
	void render();
	thread_graph_data *get_graph(int idx);

private:
	thread_graph_data *graph1;
	thread_graph_data *graph2;
	thread_graph_data *diffgraph;
	VISSTATE *clientState;
	unsigned long divergenceIdx = 0;
};
