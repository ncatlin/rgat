#pragma once
#include <stdafx.h>
#include <set>
#include "GUIStructs.h"
#include "traceStructs.h"
#include "thread_graph_data.h"

struct COLSTRUCT {
	float r;
	float g;
	float b;
};
class heatmap_renderer
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	bool die = false;
	void setUpdateDelay(int delay) { updateDelayMS = delay; }

private:
	int updateDelayMS = 200;

	void heatmap_thread();
	bool render_graph_heatmap(thread_graph_data *graph);
	vector<COLSTRUCT> colourRange;

};
