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
The thread that performs low (ie:periodic) performance rendering of all graphs for the preview pane
*/
#pragma once
#include <stdafx.h>
#include <set>
#include "GUIStructs.h"
#include "traceStructs.h"
#include "plotted_graph.h"
#include "base_thread.h"

struct COLSTRUCT {
	float r;
	float g;
	float b;
	float a;
};

class heatmap_renderer : public base_thread
{
public:
	heatmap_renderer(unsigned int thisPID, unsigned int thisTID)
		:base_thread(thisPID, thisTID) {};

	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	void setUpdateDelay(int delay) { updateDelayMS = delay; }

private:
	void main_loop();
	int updateDelayMS = 200;
	plotted_graph *thisgraph;
	bool render_graph_heatmap(plotted_graph *graph, bool verbose = false);
	vector<COLSTRUCT> colourRange;

};
