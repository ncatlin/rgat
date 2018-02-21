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
The thread that performs high (ie:interactive) performance rendering of the selected graph
*/

#pragma once
#include <stdafx.h>
#include "traceStructs.h"
#include "rgatState.h"
#include "base_thread.h"
#include "graphplots/plotted_graph.h"

class maingraph_render_thread : public base_thread
{
public:
	maingraph_render_thread(rgatState *clientStateptr)
		:base_thread() {
		clientState = clientStateptr;
	}
	~maingraph_render_thread() { }

private:
	binaryTarget *binary = NULL;
	traceRecord* runRecord = NULL;
	rgatState *clientState = NULL;

	void main_loop();
	void update_rendering(plotted_graph *graph);
	void perform_full_render(plotted_graph *activeGraph, bool replot_existing);
};

