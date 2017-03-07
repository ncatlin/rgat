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
Client state functions
*/
#include "stdafx.h"
#include "GUIStructs.h"
#include "plotted_graph.h"

void VISSTATE::set_activeGraph(void *graph)
{
	if (activeGraph)
	{
		plotted_graph *oldGraph = (plotted_graph *)activeGraph;
		oldGraph->decrease_thread_references(162);
	}
	((plotted_graph *)graph)->increase_thread_references(1120);
	activeGraph = graph;
}