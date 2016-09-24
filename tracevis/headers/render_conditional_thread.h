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
Header for the thread that renders graph conditional data
*/
#pragma once
#include <stdafx.h>
#include "GUIStructs.h"
#include "traceStructs.h"
#include "thread_graph_data.h"

class conditional_renderer
{
public:
	static void __stdcall ThreadEntry(void* pUserData);
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	void setUpdateDelay(int delay) { updateDelayMS = delay; }
	bool die = false;

private:
	int updateDelayMS = 200;
	void conditional_thread();
	bool render_graph_conditional(thread_graph_data *graph);

	float invisibleCol[4];
	float failOnlyCol[4];
	float succeedOnlyCol[4];
	float bothPathsCol[4];
};
