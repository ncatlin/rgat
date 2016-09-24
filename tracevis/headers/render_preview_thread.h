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
Header for the thread that renders previews for each graph
*/
#pragma once
#include <stdafx.h>
#include "traceStructs.h"
#include "GUIStructs.h"

class preview_renderer
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	bool die = false;

private:
	void rendering_thread();

};
