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
