#pragma once
#include <stdafx.h>
#include "GUIStructs.h"
#include "traceStructs.h"
#include "thread_graph_data.h"

class conditional_renderer
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	bool sizeChanged;
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;

protected:
	unsigned int delme = -1;

private:
	void conditional_thread();
	bool render_graph_conditional (thread_graph_data *graph);

};
