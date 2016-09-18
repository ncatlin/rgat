#pragma once
#include <stdafx.h>
#include "traceStructs.h"
#include "GUIStructs.h"

class maingraph_render_thread
{
public:
	static void __stdcall ThreadEntry(void* pUserData);
	maingraph_render_thread();
	~maingraph_render_thread();
	bool die = false;
	void rendering_thread();
	VISSTATE *clientState;

private:
	void updateMainRender();
	void performMainGraphRendering(thread_graph_data *graph);
};

