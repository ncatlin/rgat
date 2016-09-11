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

private:
	void rendering_thread();

};
