#pragma once

#include "stdafx.h"
#include "GUIStructs.h"
#include "traceStructs.h"

class module_handler
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;

protected:
	unsigned int focusedThread = -1;

private:
	void PID_thread();
};