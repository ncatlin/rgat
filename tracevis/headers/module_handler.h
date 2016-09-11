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
	bool die = false;
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	wstring pipename;

private:
	void PID_thread();
};