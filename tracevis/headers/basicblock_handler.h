#pragma once
#include "traceStructs.h"
#include "GUIStructs.h"

size_t disassemble_ins(csh hCapstone, string opcodes, INS_DATA *insdata, long insaddr);

class basicblock_handler
{
public:
	//thread_start_data startData;
	static void __stdcall ThreadEntry(void* pUserData);
	int PID;
	PROCESS_DATA *piddata = 0;
	VISSTATE *clientState;
	bool die = false;
	wstring pipename;

private:
	void PID_BB_thread();

};
