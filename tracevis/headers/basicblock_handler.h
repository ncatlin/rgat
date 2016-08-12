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
	PID_DATA *piddata = 0;
	VISSTATE *clientState;

protected:
	unsigned int focusedThread = -1;

private:
	void PID_BB_thread();

};
