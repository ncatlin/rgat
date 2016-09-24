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
Header for the thread that processes basic block data
*/
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
