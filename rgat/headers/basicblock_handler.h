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
#include "base_thread.h"

size_t disassemble_ins(csh hCapstone, string opcodes, INS_DATA *insdata, MEM_ADDRESS insaddr);

class basicblock_handler : public base_thread
{
public:
	basicblock_handler(binaryTarget *binaryptr, traceRecord* runRecordptr, wstring pipeid)
		: base_thread() {
		binary = binaryptr;  runRecord = runRecordptr;
		int bitwidth = binary->getBitWidth();
		assert(bitwidth);
		disassemblyBitwidth = (bitwidth == 32) ? CS_MODE_32 : CS_MODE_64;

		pipename = wstring(L"\\\\.\\pipe\\");// rioThreadBB");



		pipename += pipeid;
	};

	wstring pipename;

private:
	binaryTarget *binary;
	traceRecord* runRecord;
	cs_mode disassemblyBitwidth;
	void main_loop();
};
