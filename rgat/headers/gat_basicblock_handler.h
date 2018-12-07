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

class gat_basicblock_handler : public base_thread
{
public:
	gat_basicblock_handler(binaryTarget *binaryptr, traceRecord* runRecordptr, wstring pipeid, HANDLE bbpipe)
		: base_thread() {
		binary = binaryptr;  runRecord = runRecordptr;
		int bitwidth = binary->getBitWidth();
		assert(bitwidth);
		disassemblyBitwidth = (bitwidth == 32) ? CS_MODE_32 : CS_MODE_64;


		if (bbpipe)
		{
			inputPipe = bbpipe;
		}
		else
		{
			pipename = wstring(L"\\\\.\\pipe\\");
			pipename += pipeid;
		}

	};

	wstring pipename;

private:
	void main_loop();
	bool connectPipe();

	binaryTarget *binary;
	traceRecord* runRecord;
	cs_mode disassemblyBitwidth;
	HANDLE inputPipe = NULL;
};
