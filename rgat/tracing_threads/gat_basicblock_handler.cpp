/*
Copyright 2016-2017 Nia Catlin

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
This thread reads the basic block data from drgat,
disassembles it using Capstone and makes it available to the graph renderer
*/

#include "stdafx.h"
#include "gat_basicblock_handler.h"
#include "traceConstants.h"
#include "traceMisc.h"
#include "traceStructs.h"
#include "OSspecific.h"

#define LARGEST_INSTRUCTION_SIZE 15

//listen to BB data for given PID
void gat_basicblock_handler::main_loop()
{
	alive = true;



	if (!inputPipe) //if using pin the connection was established earlier
	{
		pipename.append(runRecord->getModpathID());
		const wchar_t* szName = pipename.c_str();
		inputPipe = CreateNamedPipe(szName,
			PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
			255, 64, 56 * 1024, 300, NULL);

		if (inputPipe == INVALID_HANDLE_VALUE)
		{
			cerr << "[rgat]ERROR: BB thread CreateNamedPipe error: " << GetLastError() << endl;
			alive = false;
			return;
		}

		OVERLAPPED ov = { 0 };
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

		if (ConnectNamedPipe(inputPipe, &ov))
		{
			wcerr << "[rgat]Failed to ConnectNamedPipe to " << pipename << " for PID " << runRecord->getPID() << ". Error: " << GetLastError();
			alive = false;
			return;
		}

		while (!die)
		{
			int result = WaitForSingleObject(ov.hEvent, 3000);
			if (result != WAIT_TIMEOUT) break;
			cerr << "[rgat]WARNING:Long wait for basic block handler pipe" << endl;
		}
	}



	csh hCapstone;
	if (cs_open(CS_ARCH_X86, disassemblyBitwidth, &hCapstone) != CS_ERR_OK)
	{
		cerr << "[rgat]ERROR: BB thread Couldn't open capstone instance for PID " << runRecord->getPID() << endl;
		alive = false;
		return;
	}

	vector<uint8_t> buf;
	buf.resize(BBBUFSIZE, 0);

	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!ov2.hEvent)
	{
		cerr << "RGAT: ERROR - Failed to create overlapped event in basic block handler" << endl;
		assert(false);
	}

	const int pointerSize = (binary->getBitWidth() == 64) ? 8 : 4;

	//string savedbuf;
	PROCESS_DATA *piddata = runRecord->get_piddata();
	while (!die && !runRecord->should_die())
	{
		DWORD bread = 0;
		ReadFile(inputPipe, &buf.at(0), BBBUFSIZE, &bread, &ov2);
		while (!die)
		{
			if (WaitForSingleObject(ov2.hEvent, 300) != WAIT_TIMEOUT) break;
			if (!runRecord->isRunning() || runRecord->should_die()) break;
		}

		if (GetLastError() != ERROR_IO_PENDING) continue;
		int res2 = GetOverlappedResult(inputPipe, &ov2, &bread, false);
		buf[bread] = 0;

		if (!bread)
		{
			int err = GetLastError();
			if (err == ERROR_BROKEN_PIPE)
				break;
			else
				cerr << "[rgat]Basic block pipe read for PID "<< runRecord->getPID() <<" failed, error:"<<err;

			break;
		}

		if (bread >= BBBUFSIZE || GetLastError() == ERROR_MORE_DATA)
		{
			cerr << "[rgat]ERROR: BB Buf Exceeded!" << endl;
			break;
		}
		
		if (!bread)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				cerr << "[rgat]BBPIPE ERROR: "<< err << endl;
			break;
		}

		//savedbuf = buf;
		buf[bread] = 0;
		int bufPos = 0;
		if (buf[bufPos++] == 'B')
		{
			MEM_ADDRESS targetaddr = 0;			
			UINT32 localmodnum = 0;
			long globalModNum;
			uint8_t InsOpcodesBuf[15];

			memcpy(&targetaddr, &buf.at(bufPos), pointerSize);			
			bufPos += pointerSize;
			assert(buf.at(bufPos) == '@');			
			bufPos++;
			memcpy(&localmodnum, &buf.at(bufPos), sizeof(UINT32));
			bufPos += sizeof(UINT32);
			assert(buf.at(bufPos) == '@');
			bufPos++;

			globalModNum = runRecord->modIDTranslationVec.at(localmodnum);
			MEM_ADDRESS modulestart = runRecord->get_piddata()->modBounds.at(localmodnum)->first;
			ADDRESS_OFFSET modoffset = targetaddr - modulestart;

			char instrumentedStatusByte = buf[bufPos++];

			bool instrumented, dataExecution = false;
			if (instrumentedStatusByte == UNINSTRUMENTED_CODE)
				instrumented = false;
			else 
			{
				instrumented = true;
				if (instrumentedStatusByte == CODE_IN_DATA_AREA)
					dataExecution = true;
			}
			
			BLOCK_IDENTIFIER blockID;
			memcpy(&blockID, &buf.at(bufPos), sizeof(BLOCK_IDENTIFIER));
			bufPos += sizeof(BLOCK_IDENTIFIER);

			//logf << "blockaddr: " << start_s << " module : " <<modnum << " instrumented: "<<instrumented<<endl;

			if (!instrumented) //should nolonger happen
			{
				assert(false);
				ROUTINE_STRUCT *bbdata = new ROUTINE_STRUCT;
				bbdata->globalmodnum = globalModNum;

				piddata->getExternDictWriteLock();
				piddata->externdict.insert(make_pair(targetaddr, bbdata));
				piddata->dropExternDictWriteLock();

				piddata->getDisassemblyReadLock();
				if (piddata->modsymsPlain.count(globalModNum) && piddata->modsymsPlain.at(globalModNum).count(modoffset))
					bbdata->hasSymbol = true;
				piddata->dropDisassemblyReadLock();

				//if (bbdata->hasSymbol)
				//	fill_taint_data_for_symbol(bbdata);

				continue;
			}

			INSLIST *blockInstructions = new INSLIST;
			MEM_ADDRESS insaddr = targetaddr;
			
			while (true)
			{


				if (buf.at(bufPos++) != '@')
					break;
				char insByteCount = buf.at(bufPos++);
				assert(insByteCount < 16);

				INS_DATA *instruction = NULL;

				piddata->getDisassemblyWriteLock();
				map<MEM_ADDRESS, INSLIST>::iterator addressDissasembly = piddata->disassembly.find(insaddr);
				if (addressDissasembly != piddata->disassembly.end())
				{
					instruction = addressDissasembly->second.back();
					//if address has been seen but opcodes are not same as most recent, disassemble again
					//might be a better to check all mutations instead of most recent

					bool differentInstruction = ((instruction->numbytes != insByteCount) || 
													memcmp(instruction->opcodes, &buf.at(bufPos), insByteCount));
					if (differentInstruction)
						instruction = NULL;
				}
				else
				{
					//the address has not been seen before, make a new disassembly list;
					INSLIST insDisassemblyList;
					piddata->disassembly[insaddr] = insDisassemblyList;
				}
 
				if (!instruction)
				{
					instruction = new INS_DATA;
					instruction->opcodes = (uint8_t *)malloc(insByteCount);
					memcpy(instruction->opcodes, &buf.at(bufPos), insByteCount);
					instruction->numbytes = insByteCount;
					instruction->globalmodnum = globalModNum;
					instruction->dataEx = dataExecution;
					instruction->blockIDs.push_back(make_pair(targetaddr,blockID));

					if (piddata->modsymsPlain.count(globalModNum) && piddata->modsymsPlain.at(globalModNum).count(targetaddr))
						instruction->hasSymbol = true;

					if (!disassemble_ins(hCapstone, instruction, insaddr)) 
					{
						cerr << "[rgat]ERROR: Bad dissasembly in PID: " << runRecord->getPID() << ". Corrupt trace?" << endl;
						assert(0);
					}

					piddata->disassembly[insaddr].push_back(instruction);
					instruction->mutationIndex = (unsigned int)piddata->disassembly[insaddr].size()-1;
				}
				blockInstructions->push_back(instruction);

				piddata->dropDisassemblyWriteLock();

				insaddr += instruction->numbytes;
				bufPos += instruction->numbytes;
			}

			piddata->getDisassemblyWriteLock();
			piddata->addressBlockMap[targetaddr][blockID] = blockInstructions;
			if (blockID == piddata->blockList.size())
			{
				BLOCK_DESCRIPTOR *bd = new BLOCK_DESCRIPTOR;
				bd->blockType = eBlockInternal;
				bd->inslist = blockInstructions;
				piddata->blockList.push_back(make_pair(targetaddr, bd));
			}
			else
				cout << "other size" << endl;
			piddata->dropDisassemblyWriteLock();
			continue;
		}

		cerr << "[rgat]UNKNOWN BB ENTRY: ";
		for (auto i = buf.begin(); i != buf.end(); ++i)
			std::cerr << *i;
		cerr << endl;

	}

	cs_close(&hCapstone);
	CloseHandle(inputPipe);
	alive = false;
}
