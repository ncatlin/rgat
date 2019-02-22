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

bool gat_basicblock_handler::connectPipe()
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
		return false;
	}

	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	if (ConnectNamedPipe(inputPipe, &ov))
	{
		wcerr << "[rgat]Failed to ConnectNamedPipe to " << pipename << " for PID " << runRecord->getPID() << ". Error: " << GetLastError();
		alive = false;
		return false;
	}

	while (!die)
	{
		int result = WaitForSingleObject(ov.hEvent, 3000);
		if (result != WAIT_TIMEOUT) break;
		cerr << "[rgat]WARNING:Long wait for basic block handler pipe" << endl;
	}

	return true;
}

bool gat_basicblock_handler::readDataFromWindowsPipe(vector<uint8_t> &buf, DWORD &bytesRead, bool &pending, OVERLAPPED &ov2)
{
	ReadFile(inputPipe, &buf.at(0), BBBUFSIZE, &bytesRead, &ov2);
	while (!die)
	{
		if (WaitForSingleObject(ov2.hEvent, 300) != WAIT_TIMEOUT) break;
		if (!runRecord->isRunning() || runRecord->should_die()) break;
	}

	DWORD lastError = GetLastError();
	if (lastError && lastError != ERROR_IO_PENDING) { 
		pending = true;
		return true; 
	}

	int res2 = GetOverlappedResult(inputPipe, &ov2, &bytesRead, false);
	buf[bytesRead] = 0;
	pending = false;

	if (bytesRead > 0)
	{
		return true;
	}
	else
	{
		int err = GetLastError();
		if (err == ERROR_BROKEN_PIPE)
			return false;
		else
			std::cerr << "[rgat]Basic block pipe read for PID " << runRecord->getPID() << " failed, error: " << dec << err << " ";

		switch (err)
		{
		case ERROR_IO_INCOMPLETE:
			cout << " (IO INCOMPLETE)";
			break;
		default:
			break;
		}

		return false;
	}
}

//listen to BB data for given PID
void gat_basicblock_handler::main_loop()
{
	alive = true;
	if (!inputPipe) //if using pin the connection was established earlier
	{
		bool pipeConnected = connectPipe();
		if (!pipeConnected || die) return;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, disassemblyBitwidth, &hCapstone) != CS_ERR_OK)
	{
		std::cerr << "[rgat]ERROR: BB thread Couldn't open capstone instance for PID " << runRecord->getPID() << endl;
		alive = false;
		return;
	}

	vector<uint8_t> buf;
	buf.resize(BBBUFSIZE, 0);

	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!ov2.hEvent)
	{
		std::cerr << "RGAT: ERROR - Failed to create overlapped event in basic block handler" << endl;
		assert(false);
	}

	const int pointerSize = (binary->getBitWidth() == 64) ? 8 : 4;
	bool pending = false;

	//string savedbuf;
	PROCESS_DATA *piddata = runRecord->get_piddata();
	while (!die && !runRecord->should_die())
	{
		DWORD bytesRead = 0;
		if (!readDataFromWindowsPipe(buf, bytesRead, pending, ov2))
			break;
		if (pending)
			continue;

		if (bytesRead >= BBBUFSIZE || GetLastError() == ERROR_MORE_DATA)
		{
			std::cerr << "[rgat]ERROR: BB Buf exceeded after read from pipe!" << endl;
			break;
		}
		
		if (!bytesRead)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				std::cerr << "[rgat]ERROR: Non-pending BBPIPE error: "<< err << endl;
			break;
		}

		buf[bytesRead] = 0;
		int bufPos = 0;
		if (buf[bufPos++] == 'B')
		{
			MEM_ADDRESS targetaddr = 0;			
			UINT32 localmodnum = 0;
			long globalModNum;

			memcpy(&targetaddr, &buf.at(bufPos), pointerSize);			
			bufPos += pointerSize;
			assert(buf.at(bufPos) == '@');			
			bufPos++;
			memcpy(&localmodnum, &buf.at(bufPos), sizeof(UINT32));
			bufPos += sizeof(UINT32);
			assert(buf.at(bufPos) == '@');
			bufPos++;

			globalModNum = runRecord->modIDTranslationVec.at(localmodnum);
			MEM_ADDRESS modulestart = runRecord->get_piddata()->modBounds.at(globalModNum)->first;
//			ADDRESS_OFFSET modoffset = targetaddr - modulestart;

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

			if (!instrumented) //should no longer happen
			{
				cerr << "[rgat] Error: Uninstrumented code has been... instrumented?" << endl;
				assert(false);
			}

			INSLIST *blockInstructions = new INSLIST;
			MEM_ADDRESS insaddr = targetaddr;
			
			while (buf.at(bufPos++) == '@')
			{
				char insByteCount = buf.at(bufPos++);
				assert(insByteCount < 16);

				INS_DATA *instruction = NULL;

				WriteLock disasWriteLock(piddata->disassemblyRWLock);
				map<MEM_ADDRESS, INSLIST>::iterator addressDissasembly = piddata->disassembly.find(insaddr);
				if (addressDissasembly != piddata->disassembly.end())
				{
					instruction = addressDissasembly->second.back();
					//if address has been seen but opcodes are not same as most recent, disassemble again
					//might be a better to check all mutations instead of most recent

					bool differentInstruction = ((instruction->numbytes != insByteCount) || 
													memcmp(instruction->opcodes.get(), &buf.at(bufPos), insByteCount));
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
					instruction->numbytes = insByteCount;

					//uint8_t *opcodePtr = &buf.at(bufPos);

					instruction->opcodes = std::unique_ptr<uint8_t[]>(new uint8_t[insByteCount]);
					memcpy(instruction->opcodes.get(), &buf.at(bufPos), insByteCount);

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

				disasWriteLock.unlock();

				insaddr += instruction->numbytes;
				bufPos += instruction->numbytes;
			}

			WriteLock disasWriteLock(piddata->disassemblyRWLock);
			//piddata->addressBlockMap[targetaddr][blockID] = blockInstructions;
			
			if (blockID == piddata->numBlocksSeen())
			{
				BLOCK_DESCRIPTOR *bd = new BLOCK_DESCRIPTOR;
				bd->inslist = blockInstructions;
				piddata->addBlock_HaveLock(targetaddr, bd);
			}
			else
				cout << "other size" << endl;
			disasWriteLock.unlock();

			continue;
		}

		cerr << "[rgat]UNKNOWN BB ENTRY: ";
		for (auto i = buf.begin(); i != buf.end(); ++i)
			std::cerr << *i;
		cerr << endl;

	}

	cs_close(&hCapstone);
	closePipe();
	alive = false;
}
