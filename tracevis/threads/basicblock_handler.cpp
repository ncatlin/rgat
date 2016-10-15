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
This thread reads the basic block data from drgat,
disassembles it using Capstone and makes it available to the graph renderer
*/

#include "stdafx.h"
#include "basicblock_handler.h"
#include "traceConstants.h"
#include "traceMisc.h"
#include "traceStructs.h"
#include "OSspecific.h"

#pragma comment(lib, "legacy_stdio_definitions.lib") //capstone uses _sprintf
#pragma comment(lib, "capstone.lib")

size_t disassemble_ins(csh hCapstone, string opcodes, INS_DATA *insdata, long insaddr)
{
	cs_insn *insn;
	unsigned int pairs = 0;
	unsigned char opcodes_u[MAX_OPCODES];
	while (pairs * 2 < opcodes.length()) 
	{
		if (!caught_stoi(opcodes.substr(pairs * 2, 2), (int *)(opcodes_u + pairs), 16))
		{
			cerr << "[rgat]ERROR: BADOPCODE! " << opcodes << endl;
			return NULL;
		}
		++pairs;
		if (pairs >= MAX_OPCODES)
		{
			cerr << "[rgat]ERROR: Error, instruction too long! ("<< pairs << " pairs)" << endl;
			return NULL;
		}
	}

	size_t count;
	count = cs_disasm(hCapstone, opcodes_u, pairs, insaddr, 0, &insn);
	if (count != 1) {
		cerr << "[rgat]ERROR: BB thread failed disassembly for opcodes: "<< opcodes << " count: "<< count << endl;
		return NULL;
	}

	insdata->mnemonic = string(insn->mnemonic);
	insdata->op_str   = string(insn->op_str);
	insdata->ins_text = string(insdata->mnemonic + " " + insdata->op_str);
	insdata->numbytes = (int)floor(opcodes.length() / 2);
	insdata->address  = insaddr;

	if (insdata->mnemonic == "call")
		insdata->itype = OPCALL;
	else if (insdata->mnemonic == "ret") //todo: iret
		insdata->itype = OPRET;
	else if (insdata->mnemonic == "jmp")
		insdata->itype = OPJMP;
	else
	{
		insdata->itype = OPUNDEF;
		//assume all j+ instructions asside from jmp are conditional
		if (insdata->mnemonic[0] == 'j')
		{
			insdata->conditional = true;
			insdata->condTakenAddress = std::stoul(insdata->op_str, 0, 16);
			insdata->condDropAddress = insaddr + insdata->numbytes;
		}
	}

	cs_free(insn, count);
	return count;
}

//listen to BB data for given PID
void basicblock_handler::main_loop()
{
	alive = true;
	pipename = wstring(L"\\\\.\\pipe\\rioThreadBB");
	pipename.append(std::to_wstring(PID));

	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE ,
		255, 64, 56 * 1024, 300, NULL);

	if ((int)hPipe == -1)
	{
		cerr << "[rgat]ERROR: BB thread CreateNamedPipe error: " << GetLastError() << endl;
		alive = false;
		return;
	}
	OVERLAPPED ov = { 0 };
	ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)
	{
		cerr << "[rgat]ERROR: BB thread Couldn't open capstone instance for PID " << PID << endl;
		alive = false;
		return;
	}

	if (ConnectNamedPipe(hPipe, &ov))
	{
		wcerr << "[rgat]Failed to ConnectNamedPipe to " << pipename << " for PID " << PID << ". Error: " << GetLastError();
		alive = false;
		return;
	}
	
	while (!die)
	{
		int result = WaitForSingleObject(ov.hEvent, 3000);
		if (result != WAIT_TIMEOUT) break;
		cerr << "[rgat]WARNING:Long wait for BB handler pipe" << endl;
	}
	char *buf= (char *)malloc(BBBUFSIZE);
	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	//string savedbuf;
	while (!die && !piddata->should_die())
	{
		DWORD bread = 0;
		ReadFile(hPipe, buf, BBBUFSIZE, &bread, &ov2);
		while (!die)
		{
			if (WaitForSingleObject(ov2.hEvent, 300) != WAIT_TIMEOUT) break;
		}

		if (GetLastError() != ERROR_IO_PENDING) continue;
		int res2 = GetOverlappedResult(hPipe, &ov2, &bread, false);
		buf[bread] = 0;

		if (!bread)
		{
			int err = GetLastError();
			if (err == ERROR_BROKEN_PIPE)
				break;
			else
				cerr << "[rgat]Basic block pipe read for PID "<<PID<<" failed, error:"<<err;

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
		if (buf[0] == 'B')
		{
			char *next_token = buf + 1;
			size_t i = 0;

			char *start_s = strtok_s(next_token, "@", &next_token); //start addr
			MEM_ADDRESS targetaddr;
			if (!caught_stoul(string(start_s), &targetaddr, 16)) {
				cerr << "[rgat]bb start_s stol error: " << start_s << endl;
				assert(0);
			}
			
			char *modnum_s = strtok_s(next_token, "@", &next_token);
			int modnum;
			if (!caught_stoi(string(modnum_s), &modnum, 10)) {
				cerr << "[rgat]bb modnum stoi error: " << modnum_s << endl;
				assert(0);
			}

			char *instrumented_s = strtok_s(next_token, "@", &next_token);
			bool instrumented, dataExecution = false;
			if (instrumented_s[0] == '0')
				instrumented = false;
			else {
				instrumented = true;
				if (instrumented_s[0] == '2')
					dataExecution = true;
			}
			
			char *blockID_s = strtok_s(next_token, "@", &next_token);
			BLOCK_IDENTIFIER blockID;
			if (!caught_stoul(string(blockID_s), &blockID, 16)) {
				cerr << "[rgat]bb blockID stoi error: " << blockID_s << endl;
				assert(0);
			};

			//logf << "blockaddr: " << start_s << " module : " <<modnum << " instrumented: "<<instrumented<<endl;

			if (!instrumented)
			{
				BB_DATA *bbdata = new BB_DATA;
				bbdata->modnum = modnum;

				piddata->getDisassemblyReadLock();
				if (piddata->modsymsPlain.count(modnum) && piddata->modsymsPlain.at(modnum).count(targetaddr))
					bbdata->hasSymbol = true;
				piddata->dropDisassemblyReadLock();

				piddata->getExternlistWriteLock();
				piddata->externdict.insert(make_pair(targetaddr, bbdata));
			
				if (piddata->externdict[targetaddr] == 0)
				{
					assert(0); //why would this happen? delete me if no assert here
					piddata->externdict[targetaddr] = bbdata;
				}
				piddata->dropExternlistWriteLock();
				continue;
			}

			INSLIST *blockInstructions = new INSLIST;
			MEM_ADDRESS insaddr = targetaddr;
			while (true)
			{
				if (next_token[0] == NULL) 
					break;
				INS_DATA *instruction = NULL;

				string opcodes(strtok_s(next_token, "@", &next_token));

				piddata->getDisassemblyWriteLockB();
				map<MEM_ADDRESS, INSLIST>::iterator addressDissasembly = piddata->disassembly.find(insaddr);
				if (addressDissasembly != piddata->disassembly.end())
				{
					instruction = addressDissasembly->second.back();
					//if address has been seen but opcodes are not same as most recent, disassemble again
					//might be a better to check all mutations instead of most recent
					if (instruction->opcodes != opcodes) 
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
					instruction->opcodes = opcodes;
					instruction->modnum = modnum;
					instruction->dataEx = dataExecution;
					instruction->blockIDs.push_back(make_pair(targetaddr,blockID));
					if (piddata->modsymsPlain.count(modnum) && piddata->modsymsPlain.at(modnum).count(targetaddr))
						instruction->hasSymbol = true;

					if (!disassemble_ins(hCapstone, opcodes, instruction, insaddr)) {
						cerr << "[rgat]ERROR: Bad dissasembly in PID: " << PID << ". Corrupt trace?" << endl;
						assert(0);
					}

					piddata->disassembly[insaddr].push_back(instruction);
					instruction->mutationIndex = piddata->disassembly[insaddr].size()-1;
				}
				blockInstructions->push_back(instruction);

				piddata->dropDisassemblyWriteLockB();

				insaddr += instruction->numbytes;
				if (next_token >= buf + bread) break;
				++i;
			}

			piddata->getDisassemblyWriteLockB();
			piddata->blocklist[targetaddr][blockID] = blockInstructions;
			piddata->dropDisassemblyWriteLockB();
			continue;
		}

		cerr << "[rgat]UNKNOWN BB ENTRY " << buf << endl;

	}

	free(buf);
	cs_close(&hCapstone);
	alive = false;
}
