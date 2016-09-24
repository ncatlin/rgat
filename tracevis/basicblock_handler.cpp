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

		if (insdata->mnemonic[0] == 'j')
		{
			insdata->conditional = true;
			insdata->condTakenAddress = std::stol(insdata->op_str, 0, 16);
			insdata->condDropAddress = insaddr + insdata->numbytes;
		}
	}

	cs_free(insn, count);
	return count;
}

void __stdcall basicblock_handler::ThreadEntry(void* pUserData) {
	return ((basicblock_handler*)pUserData)->PID_BB_thread();
}

//listen to BB data for given PID
void basicblock_handler::PID_BB_thread()
{
	pipename = wstring(L"\\\\.\\pipe\\rioThreadBB");
	pipename.append(std::to_wstring(PID));

	const wchar_t* szName = pipename.c_str();
	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_READMODE_MESSAGE,
		255, 64, 56 * 1024, 300, NULL);

	if ((int)hPipe == -1)
	{
		cerr << "[rgat]ERROR: BB thread CreateNamedPipe error: " << GetLastError();
		return;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)
	{
		cerr << "[rgat]ERROR: Couldn't open capstone instance" << endl;
		return;
	}

	ConnectNamedPipe(hPipe, NULL);
	char *buf= (char *)malloc(BBBUFSIZE);
	int PIDcount = 0;

	string savedbuf;
	while (true)
	{
		if (die) break;
		DWORD bread = 0;
		if (!ReadFile(hPipe, buf, BBBUFSIZE, &bread, NULL))
		{
			int err = GetLastError();
			if (err == ERROR_BROKEN_PIPE)
				break;
			else if (err == ERROR_MORE_DATA) //could just read more if this is ever a problem
				cerr << "[rgat]Error! Basic block data exceeding BBBUFSIZE!" << endl;
			else
				cerr << "[rgat]Basic block pipe read for PID "<<PID<<" failed, error:"<<err;

			break;
		}

		if (bread >= BBBUFSIZE)
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

		savedbuf = buf;
		buf[bread] = 0;
		if (buf[0] == 'B')
		{
			char *next_token = buf + 1;
			size_t i = 0;

			char *start_s = strtok_s(next_token, "@", &next_token); //start addr
			unsigned long targetaddr;
			if (!caught_stol(string(start_s), &targetaddr, 16)) {
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
			unsigned int blockID;
			if (!caught_stoi(string(blockID_s), &blockID, 16)) {
				cerr << "[rgat]bb blockID stoi error: " << blockID_s << endl;
				assert(0);
			};

			if (!instrumented)
			{
				BB_DATA *bbdata = new BB_DATA;
				bbdata->modnum = modnum;
				bbdata->symbol.clear();

				obtainMutex(piddata->externDictMutex, 1000);
				piddata->externdict.insert(make_pair(targetaddr, bbdata));
			
				if (piddata->externdict[targetaddr] == 0)
					piddata->externdict[targetaddr] = bbdata;
				dropMutex(piddata->externDictMutex);

				continue;
			}

			while (true)
			{
				bool mutation = false;
				if (next_token[0] == NULL) 
					break;
				string opcodes(strtok_s(next_token, "@", &next_token));

				obtainMutex(piddata->disassemblyMutex, 4000);
				map<unsigned long,INSLIST>::iterator addressDissasembly = piddata->disassembly.find(targetaddr);
				if (addressDissasembly != piddata->disassembly.end())
				{
					//ignore if address has been seen and opcodes are most recent
					INS_DATA *insd = addressDissasembly->second.back();
					if (insd->opcodes == opcodes)
					{
						if (std::find(insd->blockIDs.begin(), insd->blockIDs.end(), blockID) == insd->blockIDs.end())
							insd->blockIDs.push_back(blockID);
						dropMutex(piddata->disassemblyMutex);
						targetaddr += insd->numbytes;
						if (next_token >= buf + bread) break;
						i++;
						continue;
					}
					//if we get here it's a mutation of previously seen code
				}
				else
				{
					//the address has not been seen before, disassemble it from new
					INSLIST disVec;
					piddata->disassembly[targetaddr] = disVec;
				}

				INS_DATA *insdata = new INS_DATA;
				insdata->opcodes = opcodes;
				insdata->modnum = modnum;
				insdata->dataEx = dataExecution;
				insdata->blockIDs.push_back(blockID);

				if (!disassemble_ins(hCapstone, opcodes, insdata, targetaddr)) {
					cerr << "[rgat]ERROR: Bad dissasembly for buf " << savedbuf 
						<< "PID: " << PID <<". Corrupt trace?" << endl;
					assert(0);
				}

				piddata->disassembly[targetaddr].push_back(insdata);
				dropMutex(piddata->disassemblyMutex);

				targetaddr += insdata->numbytes;
				if (next_token >= buf + bread) break;
				++i;
			}
			continue;
		}

		cerr << "[rgat]UNKNOWN BB ENTRY " << buf << endl;

	}

	free(buf);
	cs_close(&hCapstone);
}
