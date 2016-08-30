#include "stdafx.h"
#include "basicblock_handler.h"
#include "traceConstants.h"
#include "traceMisc.h"
#include "traceStructs.h"

#pragma comment(lib, "legacy_stdio_definitions.lib") //capstone uses _sprintf
#pragma comment(lib, "capstone.lib")

size_t disassemble_ins(csh hCapstone, string opcodes, INS_DATA *insdata, long insaddr)
{
	cs_insn *insn;
	unsigned int pairs = 0;
	unsigned char opcodes_u[MAX_OPCODES];
	while (pairs * 2 < opcodes.length()) {
		if (!caught_stoi(opcodes.substr(pairs * 2, 2), (int *)(opcodes_u + pairs), 16))
		{
			printf("BADOPCODE! %s\n", opcodes.c_str());
			continue;
		}
		pairs++;
		if (pairs >= MAX_OPCODES)
		{
			printf("Error, instruction too long!");
			return NULL;
		}
	}

	size_t count;
	count = cs_disasm(hCapstone, opcodes_u, pairs, insaddr, 0, &insn);
	if (count != 1) {
		printf("\tFATAL: Failed disassembly for opcodes: %s\n count: %d\n",  
			opcodes.c_str(), count);  //TODO: THIS HAS HAPPENED, DEAL WITH IT
		return NULL;
	}
	int ida = insn->id;

	string mnemonic = string(insn->mnemonic);
	insdata->mnemonic = mnemonic;

	if (mnemonic == "call")
		insdata->itype = OPCALL;
	else if (mnemonic == "ret") //todo: iret
		insdata->itype = OPRET;
	else if (mnemonic == "jmp")
		insdata->itype = OPJMP;
	else
	{
		insdata->itype = OPUNDEF;

		if (mnemonic[0] == 'j') //should probably check for non-conditionaljump 'j' instructions
			insdata->conditional = true;
	}

	//if we do want to make save files more concise, save the opcodes and reconstruct
	//instead of dumping everything else to disk
	//insdata->serialize_opstr = string(opcodes);
	insdata->op_str = string(insn->op_str);
	insdata->ins_text = string(insdata->mnemonic + " " + insdata->op_str);
	insdata->numbytes = (int)floor(opcodes.length() / 2);
	insdata->address = insaddr;
	cs_free(insn, count);

	//printf("Dissasembled 0x%lx to %s\n", insaddr, insdata->op_str.c_str());
	return count;
}

void __stdcall basicblock_handler::ThreadEntry(void* pUserData) {
	return ((basicblock_handler*)pUserData)->PID_BB_thread();
}

//listen to BB data for given PID
void basicblock_handler::PID_BB_thread()
{
	wstring pipename(L"\\\\.\\pipe\\rioThreadBB");
	pipename.append(std::to_wstring(PID));

	const wchar_t* szName = pipename.c_str();
	wprintf(L"[vis bb thread] creating bb pipe %s\n", szName);

	HANDLE hPipe = CreateNamedPipe(szName,
		PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_READMODE_MESSAGE,
		255, 64, 56 * 1024, 300, NULL);

	if ((int)hPipe == -1)
	{
		printf("Error: BBTHREAD Handle:%d - error:%d\n", (int)hPipe, GetLastError());
		return;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)
	{
		printf("Couldn't open capstone instance\n");
		return;
	}

	std::map<long, string> oldstuf;

	ConnectNamedPipe(hPipe, NULL);
	char buf[4048] = { 0 };
	int PIDcount = 0;
	printf("[vis bb thread] pipe connected, waiting for input...\n");
	while (true)
	{
		DWORD bread = 0;
		if (!ReadFile(hPipe, buf, BBBUFSIZE, &bread, NULL)) {
			printf("\tERROR: Failed basic block pipe read for PID %d!\n",PID);
			return;
		}

		string savedbuf = string(buf);
		//printf("read buffer [%s]\n", buf);

		if (bread >= BBBUFSIZE)
		{
			printf("\tERROR: BB Buf Exceeded!\n");
			return;
		}
		buf[bread] = 0;

		if (!bread)
		{
			int err = GetLastError();
			if (err != ERROR_BROKEN_PIPE)
				printf("BBPIPE ERROR: %d\n", err);
			printf("%s", "\t!----------BBPIPE BROKEN  - no more data------------\n");
			return;
		}

		if (buf[0] == 'B')
		{
			size_t count;
			char *next_token = buf + 1;
			size_t i = 0;

			char *start_s = strtok_s(next_token, "@", &next_token); //start addr
			unsigned long targetaddr;
			if (!caught_stol(string(start_s), &targetaddr, 16)) {
				printf("bbaddr STOL ERROR: %s\n", start_s);
				continue;
			}
			bool clash = false;

			char *modnum_s = strtok_s(next_token, "@", &next_token);
			int modnum;
			if (!caught_stoi(string(modnum_s), &modnum, 10)) {
				printf("bb modnum STOL ERROR: %s\n", modnum_s);
				continue;
			}
			char *tid_s = strtok_s(next_token, "@", &next_token);
			int tid;
			if (!caught_stoi(string(tid_s), &tid, 10)) {
				printf("bb modnum STOL ERROR: %s\n", modnum_s);
				continue;
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
				
			//todo: externs still need this for callargs
			if (!instrumented)
			{
			BB_DATA *bbdata = new BB_DATA;
			bbdata->modnum = modnum;
			bbdata->symbol.clear();
			//bbdata->address = 
			piddata->externdict.insert(make_pair(targetaddr, bbdata));
			//i don't know why this sometimes happens. please tell me
			if (piddata->externdict[targetaddr] == 0)
				piddata->externdict[targetaddr] = bbdata;

			//printf("Inserting extern at address %lx -> %lx\n", targetaddr, piddata->externdict[targetaddr]);
			continue;
			}

			while (true)
			{
				bool mutation = false;
				string opcodes(strtok_s(next_token, "@", &next_token));

				obtainMutex(piddata->disassemblyMutex, "DisassemblyStart", 4000);
				if (piddata->disassembly.count(targetaddr))
				{
					//ignore if address has been seen and opcodes are most recent
					INS_DATA *insd = piddata->disassembly[targetaddr].back();
					if (insd->opcodes == opcodes)
					{
						dropMutex(piddata->disassemblyMutex, "Inserted Dis");
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

				count = disassemble_ins(hCapstone, opcodes, insdata, targetaddr);
				if (!count) {
					printf("BAD DISASSEMBLE for bb [%s]\n",savedbuf.c_str());
					return;
				}

				piddata->disassembly[targetaddr].push_back(insdata);
				dropMutex(piddata->disassemblyMutex, "Inserted Dis");

				targetaddr += insdata->numbytes;
				if (next_token >= buf + bread) break;
				i++;
			}
			continue;
		}

		printf("UNKNOWN BB ENTRY: %s\n", buf);

	}

	cs_close(&hCapstone);
}
