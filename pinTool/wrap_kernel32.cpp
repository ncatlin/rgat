#include "wrap_kernel32.h"
#include <iostream>
#include "threadObject.h"
#include "modules.h"

VOID wraphead_WriteFile(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD bytesOutArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%ld\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, bytesOutArg);
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_ReadFile(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD bytesInArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%ld\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, bytesInArg);
	fflush(threaddata->threadpipeFILE);
#ifdef BREAK_LOOP_ON_BLOCK
	printTagCache(thread);
#endif
}

VOID wraphead_GetStdHandle(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD arg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	switch (arg)
	{
	case STD_INPUT_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,STDIN\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	case STD_OUTPUT_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,STDOUT\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		printf("WritingD: A,%d,%lx,%lx,E,STDOUT\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	case STD_ERROR_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,STDERR\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	default:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,INVALID(%d)\x01", 0, (void*)funcaddr, threaddata->lastBlock->blockID, arg);
		break;
	}
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_GetModuleHandleA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, char * modulestring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, modulestring);
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_GetModuleHandleW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, const wchar_t *modulewstring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	
	char argbuf[PATH_MAX];
	wcstombs(argbuf, modulewstring, PATH_MAX);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_LoadlibraryW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, const wchar_t *modulewstring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	char argbuf[PATH_MAX];
	wcstombs(argbuf, modulewstring, PATH_MAX);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_LoadlibraryA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, const char *modulestring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, modulestring);
	fflush(threaddata->threadpipeFILE);
}


VOID wraphead_GetProcAddress(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, char * procstring)
{

	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	if ((unsigned long)procstring < 0xffff)
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%d\x01", 1, funcaddr, threaddata->lastBlock->blockID, (int)procstring);
	}
	else
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%s\x01", 1, funcaddr, threaddata->lastBlock->blockID, procstring);
	}
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_Sleep(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD msarg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%d\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, msarg);
	fflush(threaddata->threadpipeFILE);

	//todo
	//if (traceClientptr->hidetime)
	//	drwrap_set_arg(wrapcxt, 0, 0);
#ifdef BREAK_LOOP_ON_BLOCK
	else if (timeout > 1000)
		printTagCache(thread);
#endif
}

static char* protectionToString(DWORD protect)
{
	switch (protect)
	{
	case PAGE_EXECUTE: return "--X";
	case PAGE_EXECUTE_READ: return "R-X";
	case PAGE_EXECUTE_READWRITE: return "RWX";
	case PAGE_EXECUTE_WRITECOPY: return "-WXcp";
	case PAGE_NOACCESS: return "NO ACCESS";
	case PAGE_READONLY: return "R--";
	case PAGE_READWRITE: return "RW-";
	case PAGE_WRITECOPY: return "-W-cp";
	case 0x40000000: return "TARG INVAL_NOUPDATE";
	default:
		return "";
	}
}

VOID wraphead_VirtualProtect(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%x:%s\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, 
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualProtectEx(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%x:%s\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualAlloc(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD sizearg, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,M,%d bytes\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sizearg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%x:%s\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualAllocEx(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, ADDRINT returnaddr, DWORD sizearg, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,M,%d bytes\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sizearg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d,%lx,%lx,E,%x:%s\x01", 4, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, 
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}


void wrapKernel32Funcs(IMG img, UINT32 TLS_KEY)
{
	RTN rtn = RTN_FindByName(img, "GetProcAddress");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetProcAddress,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "GetModuleHandleA");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetModuleHandleA,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "GetModuleHandleW");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetModuleHandleW,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "LoadLibraryA");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_LoadlibraryA,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "LoadLibraryW");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_LoadlibraryW,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}
	
		

	rtn = RTN_FindByName(img, "GetStdHandle");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetStdHandle,
			IARG_THREAD_ID,	IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "ReadFile");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_ReadFile,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "WriteFile");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_WriteFile,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "Sleep");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_Sleep,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualProtect");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualProtect,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualProtectEx");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualProtectEx,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualAlloc");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualAlloc,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualAllocEx");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualAllocEx,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, IARG_RETURN_IP,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);

		RTN_Close(rtn);
	}

}