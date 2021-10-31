#include "wrap_kernel32.h"
#include <iostream>
#include "threadObject.h"
#include "modules.h"
#include "windows_include.h"


VOID wraphead_CloseHandle(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD handle)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, handle);
	fflush(threaddata->threadpipeFILE);
}


VOID wraphead_ReadFile(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD handleArg, DWORD bytesInArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, handleArg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%ld\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, bytesInArg);
	fflush(threaddata->threadpipeFILE);
#ifdef BREAK_LOOP_ON_BLOCK
	printTagCache(thread);
#endif
}


WINDOWS::HANDLE replacement_CreateFileW(
	LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
	WINDOWS::LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	WINDOWS::HANDLE hTemplateFile)
{
	WINDOWS::HANDLE retval;
	
	PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
		PIN_PARG(WINDOWS::HANDLE), &retval,
		PIN_PARG(WINDOWS::LPCWSTR), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(WINDOWS::HANDLE), hTemplateFile,
		PIN_PARG_END());


	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID != -1)
	{
		char argbuf[PATH_MAX];
		wcstombs(argbuf, lpFileName, PATH_MAX);
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);
		fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,0x%lx\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, retval);
		fflush(threaddata->threadpipeFILE);
	}
	return retval;
}


WINDOWS::HANDLE replacement_CreateFileA(
	 LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
	WINDOWS::LPCTSTR  lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	WINDOWS::HANDLE hTemplateFile)
{
	WINDOWS::HANDLE retval;
	PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
		PIN_PARG(WINDOWS::HANDLE), &retval,
		PIN_PARG(WINDOWS::LPCTSTR), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(WINDOWS::HANDLE), hTemplateFile,
		PIN_PARG_END());

	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID != -1)
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, lpFileName);
		fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,0x%lx\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, retval);
		fflush(threaddata->threadpipeFILE);
	}
	return retval;
}

/// <summary>
/// Send the return value of the wrapped function
/// </summary>
/// <param name="threadid">PIN THREADID reference</param>
/// <param name="tlskey">tls key of the thread data</param>
/// <param name="return_value">Return value to send, with 0x hex prefix</param>
VOID wraptail_dword_return(LEVEL_VM::THREADID threadid, UINT32 tlskey, DWORD return_value)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,0x%lx\x01", (void*)0, (void*)threaddata->lastBlock->blockID, return_value);
	fflush(threaddata->threadpipeFILE);
}


VOID wraphead_GetStdHandle(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD arg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	switch (arg)
	{
	case STD_INPUT_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,STDIN\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	case STD_OUTPUT_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,STDOUT\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	case STD_ERROR_HANDLE:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,STDERR\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		break;
	default:
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,INVALID(%d)\x01", 0, (void*)funcaddr, threaddata->lastBlock->blockID, arg);
		break;
	}
	fflush(threaddata->threadpipeFILE);
}


VOID wraphead_LoadlibraryW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const wchar_t* modulewstring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	char argbuf[PATH_MAX];
	wcstombs(argbuf, modulewstring, PATH_MAX);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);
	fflush(threaddata->threadpipeFILE);
}



VOID wraphead_LoadlibraryA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const char* modulestring)
{
	writeEventPipe("!in LoadLibraryA: %s\n", modulestring);
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, modulestring);
	fflush(threaddata->threadpipeFILE);
}


VOID wraphead_GetModuleHandleA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const char* modulestring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	if (modulestring == NULL)
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, "NULL");
	}
	else 
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, modulestring);
	}
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_GetModuleHandleW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const wchar_t* modulewstring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	if (modulewstring == NULL)
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, "NULL");
	}
	else
	{
		char argbuf[PATH_MAX];
		wcstombs(argbuf, modulewstring, PATH_MAX);
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);
	}
	fflush(threaddata->threadpipeFILE);
}




VOID wraphead_GetProcAddress(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, char* procstring)
{

	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	if ((unsigned long)procstring < 0xffff)
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%d\x01", 1, funcaddr, threaddata->lastBlock->blockID, (int)procstring);
	}
	else
	{
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 1, funcaddr, threaddata->lastBlock->blockID, procstring);
	}
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_Sleep(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD msarg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%d\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, msarg);
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

VOID wraphead_VirtualProtect(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%x:%s\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualProtectEx(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%x:%s\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualAlloc(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD sizearg, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%d bytes\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sizearg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%x:%s\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_VirtualAllocEx(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD sizearg, DWORD newprotectArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%d bytes\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sizearg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%x:%s\x01", 4, (void*)funcaddr, (void*)threaddata->lastBlock->blockID,
		newprotectArg, protectionToString(newprotectArg));
	fflush(threaddata->threadpipeFILE);
}



VOID wraphead_WriteFile(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, DWORD handleArg, DWORD bytesOutArg)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, handleArg);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%ld\x01", 2, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, bytesOutArg);
	fflush(threaddata->threadpipeFILE);
}

void wrapKernel32Funcs(IMG img, UINT32 TLS_KEY)
{
	RTN rtn = RTN_FindByName(img, "CloseHandle");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_CloseHandle,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "GetProcAddress");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetProcAddress,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "GetModuleHandleA");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetModuleHandleA,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "GetModuleHandleW");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetModuleHandleW,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "LoadLibraryA");
	if (RTN_Valid(rtn))
	{
		writeEventPipe("!wrapping LoadLibraryA");

		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_LoadlibraryA,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "LoadLibraryW");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_LoadlibraryW,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}



	rtn = RTN_FindByName(img, "GetStdHandle");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_GetStdHandle,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "ReadFile");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_ReadFile,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "WriteFile");
	if (RTN_Valid(rtn))
	{

		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_WriteFile,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		//RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)test1, IARG_THREAD_ID, IARG_UINT32, TLS_KEY, 13357, IARG_END);// IARG_INST_PTR,  IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(rtn);
	}


	rtn = RTN_FindByName(img, "CreateFileA");
	if (RTN_Valid(rtn))
	{

		PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL,
			"CreateFileA",
			PIN_PARG(WINDOWS::LPCTSTR),
			PIN_PARG(DWORD),
			PIN_PARG(DWORD),
			PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
			PIN_PARG(DWORD),
			PIN_PARG(DWORD),
			PIN_PARG(WINDOWS::HANDLE),
			PIN_PARG_END());

		RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_CreateFileA,
			IARG_PROTOTYPE, proto,
			IARG_CONTEXT,
			IARG_THREAD_ID,
			IARG_UINT32, TLS_KEY,
			IARG_ORIG_FUNCPTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
			IARG_END);


		PROTO_Free(proto);
	}

	rtn = RTN_FindByName(img, "CreateFileW");
	if (RTN_Valid(rtn))
	{
		PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL,
			"CreateFileW",
			PIN_PARG(WINDOWS::LPCTSTR),
			PIN_PARG(DWORD),
			PIN_PARG(DWORD),
			PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
			PIN_PARG(DWORD),
			PIN_PARG(DWORD),
			PIN_PARG(WINDOWS::HANDLE),
			PIN_PARG_END());

		RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_CreateFileW,
			IARG_PROTOTYPE, proto,
			IARG_CONTEXT,
			IARG_THREAD_ID,
			IARG_UINT32, TLS_KEY,
			IARG_ORIG_FUNCPTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
			IARG_END);

		PROTO_Free(proto);

	}



	rtn = RTN_FindByName(img, "Sleep");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_Sleep,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualProtect");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualProtect,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualProtectEx");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualProtectEx,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "VirtualAlloc");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_VirtualAlloc,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
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
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);

		RTN_Close(rtn);
	}

}