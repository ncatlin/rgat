#include "wrap_user32.h"
#include <iostream>
#include "threadObject.h"
#include "modules.h"
#include "windows_include.h"



VOID wraphead_FindWindowA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const char* lpClassName, const char* lpWindowName)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	std::string classarg = lpClassName ? std::string(lpClassName) : "NULL";
	std::string windowarg = lpWindowName ? std::string(lpWindowName) : "NULL";

	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, classarg.c_str());
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, windowarg.c_str());

	fflush(threaddata->threadpipeFILE);
}

VOID wraphead_FindWindowW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, const wchar_t* lpClassName, const wchar_t* lpWindowName)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;

	char argbuf[PATH_MAX];

	std::wstring classarg = lpClassName ? std::wstring(lpClassName) : L"NULL";
	wcstombs(argbuf, classarg.c_str(), PATH_MAX);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);

	std::wstring windowarg = lpWindowName ? std::wstring(lpWindowName) : L"NULL";
	wcstombs(argbuf, windowarg.c_str(), PATH_MAX);
	fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, argbuf);

	fflush(threaddata->threadpipeFILE);
}


void wrapUser32Funcs(IMG img, int TLS_KEY)
{

	RTN rtn = RTN_FindByName(img, "FindWindowA");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_FindWindowA,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);

		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, "FindWindowW");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_FindWindowW,
			IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);

		RTN_Close(rtn);
	}
}
