#include "wrap_ucrtbase.h"
#include "threadObject.h"
#include <iostream>


VOID wraphead_fopen_s(LEVEL_VM::THREADID threadid, UINT32 tlskey, void **fdPtr, char * namestring)
{
	threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
	if (threaddata->lastBlock->blockID == -1) return;
	snprintf(threaddata->tmpcharbuf, THREAD_CHARBUF_SIZE, "%s", namestring);
	threaddata->tempPtr1 = (ADDRINT)fdPtr;

}

VOID wraptail_fopen_s(LEVEL_VM::THREADID threadid, UINT32 tlskey, int errnovalue)
{
	if (errnovalue == 0)
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;
		std::cout << "fopen handle ret:" << "(" << *((ADDRINT **)threaddata->tempPtr1) << ") for file " << threaddata->tmpcharbuf << std::endl;
	}
}

void wrapUCRTbaseFuncs(IMG img, int TLS_KEY)
{
	RTN rtnfopen_s = RTN_FindByName(img, "fopen_s");
	if (RTN_Valid(rtnfopen_s))
	{
		RTN_Open(rtnfopen_s);

		// Instrument malloc() to print the input argument value and the return value.
		RTN_InsertCall(rtnfopen_s, IPOINT_BEFORE, (AFUNPTR)wraphead_fopen_s, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
		RTN_InsertCall(rtnfopen_s, IPOINT_AFTER, (AFUNPTR)wraptail_fopen_s,  IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(rtnfopen_s);
	}
}
