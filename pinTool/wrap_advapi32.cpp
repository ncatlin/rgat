#include "wrap_kernel32.h"
#include <iostream>
#include "threadObject.h"
#include "modules.h"
#include "windows_include.h"
#include "winapi_wrap_utils.h"
#include "utilities.h"



	VOID wraphead_RegCloseKey(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, WINDOWS::HKEY hKey)
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;
		fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);
		fflush(threaddata->threadpipeFILE);
	}


	WINDOWS::LSTATUS replacement_RegCreateKeyExA(
		LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
		WINDOWS::HKEY  hKey,
		WINDOWS::LPCSTR lpSubKey,
		WINDOWS::DWORD Reserved,
		WINDOWS::LPSTR lpClass,
		WINDOWS::DWORD dwOptions,
		WINDOWS::REGSAM samDesired,
		const WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		WINDOWS::PHKEY phkResult,
		WINDOWS::LPDWORD lpdwDisposition)
	{

		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));

		if (threaddata->lastBlock->blockID != -1)
		{
			std::string key = HKEY_to_string(hKey);

			if (!key.empty())
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);
			
			if (lpSubKey != 0)
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, lpSubKey);
			}
			else
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
			}
		}

		WINDOWS::LSTATUS retval;
		PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
			PIN_PARG(WINDOWS::LSTATUS), &retval,
			PIN_PARG(WINDOWS::HKEY), hKey,
			PIN_PARG(WINDOWS::LPCTSTR), lpSubKey,
			PIN_PARG(WINDOWS::DWORD), Reserved,
			PIN_PARG(WINDOWS::LPWSTR), lpClass,
			PIN_PARG(WINDOWS::DWORD), dwOptions,
			PIN_PARG(WINDOWS::REGSAM), samDesired,
			PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
			PIN_PARG(WINDOWS::PHKEY), phkResult,
			PIN_PARG(WINDOWS::LPDWORD), lpdwDisposition,
			PIN_PARG_END());

		if (threaddata->lastBlock->blockID != -1)
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 7, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, *phkResult);
			fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,%s\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, ErrorCodeToString(retval).c_str());
			fflush(threaddata->threadpipeFILE);
		}
		return retval;
	}
		
	
	
	WINDOWS::LSTATUS replacement_RegCreateKeyExW(
		LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
		WINDOWS::HKEY  hKey,
		WINDOWS::LPCWSTR lpSubKey,
		WINDOWS::DWORD Reserved,
		WINDOWS::LPWSTR lpClass,
		WINDOWS::DWORD dwOptions,
		WINDOWS::REGSAM samDesired,
		const WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		WINDOWS::PHKEY phkResult,
		WINDOWS::LPDWORD lpdwDisposition)
	{

		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));

		if (threaddata->lastBlock->blockID != -1)
		{
			std::string key = HKEY_to_string(hKey);

			if (!key.empty())
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);
			
			if (lpSubKey != 0)
			{
				char keypath[PATH_MAX];
				wcstombs(keypath, lpSubKey, PATH_MAX);
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, keypath);
			}
			else
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
			}
		}

		WINDOWS::LSTATUS retval;
		PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
			PIN_PARG(WINDOWS::LSTATUS), &retval,
			PIN_PARG(WINDOWS::HKEY), hKey,
			PIN_PARG(WINDOWS::LPCTSTR), lpSubKey,
			PIN_PARG(WINDOWS::DWORD), Reserved,
			PIN_PARG(WINDOWS::LPWSTR), lpClass,
			PIN_PARG(WINDOWS::DWORD), dwOptions,
			PIN_PARG(WINDOWS::REGSAM), samDesired,
			PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
			PIN_PARG(WINDOWS::PHKEY), phkResult,
			PIN_PARG(WINDOWS::LPDWORD), lpdwDisposition,
			PIN_PARG_END());

		if (threaddata->lastBlock->blockID != -1)
		{
			if (retval == ERROR_SUCCESS) {
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 7, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, *phkResult);
			}
			fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,%s\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, ErrorCodeToString(retval).c_str());
			fflush(threaddata->threadpipeFILE);
		}
		return retval;
	}


	WINDOWS::LSTATUS replacement_RegOpenKeyExA(
		LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
		WINDOWS::HKEY  hKey,
		WINDOWS::LPCSTR lpSubKey,
		WINDOWS::DWORD ulOptions,
		WINDOWS::REGSAM samDesired,
		WINDOWS::PHKEY phkResult)
	{

		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));

		if (threaddata->lastBlock->blockID != -1)
		{
			std::string key = HKEY_to_string(hKey);

			if (!key.empty())
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

			if (lpSubKey != 0)
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,%s\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, lpSubKey);
			}
			else
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
			}
		}

		WINDOWS::LSTATUS retval;
		PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
			PIN_PARG(WINDOWS::LSTATUS), &retval,
			PIN_PARG(WINDOWS::HKEY), hKey,
			PIN_PARG(WINDOWS::LPCSTR), lpSubKey,
			PIN_PARG(WINDOWS::DWORD), ulOptions,
			PIN_PARG(WINDOWS::REGSAM), samDesired,
			PIN_PARG(WINDOWS::PHKEY), phkResult,
			PIN_PARG_END());

		if (threaddata->lastBlock->blockID != -1)
		{
			if (retval == ERROR_SUCCESS) {
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 4, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, *phkResult);
			}
			fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,%s\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, ErrorCodeToString(retval).c_str());
			fflush(threaddata->threadpipeFILE);
		}
		return retval;
	}



	WINDOWS::LSTATUS replacement_RegOpenKeyExW(
		LEVEL_PINCLIENT::CONTEXT* ctx, THREADID threadid, UINT32 tlskey, AFUNPTR funcaddr,
		WINDOWS::HKEY  hKey,
		WINDOWS::LPCWSTR lpSubKey,
		WINDOWS::DWORD ulOptions,
		WINDOWS::REGSAM samDesired,
		WINDOWS::PHKEY phkResult)
	{

		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));

		if (threaddata->lastBlock->blockID != -1)
		{
			std::string key = HKEY_to_string(hKey);

			if (!key.empty())
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

			if (lpSubKey != 0)
			{
				char keypath[PATH_MAX];
				wcstombs(keypath, lpSubKey, PATH_MAX);
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, keypath);
			}
			else
			{
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
			}
		}

		WINDOWS::LSTATUS retval;
		PIN_CallApplicationFunction(ctx, threadid, CALLINGSTD_STDCALL, funcaddr, NULL,
			PIN_PARG(WINDOWS::LSTATUS), &retval,
			PIN_PARG(WINDOWS::HKEY), hKey,
			PIN_PARG(WINDOWS::LPCWSTR), lpSubKey,
			PIN_PARG(WINDOWS::DWORD), ulOptions,
			PIN_PARG(WINDOWS::REGSAM), samDesired,
			PIN_PARG(WINDOWS::PHKEY), phkResult,
			PIN_PARG_END());

		if (threaddata->lastBlock->blockID != -1)
		{
			if (retval == ERROR_SUCCESS) {
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 4, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, *phkResult);
			}
			fprintf(threaddata->threadpipeFILE, RETVAL_MARKER"," PTR_prefix ",%lx,%s\x01", (void*)funcaddr, (void*)threaddata->lastBlock->blockID, ErrorCodeToString(retval).c_str());
			fflush(threaddata->threadpipeFILE);
		}
		return retval;
	}





	VOID wraphead_RegQueryValueA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, WINDOWS::HKEY hKey, WINDOWS::LPCSTR lpSubKey )
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;

		std::string key = HKEY_to_string(hKey);

		if (!key.empty())
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
		else
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

		if (lpSubKey != 0)
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s'\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, lpSubKey);
		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		fflush(threaddata->threadpipeFILE);
	}


	VOID wraphead_RegQueryValueW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, WINDOWS::HKEY hKey, WINDOWS::LPCWSTR lpSubKey)
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;

		std::string key = HKEY_to_string(hKey);

		if (!key.empty())
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
		else
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

		if (lpSubKey != 0)
		{
			char keypath[PATH_MAX];
			wcstombs(keypath, lpSubKey, PATH_MAX);
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s'\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, keypath);
		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		fflush(threaddata->threadpipeFILE);
	}




	VOID wraphead_RegSetValueA(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, WINDOWS::HKEY hKey, WINDOWS::LPCSTR lpSubKey, WINDOWS::LPCSTR lpData)
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;

		std::string key = HKEY_to_string(hKey);

		if (!key.empty())
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
		else
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

		if (lpSubKey != 0)
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, lpSubKey);
		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		if (lpData != 0)
		{

			char sample[32];
			int i;
			for (i = 0; i < 31; i++)
			{
				sample[i] = lpData[i];
				if (sample[i] == 0) break;
			}
			sample[31] = 0;
			if (i  < 31)
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s'\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sample);
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s...'\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, sample);

		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,NULL\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		fflush(threaddata->threadpipeFILE);
	}



	VOID wraphead_RegSetValueW(LEVEL_VM::THREADID threadid, UINT32 tlskey, ADDRINT funcaddr, WINDOWS::HKEY hKey, WINDOWS::LPCWSTR lpSubKey, WINDOWS::LPCWSTR lpData)
	{
		threadObject* threaddata = static_cast<threadObject*>(PIN_GetThreadData(tlskey, threadid));
		if (threaddata->lastBlock->blockID == -1) return;

		std::string key = HKEY_to_string(hKey);

		if (!key.empty())
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, key.c_str());
		else
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,0x%lx\x01", 0, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, hKey);

		if (lpSubKey != 0)
		{
			char keypath[PATH_MAX];
			wcstombs(keypath, lpSubKey, PATH_MAX);
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,'%s'\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, keypath);
		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,M,NULL\x01", 1, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		if (lpData != 0)
		{

			wchar_t sample[32];
			int i;
			for (i = 0; i < 31; i++)
			{
				sample[i] = lpData[i];
				if (sample[i] == 0) break;
			}
			sample[31] = 0;

			char samplec[64];
			wcstombs(samplec, sample, PATH_MAX);
			if (i < 31)
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s'\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, samplec);
			else
				fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,'%s...'\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID, samplec);

		}
		else
		{
			fprintf(threaddata->threadpipeFILE, ARG_MARKER",%d," PTR_prefix ",%lx,E,NULL\x01", 3, (void*)funcaddr, (void*)threaddata->lastBlock->blockID);
		}

		fflush(threaddata->threadpipeFILE);
	}



	void wrapAdvapi32Funcs(IMG img, UINT32 TLS_KEY)
	{

		RTN rtn = RTN_FindByName(img, "RegCloseKey");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegCloseKey,
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);

			RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, "RegCreateKeyExA");
		if (RTN_Valid(rtn))
		{

			PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL,	"RegCreateKeyExA",
				PIN_PARG(WINDOWS::HKEY),
				PIN_PARG(WINDOWS::LPCSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::LPSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::REGSAM),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(WINDOWS::PHKEY),
				PIN_PARG(WINDOWS::LPDWORD),
				PIN_PARG_END());

			RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_RegCreateKeyExA,
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
				IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
				IARG_END);


			PROTO_Free(proto);
		}
				
		
		rtn = RTN_FindByName(img, "RegCreateKeyExW");
		if (RTN_Valid(rtn))
		{

			PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL,	"RegCreateKeyExW",
				PIN_PARG(WINDOWS::HKEY),
				PIN_PARG(WINDOWS::LPCWSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::LPWSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::REGSAM),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(WINDOWS::PHKEY),
				PIN_PARG(WINDOWS::LPDWORD),
				PIN_PARG_END());

			RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_RegCreateKeyExW,
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
				IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
				IARG_END);


			PROTO_Free(proto);
		}

		rtn = RTN_FindByName(img, "RegDeleteKeyA");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegQueryValueA,//we handle both query and delete by reading the first 2 identical args
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, "RegDeleteKeyW");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegQueryValueW, //we handle both query and delete by reading the first 2 identical args
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			RTN_Close(rtn);
		}



		rtn = RTN_FindByName(img, "RegOpenKeyExA");
		if (RTN_Valid(rtn))
		{

			PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL,	"RegOpenKeyExA",
				PIN_PARG(WINDOWS::HKEY),
				PIN_PARG(WINDOWS::LPCSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::REGSAM),
				PIN_PARG(WINDOWS::PHKEY),
				PIN_PARG_END());

			RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_RegOpenKeyExA,
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
				IARG_END);


			PROTO_Free(proto);
		}		
		
		rtn = RTN_FindByName(img, "RegOpenKeyExW");
		if (RTN_Valid(rtn))
		{

			PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::HANDLE), CALLINGSTD_STDCALL, "RegOpenKeyExW",
				PIN_PARG(WINDOWS::HKEY),
				PIN_PARG(WINDOWS::LPCWSTR),
				PIN_PARG(WINDOWS::DWORD),
				PIN_PARG(WINDOWS::REGSAM),
				PIN_PARG(WINDOWS::PHKEY),
				PIN_PARG_END());

			RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_RegOpenKeyExW,
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
				IARG_END);


			PROTO_Free(proto);
		}

		rtn = RTN_FindByName(img, "RegQueryValueA");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegQueryValueA,
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, "RegQueryValueW");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegQueryValueW,
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, "RegSetValueA");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegSetValueA,
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_END);

			RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, "RegSetValueW");
		if (RTN_Valid(rtn))
		{
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)wraphead_RegSetValueW,
				IARG_THREAD_ID, IARG_UINT32, TLS_KEY, IARG_INST_PTR,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_END);

			RTN_Close(rtn);
		}


	}
