#include <traceStructs.h>

inline void PROCESS_DATA::getDisassemblyReadLock()
{
#ifdef XP_COMPATIBLE
	obtainMutex(disassemblyMutex, 6396);
#else
	AcquireSRWLockShared(&disassemblyRWLock);
#endif
}

inline void PROCESS_DATA::getDisassemblyWriteLock()
{
	
#ifdef XP_COMPATIBLE 
	obtainMutex(disassemblyMutex, 1002);
#else
	AcquireSRWLockExclusive(&disassemblyRWLock);
#endif
}

inline void PROCESS_DATA::dropDisassemblyReadLock()
{
#ifdef XP_COMPATIBLE
	dropMutex(disassemblyMutex);
#else
	ReleaseSRWLockShared(&disassemblyRWLock);
#endif
}

inline void PROCESS_DATA::dropDisassemblyWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(disassemblyMutex);
#else
	ReleaseSRWLockExclusive(&disassemblyRWLock);
#endif
}

void PROCESS_DATA::getDisassemblyWriteLockB() { getDisassemblyWriteLock(); };
void PROCESS_DATA::dropDisassemblyWriteLockB() { dropDisassemblyWriteLock(); };

void PROCESS_DATA::getExternlistReadLock()
{
#ifdef XP_COMPATIBLE
	obtainMutex(externDictMutex, 6396);
#else
	AcquireSRWLockShared(&externlistRWLock);
#endif
}

void PROCESS_DATA::getExternlistWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(externDictMutex, 1002);
#else
	AcquireSRWLockExclusive(&externlistRWLock);
#endif
}

void PROCESS_DATA::dropExternlistReadLock()
{
#ifdef XP_COMPATIBLE
	dropMutex(externDictMutex);
#else
	ReleaseSRWLockShared(&externlistRWLock);
#endif
}

void PROCESS_DATA::dropExternlistWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(externDictMutex);
#else
	ReleaseSRWLockExclusive(&externlistRWLock);
#endif
}

bool PROCESS_DATA::get_sym(unsigned int modNum, MEM_ADDRESS addr, string *sym)
{
	bool found;
	getDisassemblyReadLock();
	if (modsymsPlain[modNum][addr].empty())
	{
		*sym = "";
		found = false;
	}
	else
	{
		*sym = modsymsPlain[modNum][addr];
		found = true;
	}
	dropDisassemblyReadLock();

	return found;
}

bool PROCESS_DATA::get_modpath(unsigned int modNum, string *path)
{

	getDisassemblyReadLock();
	map<int, string>::iterator modPathIt = modpaths.find(modNum);
	dropDisassemblyReadLock();

	if (modPathIt == modpaths.end())
		return false;
	else
	{
		*path = modPathIt->second;
		return true;
	}
}