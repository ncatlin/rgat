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

void PROCESS_DATA::getExternCallerReadLock()
{
#ifdef XP_COMPATIBLE
	obtainMutex(externCallerMutex, 6366);
#else
	AcquireSRWLockShared(&externCallerRWLock);
#endif
}

void PROCESS_DATA::getExternCallerWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(externCallerMutex, 1602);
#else
	AcquireSRWLockExclusive(&externCallerRWLock);
#endif
}

void PROCESS_DATA::dropExternCallerReadLock()
{
#ifdef XP_COMPATIBLE
	dropMutex(externCallerMutex);
#else
	ReleaseSRWLockShared(&externCallerRWLock);
#endif
}

void PROCESS_DATA::dropExternCallerWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(externCallerMutex);
#else
	ReleaseSRWLockExclusive(&externCallerRWLock);
#endif
}

bool PROCESS_DATA::get_sym(unsigned int modNum, MEM_ADDRESS addr, string *sym)
{
	bool found;
	getDisassemblyWriteLock();
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
	dropDisassemblyWriteLock();

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

bool PROCESS_DATA::get_extern_at_address(MEM_ADDRESS address, BB_DATA **BB, int attempts) {

	getExternlistReadLock();
	map<MEM_ADDRESS, BB_DATA*>::iterator externIt = externdict.find(address);
	while (externIt == externdict.end())
	{
		if (!attempts--) {
			dropExternlistReadLock();
			return false;
		}
		dropExternlistReadLock();
		Sleep(1);
		getExternlistReadLock();
		externIt = externdict.find(address);
	}

	if (BB)
		*BB = externIt->second;
	dropExternlistReadLock();
	return true;
}