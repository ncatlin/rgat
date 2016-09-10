#include "stdafx.h"
#include "traceMisc.h"

//gets [mutation]'th disassembly of [address]. if absent and [fuzzy] then returns the most recent 
INS_DATA* getDisassembly(unsigned long address,int mutation, HANDLE mutex, map<unsigned long, INSLIST> *disas, bool mostRecent = false)
{
	obtainMutex(mutex, 0, 4000);
	map<unsigned long, INSLIST>::iterator disasIt = disas->find(address);


	if (disasIt == disas->end() || (!mostRecent && disasIt->second.size()-1 < mutation))
	{
		int waitTime = 150;
		while (true)
		{
			dropMutex(mutex, 0);
			Sleep(waitTime);

			obtainMutex(mutex, 0, 4000);
			disasIt = disas->find(address);
			
			if (disasIt == disas->end())
			{
				waitTime += 100;
				if (waitTime > 800)
					printf("Long wait for disassembly of %lx, mutation %d.\n", address, mutation);
				continue;
			}

			if (mostRecent)
			{
				mutation = disasIt->second.size() - 1;
				break;
			}
			else
				if (disasIt->second.size() - 1 >= mutation)
					break;
		}
	}

	INS_DATA *result = disasIt->second.at(mutation);
	dropMutex(mutex, 0);
	return result;
}

INS_DATA* getLastDisassembly(unsigned long address, HANDLE mutex, map<unsigned long, INSLIST> *disas, int *mutationIndex)
{
	obtainMutex(mutex, 0, 4000);
	map<unsigned long, INSLIST>::iterator disasIt = disas->find(address);
	if (disasIt == disas->end())
	{
		
		dropMutex(mutex, 0);
		int waitTime = 5;
		while (true)
		{
			printf("waiting %d ms for disassembly of addr 0x%lx\n", waitTime, address);
			Sleep(waitTime);
			obtainMutex(mutex, 0, 4000);
			disasIt = disas->find(address);
			if (disasIt != disas->end())
				break;
			dropMutex(mutex, 0);
			waitTime += 5;
		}
	}
	INS_DATA *result = disasIt->second.back();
	if(mutationIndex)
		*mutationIndex = disasIt->second.size()-1;
	dropMutex(mutex, 0);
	return result;
}
//takes MARKER1234 buf, marker and target int
//if MARKER matches marker, converts 1234 to integer and places
//in target
int extract_integer(char *char_buf, string marker, int *target) {
	string pipeinput(char_buf);

	if (pipeinput.substr(0, marker.length()) == marker)
	{
		std::string::size_type sz = 0;
		string x = pipeinput.substr(marker.length(), pipeinput.length());
		try {
			*target = std::stoi(x, &sz);
		}
		catch (const std::exception& ia) {
			sz = 0;
		}

		if (sz == 0)
			return 0;
		else
			return 1;
	}
	else
		return 0;

}

int caught_stoi(string s,int *result, int base) {
	try {
		*result = std::stoi(s,0,base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stoi(string s, unsigned int *result, int base) {
	try {
		*result = std::stoi(s, 0, base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stol(string s, unsigned long *result, int base) {
	try {
		*result = std::stoll(s,0,base);
	}
	catch (std::exception const & e) {

		return 0;
	}
	return 1;
}

bool obtainMutex(HANDLE mutex, char *errorLocation, int waitTime)
{
	DWORD waitresult = WaitForSingleObject(mutex, waitTime);
	if (waitresult == WAIT_TIMEOUT) {
		//assert(waitresult != WAIT_TIMEOUT);
		if (errorLocation)
			printf("WARNING! Mutex %x wait expired at %s ERROR!\n", (unsigned int)mutex, errorLocation);
		return false;
	}
	//if (errorLocation) 	
	//printf("Successfully obtained mutex %x -> %s...\n", mutex, errorLocation);
	return true;
}

void dropMutex(HANDLE mutex, char *location) {
	//if (location) 
	//printf("Dropping mutex %x -> %s\n", mutex, location);
	ReleaseMutex(mutex);
}