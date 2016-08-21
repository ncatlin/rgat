#include "stdafx.h"
#include "traceMisc.h"

INS_DATA* getDisassembly(unsigned long address, HANDLE mutex, map<unsigned long,vector<INS_DATA *>> *disas)
{
	obtainMutex(mutex, 0, 4000);
	if (!disas->count(address))
	{
		dropMutex(mutex, 0);
		int waitTime = 150;
		while (true)
		{
			Sleep(waitTime);
			obtainMutex(mutex, 0, 4000);
			if (disas->count(address))
				break;
			dropMutex(mutex, 0);
			waitTime += 100;
		}
	}
	INS_DATA *result = disas->at(address).back();
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
		if (errorLocation)
			printf("WARNING! Mutex %x wait expired at %s ERROR!\n", mutex, errorLocation);
		return false;
	}
	//if (errorLocation) 	
	//	printf("Successfully obtained mutex %x -> %s...\n", mutex, errorLocation);
	return true;
}

void dropMutex(HANDLE mutex, char *location) {
	//if (location) 
	//	printf("Dropping mutex %x -> %s\n", mutex, location);
	ReleaseMutex(mutex);
}