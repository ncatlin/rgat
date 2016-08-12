#include "stdafx.h"

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
		printf("\n\nERROR! Mutex wait expired at %s ERROR!\n",errorLocation);
		return false;
	}
	return true;
}