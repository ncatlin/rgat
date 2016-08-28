#pragma once 
#include <stdafx.h>


#ifdef WIN32
string getModulePath()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

string get_dr_path()
{
	//first try reading from config file

	//in the event of it not working, try going with an 'it just works' philosophy and check exe dir
	string moduleDir = getModulePath();
	string DRPath = moduleDir + "\\DynamoRIO\\";
	if (al_filename_exists(DRPath.c_str()))
	{
		//if 64 bit
		//if 32 bit
		DRPath.append("bin32\\drrun.exe");
		if (!al_filename_exists(DRPath.c_str()))
		{
			printf("Unable to find drrun.exe! at %s!\n", DRPath.c_str());
			return 0;
		}
	}

	string DRGATpath = moduleDir + "\\drgat\\drgat.dll";
	if (!al_filename_exists(DRGATpath.c_str()))
	{
		printf("Unable to find drgat.dll! at %s!\n", DRGATpath.c_str());
		return 0;
	}

	string drrunArgs = " -c ";
	string retstring = DRPath + drrunArgs + DRGATpath + " -- ";
	return retstring;
}

void execute_tracer(string executable) {

	string runpath = get_dr_path();
	runpath.append(executable);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	printf("Starting execution using command line [%s]\n", runpath.c_str());
	CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}
#endif // WIN32