#pragma once 
#include <stdafx.h>
#include <GUIStructs.h>


#ifdef WIN32
bool fileExists(string path)
{
	wstring wstrpath(path.begin(), path.end());
	return PathFileExists(wstrpath.c_str());
}

//gets path rgat executable is located in
string getModulePath()
{
	CHAR buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

//returns path for saving files, tries to create if it doesn't exist
bool getSavePath(VISSTATE * clientState, string *result, int PID)
{
	stringstream savedir;
	savedir << clientState->config->saveDir;

	//if directory doesn't exist, create
	if (!fileExists(savedir.str().c_str()))
		if (!CreateDirectoryA(savedir.str().c_str(),NULL))
			return false;

	string filename = clientState->glob_piddata_map[PID]->modpaths[0];

	//http://stackoverflow.com/a/8520815
	const size_t last_slash_idx = filename.find_last_of("\\/");
	if (std::string::npos != last_slash_idx)
	{
		filename.erase(0, last_slash_idx + 1);
	}

	stringstream timestring;
	timestring << 222;

	stringstream savepath;
	savepath << savedir.str() << "\\" << filename << timestring.str() << ".rgat";
	*result = savepath.str();
	return true;
}

//get execution string of dr executable + client dll
bool get_dr_path(VISSTATE *clientState, string *path)
{
	string DRPath = clientState->config->DRDir;
#ifdef X86_32
	DRPath.append("bin32\\drrun.exe");
#elif X86_64
	DRPath.append("bin64\\drrun.exe");
#endif
	if (!fileExists(DRPath.c_str()))
	{
		printf("ERROR: Unable to find Dynamorio executable at %s\n", DRPath.c_str());
		return false;
	}

	string DRGATpath = clientState->config->clientPath + "drgat.dll";
	if (!fileExists(DRGATpath.c_str()))
	{
		printf("Unable to find drgat.dll at %s\n", DRGATpath.c_str());
		return false;
	}

	string drrunArgs = " -c ";
	string retstring = DRPath;
	if (clientState->launchopts.pause)
		retstring.append(" -msgbox_mask 15 ");

	retstring.append(drrunArgs);
	retstring.append(DRGATpath);
	*path = retstring;
	return true;
}

string get_options(VISSTATE *clientState)
{
	stringstream optstring;
	if (clientState->launchopts.caffine)
		optstring << " -caffine";

	if (clientState->launchopts.pause)
		optstring << " -sleep";

	return optstring.str();
}

void execute_tracer(string executable, VISSTATE *clientState) 
{
	if (executable.empty()) return;

	string runpath;
	if (!get_dr_path(clientState, &runpath)) return;
	runpath.append(get_options(clientState));
	runpath = runpath + " -- \"" + executable + "\"";

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	printf("Starting execution using command line [%s]\n", runpath.c_str());
	CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}
#endif // WIN32