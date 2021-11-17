#include "moduleload_windows.h"
#include "yekneb_string.h"

//pin client lock is held
VOID moduleLoad(IMG img, VOID * threadData_TLSKEY)
{
	UINT32 imageID = IMG_Id(img);

	if (imageID >= loadedModulesInfo.size())
		loadedModulesInfo.resize(imageID + 20);
	
	//TODO - check how this works on unicode files. the ones we have stored from rgat are multibyte
	//edit - i give up on unicode for now. disregard the above.
	std::string path = IMG_Name(img); 
	
	std::transform(path.begin(), path.end(), path.begin(), std::tolower);

	
	bool isInstrumented = IMG_IsMainExecutable(img) ? true : module_should_be_instrumented(path);

	moduleData *thisModule = new moduleData; 
	thisModule->start = IMG_LowAddress(img);
	thisModule->end = IMG_HighAddress(img);
	thisModule->instrumented = isInstrumented;
	thisModule->name = path;
	thisModule->ID = (INT32)imageID;
	loadedModulesInfo[imageID] = thisModule;

	writeEventPipe("mn@%s@%d@" PTR_prefix "@" PTR_prefix "@%d@", path.c_str(), imageID, thisModule->start, thisModule->end, isInstrumented);

	//std::cerr << "Module loaded: " << path << " ID: " << imageID << std::hex << " addrs: " << IMG_LowAddress(img) << "-" << IMG_HighAddress(img) << std::endl;

	/*
	if ((path.find("ucrtbase.dll") != std::string::npos)
		|| (path.find("ucrtbased.dll") != std::string::npos))
	{
		wrapUCRTbaseFuncs(img);
		std::cout << "wrapping ucrtbase funcs" << std::endl;
	}
	*/

	
	if (path.find("\\kernel32.dll") != std::string::npos)
	{
		writeEventPipe("!wrapping kern32");

		wrapKernel32Funcs(img, (UINT32)threadData_TLSKEY);
	}
	else if (path.find("\\advapi32.dll") != std::string::npos)
	{
		wrapAdvapi32Funcs(img, (UINT32)threadData_TLSKEY);
	}
	else if (path.find("\\user32.dll") != std::string::npos)
	{
		wrapUser32Funcs(img, (UINT32)threadData_TLSKEY);
	}
	
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		std::string symname = SYM_Name(sym); //sym_name memory seems to become invalid in this call on x86-32
		writeEventPipe("s!@%d@" PTR_prefix "@%s@", imageID, SYM_Value(sym), symname.c_str());
	}
}
