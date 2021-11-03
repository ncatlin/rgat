#pragma once
#include "modules.h"
#include "utilities.h"
#include "yekneb_string.h"
#include <iostream>

static NATIVE_FD commandPipe, eventPipe;
//multibyte
std::vector<std::string> TraceChoiceDirectoryList;
//multibyte
std::vector<std::string> TraceChoiceFileList;
bool DefaultIgnoreMode;

void setCommandPipe(NATIVE_FD newpipe)
{
	commandPipe = newpipe;
}

void setEventPipe(NATIVE_FD newpipe)
{
	eventPipe = newpipe;
}



OS_RETURN_CODE readCommandPipe(VOID *resultbuf, USIZE *ptrsize)
{
	OS_RETURN_CODE retval = OS_ReadFD(commandPipe, ptrsize, resultbuf);
	if (!OS_RETURN_CODE_IS_SUCCESS(retval))
	{
		std::cerr << "[pingat]Error " << retval.generic_err << "," << std::hex << retval.os_specific_err << " readControlPipe" << std::endl;
		if (retval.generic_err == OS_RETURN_CODE_FILE_READ_FAILED) {
			if (retval.os_specific_err = 0xC0000008)
			{
				std::cerr << "\t modulepipe was invalid" << std::endl;
				PIN_ExitApplication(-1);
			}
		}
	}
	return retval;
}


#define MAXMODMSGSIZE 4096
//write to the module_handler_thead
bool writeEventPipe(char *logText, ...)
{
	char str[MAXMODMSGSIZE];
	USIZE total = 0;
	va_list args;

	va_start(args, logText);
	total += vsnprintf(str, MAXMODMSGSIZE, logText, args);
	va_end(args);
	ASSERT(total, str);
	str[total] = 0;
	ASSERT(total < MAXMODMSGSIZE, "MAXMODMSGSIZE too small");

	OS_FlushFD(eventPipe);
	OS_RETURN_CODE osretcd = OS_WriteFD(eventPipe, str, &total);
	if (osretcd.generic_err != OS_RETURN_CODE_NO_ERROR)
	{
		printf("[pingat]Failed to write msg %s to control pipe ", str);

		if (osretcd.os_specific_err == 0xC00000B0 || 
			osretcd.os_specific_err == 0xC00000B1 ||
			osretcd.os_specific_err == 0xC000014B) //pipe disconnected/closing/broken
		{
			printf("because pipe closed. Did RGAT terminate?\n");
			PIN_ExitProcess(-1);
		}
		else
		{
			printf("\n\twrite_sync_mod OS_WriteFD error generic: %d, os: %lx\n", osretcd.generic_err, osretcd.os_specific_err);
		}
		return false;
	}

	OS_FlushFD(eventPipe);
	return true;
}


bool module_should_be_instrumented(std::string path)
{

	if (DefaultIgnoreMode)
	{
		//check if module in whitelisted directory or is whitelisted
		for each (std::string includedDir in TraceChoiceDirectoryList)
		{
			if (includedDir.size() > path.size()) continue;
			if (path.compare(0, includedDir.size(), includedDir) >= 0)
			{
				return true;
			}
		}
		for each (std::string includedFile in TraceChoiceFileList)
		{
			if (includedFile.size() > path.size()) continue;
			if (path.compare(0, includedFile.size(), includedFile) == 0)
			{
				return true;
			}
		}
		return false;
	}
	else
	{
		//Default include mode - instrument all except for ignored
		for each (std::string ignoredDir in TraceChoiceDirectoryList)
		{
			if (ignoredDir.size() > ignoredDir.size()) continue;
			if (path.compare(0, ignoredDir.size(), ignoredDir) >= 0)
			{
				return false;
			}
		}
		for each (std::string ignoredFile in TraceChoiceFileList)
		{
			if (ignoredFile.size() != path.size()) continue;
			if (path.compare(0, ignoredFile.size(), ignoredFile) >= 0)
				{
					return false;
				}
		}
		return true;
	}
}

void getModuleIncludeLists()
{

	const int maxEntrySize = 50*1024; 	//maximum linux path 4096 * 2bytes + meta + leeway

	char *recvBuf = (char *)malloc(maxEntrySize);
	if (!recvBuf) {
		wprintf(L"X1\n");
		std::wstring message = L"Failed to allocate a buffer for include lists, terminating process.";
		writeEventPipe("!getModuleIncludeLists(): %s", message.c_str());
		DeclareTerribleEventAndExit(message);
		return;
	}

	bool more = true;
	while (more)
	{
		USIZE dataRead = maxEntrySize;

		OS_RETURN_CODE result = readCommandPipe(recvBuf, &dataRead);
		if (result.generic_err != OS_RETURN_CODE_NO_ERROR)
		{
			std::wstringstream err;
			err << "[pingat]Got error reading modules list " << std::hex << result.os_specific_err << "/" << dataRead << " bytes list data";
			writeEventPipe("!%s", err.str());
			DeclareTerribleEventAndExit(err.str());
			return;
		}

		//Read the mode in use for DLLs (default ignore/default instrument)
		if (dataRead >= 4 && recvBuf[0] == '@' && recvBuf[3] == '@')
		{
			wchar_t mode = recvBuf[1];
			switch (mode)
			{
			case 'T':
				DefaultIgnoreMode = true;
				break;
			case 'I':
				DefaultIgnoreMode = false;
				break;
			case 'X':
				more = false;
				break;
			default:
				std::cout << "[pingat]Bad trace choice mode setting: " << mode << std::endl;
				more = false;
				break;
			}
		}
		else
		{
			std::cout << "[idx] == " << recvBuf[0] << std::endl;
			std::cout << "[idx+1] == " << recvBuf[1] << std::endl;
			std::cout << "[idx+2] == " << recvBuf[2] << std::endl;
			std::cout << "[idx+3] == " << recvBuf[3] << std::endl;
			std::cout << "[idx+4] == " << recvBuf[4] << std::endl;
			DeclareTerribleEventAndExit(L"Bad len or seperators in msg");
			return;
		}

		if (!more) break;
		const char delim[] = "@";
		char * entryDtaPtr = (char *)recvBuf;
		strtok(entryDtaPtr, delim); //skip first part which we handle manually
		char *startchar = strtok(NULL, delim);
		char* endchar = strtok(NULL, delim) - 4; //@ symbol and null;
		if (endchar <= startchar) break;

		//directory
		if (recvBuf[2] == 'D')
		{
			std::string path = b64decode(startchar, endchar - startchar);
			std::transform(path.begin(), path.end(), path.begin(), std::tolower);
#ifdef  DEBUG
			wprintf(L"Added Trace Choice Dir: %s [%s]\n", path.c_str(), DefaultIgnoreMode ? "Instrument" : "Ignore");
#endif //  DEBUG
			TraceChoiceDirectoryList.push_back(path);
			continue;
		}

		//individual module/dll
		if (recvBuf[2] == 'F')
		{
			std::string path = b64decode(startchar, endchar - startchar);
			std::transform(path.begin(), path.end(), path.begin(), std::tolower);
#ifdef  DEBUG
			wprintf(L"Added Trace Choice File: %s [%s]\n", path.c_str(), DefaultIgnoreMode ? "Instrument" : "Ignore");
#endif //  DEBUG
			TraceChoiceFileList.push_back(path);
			continue;
		}
		
		wprintf(L"[pingat]Error: bad ignore/trace list entry: %s. Data size was %d\n", recvBuf, dataRead);
		break;
	}

#ifdef DEBUG
	std::cout << "Finished reading trace ignore lists" << std::endl;
#endif

	free(recvBuf);
}


