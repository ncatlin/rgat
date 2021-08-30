
#include <string>
#include <sstream>
#include "windows_include.h"

std::string ErrorCodeToString(WINDOWS::DWORD result)
{
	switch (result)
	{
	case ERROR_SUCCESS: return "SUCCESS";
	case ERROR_FILE_NOT_FOUND: return "FILE_NOT_FOUND";
	case ERROR_PATH_NOT_FOUND: return "PATH_NOT_FOUND";
	case ERROR_ACCESS_DENIED: return "ACCESS_DENIED";
	case ERROR_INVALID_HANDLE: return "INVALID_HANDLE";
	case ERROR_SHARING_VIOLATION: return "SHARING_VIOLATION";
	case ERROR_FILE_EXISTS: return "FILE_EXISTS";
	case ERROR_INVALID_PARAMETER: return "INVALID_PARAMETER";
	case ERROR_BROKEN_PIPE: return "BROKEN_PIPE";
	case ERROR_VIRUS_DELETED: return "VIRUS_DELETED";
	case ERROR_BAD_PIPE: return "BAD_PIPE";
	case ERROR_PIPE_BUSY: return "PIPE_BUSY";
	case ERROR_NO_DATA: return "NO_DATA";
	case ERROR_PIPE_NOT_CONNECTED: return "NOT_CONNECTED";
	case WAIT_TIMEOUT: return "WAIT_TIMEOUT";
	case ERROR_DIRECTORY: return "ERROR_DIRECTORY";
	default:
		std::ostringstream os;
	    os << std::hex << result;
		return os.str();
	}
}



std::string HKEY_to_string(WINDOWS::HKEY hkey)
{
	using namespace WINDOWS;
	switch ((DWORD)hkey)
	{
	case HKEY_CLASSES_ROOT:		return "HKEY_CLASSES_ROOT";
	case HKEY_CURRENT_CONFIG:	return "HKEY_CURRENT_CONFIG";
	case HKEY_CURRENT_USER:		return "HKEY_CURRENT_USER";
	case HKEY_CURRENT_USER_LOCAL_SETTINGS:	return "HKEY_CURRENT_USER_LOCAL_SETTINGS";
	case HKEY_DYN_DATA:			return "HKEY_DYN_DATA";
	case HKEY_LOCAL_MACHINE:	return "HKEY_LOCAL_MACHINE";
	case HKEY_PERFORMANCE_DATA:	return "HKEY_PERFORMANCE_DATA";
	case HKEY_PERFORMANCE_NLSTEXT:	return "HKEY_PERFORMANCE_NLSTEXT";
	case HKEY_USERS:	return "HKEY_USERS";
	default:
		return "";
	}
}

	
