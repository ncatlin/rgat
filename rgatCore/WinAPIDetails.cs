using System.Collections.Generic;

namespace rgatCore
{
    public class WinAPIDetails
    {
        public enum APIModule { Advapi32, Crypt32, DHCPcsvc, DnsAPI, Kernel32, MSVCRT, NTDLL, UCRT, UrlMon, WS32, Wininet, WinHTTP, Other }

        //these two data structures are probably better off loaded from disk or a resource, so leaving them in an amenable format
        static Dictionary<string, APIModule> _configuredModules = new Dictionary<string, APIModule>()
        {
            { "advapi32.dll" , APIModule.Advapi32 },
            { "crypt32.dll" , APIModule.Crypt32 },
            { "dhcpcsvc.dll" , APIModule.DHCPcsvc },
            { "dnsapi.dll" , APIModule.DnsAPI },
            { "kernel32.dll" , APIModule.Kernel32 },
            { "msvcrt.dll" , APIModule.MSVCRT },
            { "ntdll.dll" , APIModule.NTDLL },
            { "ucrtbase.dll" , APIModule.UCRT },
            { "ucrtbased.dll" , APIModule.UCRT },
            { "urlmon.dll" , APIModule.UrlMon },
            { "winhttp.dll" , APIModule.WinHTTP },
            { "wininet.dll" , APIModule.Wininet },
            { "ws2_32.dll" , APIModule.WS32 }
        };


        static Dictionary<APIModule, Dictionary<string, Logging.LogFilterType>> _configuredSymbols = new Dictionary<APIModule, Dictionary<string, Logging.LogFilterType>>()
        {
            {
                APIModule.Advapi32,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.Crypt32,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.DHCPcsvc,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.DnsAPI,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.Kernel32,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "CloseHandle", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryA", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryW", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryExA", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryExW", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryTransactedA", Logging.LogFilterType.APIFile},
                    { "CreateDirectoryTransactedW", Logging.LogFilterType.APIFile},
                    { "CreateFileA", Logging.LogFilterType.APIFile},
                    { "CreateFileW", Logging.LogFilterType.APIFile},
                    { "CreateFile2", Logging.LogFilterType.APIFile},
                    { "CreateProcessA", Logging.LogFilterType.APIProcess},
                    { "CreateProcessW", Logging.LogFilterType.APIProcess},
                    { "CreateThread", Logging.LogFilterType.APIFile},
                    { "ExitProcess", Logging.LogFilterType.APIProcess},
                    { "ExitThread", Logging.LogFilterType.APIProcess},
                    { "FindFirstFileA", Logging.LogFilterType.APIFile},
                    { "FindFirstFileExA", Logging.LogFilterType.APIFile},
                    { "FindFirstFileW", Logging.LogFilterType.APIFile},
                    { "FindFirstFileExW", Logging.LogFilterType.APIFile},
                    { "DeleteFileA", Logging.LogFilterType.APIFile},
                    { "DeleteFileW", Logging.LogFilterType.APIFile},
                    { "GetModuleHandleA", Logging.LogFilterType.APIProcess},
                    { "GetModuleHandleW", Logging.LogFilterType.APIProcess},
                    { "GetTempPathA", Logging.LogFilterType.APIFile},
                    { "GetTempPathW", Logging.LogFilterType.APIFile},
                    { "GetTempFileNameA", Logging.LogFilterType.APIFile},
                    { "GetTempFileNameW", Logging.LogFilterType.APIFile},
                    { "OpenProcess", Logging.LogFilterType.APIProcess},
                    { "OpenThread", Logging.LogFilterType.APIProcess},
                    { "ReadFile", Logging.LogFilterType.APIFile},
                    { "ReadProcessMemory", Logging.LogFilterType.APIProcess},
                    { "RegCreateKeyExA", Logging.LogFilterType.APIReg},
                    { "RegCreateKeyExW", Logging.LogFilterType.APIReg},
                    { "RegDeleteKeyExA", Logging.LogFilterType.APIReg},
                    { "RegDeleteKeyExW", Logging.LogFilterType.APIReg},
                    { "RegDeleteValueA", Logging.LogFilterType.APIReg},
                    { "RegDeleteValueW", Logging.LogFilterType.APIReg},
                    { "ResumeThread", Logging.LogFilterType.APIProcess},
                    { "WriteFile", Logging.LogFilterType.APIFile},
                    { "WriteProcessMemory", Logging.LogFilterType.APIProcess}
                }
            },
            {
                APIModule.MSVCRT,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.NTDLL,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.UCRT,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.UrlMon,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.WinHTTP,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.Wininet,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },
            {
                APIModule.WS32,
                new Dictionary<string, Logging.LogFilterType>() {
                    { "a_shaupdate", Logging.LogFilterType.APIAlgos}
                }
            },

        };

        public static APIModule ResolveModuleEnum(string path)
        {
            string fname = System.IO.Path.GetFileName(path).ToLower();
            if (_configuredModules.TryGetValue(fname, out APIModule moduleEnum))
                return moduleEnum;
            return APIModule.Other;
        }

        public static Logging.LogFilterType ResolveAPI(APIModule modenum, string symbolname)
        {
            if (_configuredSymbols[modenum].TryGetValue(symbolname, out Logging.LogFilterType filterType)) return filterType;

            //some libraries are specific enough that pretty much all of the offerings fall in a single category
            switch (modenum)
            {
                case APIModule.Crypt32:
                case APIModule.UCRT: //not really worth recording most of these (tan, ceil, isdigit, etc)
                    return Logging.LogFilterType.APIAlgos;

                case APIModule.DHCPcsvc:
                case APIModule.DnsAPI:
                case APIModule.WinHTTP:
                case APIModule.Wininet:
                case APIModule.WS32:
                    return Logging.LogFilterType.APINetwork;

                case APIModule.Advapi32:
                case APIModule.NTDLL:
                case APIModule.MSVCRT:
                    return Logging.LogFilterType.APIOther;

                default:
                    return Logging.LogFilterType.APIOther;
            }


        }
    }
}