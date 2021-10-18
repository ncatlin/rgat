// RegistryAPITest.cpp : This opens, writes to and reads a registry key
// The key path/handles should be shown and linked on the analysis chart
//


#include <filesystem>
#include <Windows.h>
#include <cstdio>

int main()
{
    DWORD dwDisposition; //It verify new key is created or open existing key
    HKEY  hKey;
    DWORD Ret;
    Ret =
        RegCreateKeyEx(
            HKEY_CURRENT_USER,
            L"SOFTWARE\\rgatTest\\DeleteMe",
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hKey,
            &dwDisposition);
    if (Ret != ERROR_SUCCESS)
    {
        printf("Error opening or creating new key\n");
        return FALSE;
    }

    RegCloseKey(hKey); //close the key


    Ret = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rgatTest\\DeleteMe", 0, KEY_ALL_ACCESS , &hKey);
    if (Ret != ERROR_SUCCESS)
    {
        printf("Error opening or creating existing key\n");
        return FALSE;
    }

    Ret = RegSetValueA(hKey, "DeleteMeVal", REG_SZ, "This should be deleted", NULL);
    if (Ret != ERROR_SUCCESS)
    {
        printf("Error setting value\n");
        return FALSE;
    }

    wchar_t out[400];
    long bufsz = 400;
    Ret = RegQueryValue(hKey, L"DeleteMeVal", out, &bufsz);
    if (Ret != ERROR_SUCCESS)
    {
        printf("Error getting value:  %d\n", Ret);
        return FALSE;
    }

    printf("Got value %S\n", out);
    RegCloseKey(hKey); //close the key

    Ret = RegDeleteKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\rgatTest\\DeleteMe\\DeleteMeVal");
    Ret = RegDeleteKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\rgatTest\\DeleteMe");
    Ret = RegDeleteKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\rgatTest");


    return TRUE;
}
