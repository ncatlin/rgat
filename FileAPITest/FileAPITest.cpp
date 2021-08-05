// FileAPITest.cpp : This opens, writes to and reads a temporary file a few times.
// The file path/handles should be shown and linked on the analysis chart
//


#include <filesystem>
#include <Windows.h>

int main()
{
    TCHAR lpTempPathBuffer[MAX_PATH];
    TCHAR szTempFileName[MAX_PATH];
    DWORD count;
    DWORD dwRetVal = GetTempPath(MAX_PATH, lpTempPathBuffer);

    //  Generates a temporary file name. 
    UINT uRetVal = GetTempFileName(lpTempPathBuffer, TEXT("rgatTestFile"), 0, szTempFileName);

    //create + write    
    bool resultbool = false;
    HANDLE  hFile = CreateFileW(szTempFileName,   GENERIC_WRITE, 0, NULL,  OPEN_EXISTING ,  FILE_ATTRIBUTE_NORMAL, NULL);
    printf("CreateW err: %d, Handle: 0x%lx\n", GetLastError(), (unsigned long)hFile);

    resultbool = WriteFile(hFile, "testdata", 8, &count, NULL);
    printf("Write result: %d\n", resultbool);
    CloseHandle(hFile);

    //open + read wide
    hFile = CreateFileW(szTempFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("CreateW err: %d, handle: 0x%lx\n", GetLastError(), (unsigned long)hFile);
    char testdata2[5];
    resultbool = ReadFile(hFile, testdata2, 4, &count, NULL);
    printf("ReadFile result1: %d\n", resultbool);
    testdata2[4] = 0;
    CloseHandle(hFile);    
    
    //open + read ascii
    char mbspath[sizeof(szTempFileName)*2];
    size_t conv;
    wcstombs_s(&conv, mbspath, szTempFileName, sizeof(szTempFileName) * 2);
    hFile = CreateFileA(mbspath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
    printf("CreateA err: %d, Handle:0x%lx\n", GetLastError(), (unsigned long)hFile);
    resultbool = ReadFile(hFile, testdata2, 4, &count, NULL);
    printf("ReadFile result1: %d\n", resultbool);
    testdata2[4] = 0;
    CloseHandle(hFile);

    printf("Read %d bytes: %s\n", count, testdata2);
    DeleteFile(szTempFileName);
}
