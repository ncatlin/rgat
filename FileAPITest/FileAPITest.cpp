// FileAPITest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include <filesystem>
#include <Windows.h>

int main()
{
    TCHAR lpTempPathBuffer[MAX_PATH];
    TCHAR szTempFileName[MAX_PATH];

    DWORD dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
        lpTempPathBuffer); // buffer for path 

    //  Generates a temporary file name. 
    UINT uRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
        TEXT("rgatTestFile"),     // temp file name prefix 
        0,                // create unique name 
        szTempFileName);  // buffer for name 

    //create + write    
    HANDLE  hFile = CreateFile(szTempFileName,   GENERIC_WRITE, 0, NULL,  OPEN_EXISTING ,  FILE_ATTRIBUTE_NORMAL, NULL);       

    char testdata[] = "testdata";
    DWORD written;
    WriteFile(hFile, testdata, 8, &written, NULL);
    CloseHandle(hFile);

    //open + read
    HANDLE  hFile2 = CreateFile(szTempFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char testdata2[5];
    DWORD read;
    ReadFile(hFile2, testdata2, 4, &read, NULL);
    testdata2[4] = 0;
    CloseHandle(hFile2);

    printf("Read %d bytes: %s\n", read, testdata2);

    DeleteFile(szTempFileName);
}
