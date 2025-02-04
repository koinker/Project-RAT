
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