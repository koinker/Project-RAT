#include <winsock2.h>
#include <Windows.h>
#include <wininet.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "wininet.lib")

// Download a file from a URL and save it to the local path
BOOL downloadfile(const CHAR* url, const CHAR* filePath, CHAR** output) {
    *output = (CHAR*)calloc(BUFFER_SIZE, sizeof(CHAR));
    if (!*output) {
        return FALSE; // Memory allocation failed
    }

    HINTERNET hInternet = InternetOpenA("FileDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        snprintf(*output, BUFFER_SIZE, "Error opening internet: %lu\n", GetLastError());
        return FALSE;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        snprintf(*output, BUFFER_SIZE, "Error opening URL: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Open the file to save the downloaded content
    HANDLE hLocalFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLocalFile == INVALID_HANDLE_VALUE) {
        snprintf(*output, BUFFER_SIZE, "Error creating file: %lu\n", GetLastError());
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Read and write the data in chunks
    char buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    while (InternetReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead) && bytesRead > 0) {
        WriteFile(hLocalFile, buffer, bytesRead, &bytesWritten, NULL);
    }

    // Clean up
    CloseHandle(hLocalFile);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    snprintf(*output, BUFFER_SIZE, "Downloaded file from %s to %s\n", url, filePath);
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