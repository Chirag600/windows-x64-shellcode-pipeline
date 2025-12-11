#pragma once
#include <windows.h>

typedef struct _SC_ENV {
    HMODULE kernel32;
    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
} SC_ENV;

void sc_init_env(SC_ENV *env);