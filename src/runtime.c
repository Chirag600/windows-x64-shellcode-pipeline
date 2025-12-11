// Adapted from "From a C project, through assembly, to shellcode"
// by hasherezade for @vxunderground
// Ref: https://raw.githubusercontent.com/hasherezade/masm_shc/master/docs/FromaCprojectthroughassemblytoshellcode.pdf

#include "runtime.h"

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    HANDLE SectionHandle;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

static LPVOID get_module_by_name(WCHAR* module_name) {
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY *curr = head->Flink;

    while (curr && curr != head) {
        PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)curr;
        if (mod->BaseDllName.Buffer != NULL) {
            WCHAR *curr_name = mod->BaseDllName.Buffer;
            size_t i = 0;
            for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
                WCHAR c1, c2;
                TO_LOWERCASE(c1, module_name[i]);
                TO_LOWERCASE(c2, curr_name[i]);
                if (c1 != c2) {
                    break;
                }
            }
            if (module_name[i] == 0 && curr_name[i] == 0) {
                return mod->BaseAddress;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

static LPVOID get_func_by_name(LPVOID module, char* func_name) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == 0) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)((BYTE*)module + funcNamesListRVA + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)((BYTE*)module + namesOrdsListRVA + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)((BYTE*)module + funcsListRVA + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)((BYTE*)module + *nameRVA);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) {
                break;
            }
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

void sc_init_env(SC_ENV *env) {
    WCHAR kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };

    LPVOID base = get_module_by_name(kernel32_dll_name);
    if (!base) {
        env->kernel32 = NULL;
        env->pLoadLibraryA = NULL;
        env->pGetProcAddress = NULL;
        return;
    }

    env->kernel32 = (HMODULE)base;
    env->pLoadLibraryA = (HMODULE (WINAPI*)(LPCSTR))get_func_by_name(base, load_lib_name);
    env->pGetProcAddress = (FARPROC (WINAPI*)(HMODULE, LPCSTR))get_func_by_name(base, get_proc_name);
}
