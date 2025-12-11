#include "runtime.h"

void payload_main(SC_ENV *env) {
    if (!env->pLoadLibraryA || !env->pGetProcAddress) {
        return;
    }

    char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };

    wchar_t msg_content[] = { 'H','e','l','l','o',' ','W','o','r','l','d','!', 0 };
    wchar_t msg_title[]   = { 'D','e','m','o','!', 0 };

    HMODULE u32 = env->pLoadLibraryA(user32_dll_name);
    if (!u32) {
        return;
    }

    int (WINAPI *pMessageBoxW)(
        HWND,
        LPCWSTR,
        LPCWSTR,
        UINT
    ) = (int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT))
        env->pGetProcAddress(u32, message_box_name);

    if (!pMessageBoxW) {
        return;
    }

    pMessageBoxW(0, msg_content, msg_title, MB_OK);
}
