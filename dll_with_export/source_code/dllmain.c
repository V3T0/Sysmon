
#include <Windows.h>

// Exported function
extern __declspec(dllexport) void Sysmon() {
    MessageBoxA(NULL, "Let's learn sysmon internals together", "Message", MB_ICONINFORMATION);
}

// Entry point for the DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}