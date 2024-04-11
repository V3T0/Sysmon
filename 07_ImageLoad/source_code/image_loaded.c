#include <windows.h>
#include <stdio.h>
 
typedef void (WINAPI* ExportedFunctionPointer)();

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[Usage] image_loaded.exe path_to_dll exported_function_to_call");
        return 0;
    }

    HMODULE hModule = GetModuleHandleA(argv[1]);

    if (hModule == NULL) {
        // If the DLL is not loaded in memory, use LoadLibrary to load it
        hModule = LoadLibraryA(argv[1]);
        if (hModule == NULL) {
            printf("[ERROR] Unable to load DLL into memory! Exiting the program");
            return 0;
        }
    }

    PVOID pExportedFunction = GetProcAddress(hModule, argv[2]);

    if (pExportedFunction == NULL) {
        printf("[ERROR] Couldn't find the exported function");
        return 0;
    }

    ExportedFunctionPointer ExportedFunction = (ExportedFunctionPointer)pExportedFunction;

    ExportedFunction();

    return 0;

}