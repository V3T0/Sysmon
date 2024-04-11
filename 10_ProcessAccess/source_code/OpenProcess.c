#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


int wmain(int argc, wchar_t* argv[]) {
	DWORD dwDesiredAccess = NULL;
	PROCESSENTRY32	Process = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	if (argc < 2) {
		printf("[INFO] Usage : %ls process_name \n", argv[0]);
		printf("[NOTE] process_name is case-sensitive");
		return -1;
	}

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[ERROR] CreateToolhelp32Snapshot Failed");
		return -1;
	}

	if (!Process32First(hSnapShot, &Process)) {
		printf("[ERROR] Process32First Failed");
		return -1;
	}

	do {
		if (wcscmp(Process.szExeFile, argv[1]) == 0) {
			DWORD dwProcessId = Process.th32ProcessID;
			dwDesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE;
			printf("[INFO] Opening %ls with 0x%x access mask\n", argv[1], dwDesiredAccess);
			HANDLE hProcess = OpenProcess(dwDesiredAccess, FALSE, Process.th32ProcessID);
			if (hProcess == NULL) {
				printf("[ERROR] OpenProcess Failed");
				break;
			}
			printf("[INFO] %ls running with PID %d has been opened! \n", argv[1], dwProcessId);
			CloseHandle(hProcess);
			break;
		}
	} while (Process32Next(hSnapShot, &Process));
	return 0;
}

