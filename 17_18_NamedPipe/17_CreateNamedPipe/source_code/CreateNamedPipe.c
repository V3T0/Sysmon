#include <windows.h>
#include <stdio.h>

int wmain(int argc, char* argv[]) {
	char buffer[1024];
	DWORD dwRead;
	HANDLE hNamedPipe = CreateNamedPipeA(
		(LPCSTR)"\\\\.\\pipe\\TestPipe",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL
	);

	if (hNamedPipe == INVALID_HANDLE_VALUE) {
		printf("Invalid Handle: %d", GetLastError());
		return -1;
	}

	while (hNamedPipe != INVALID_HANDLE_VALUE) {
		if (ConnectNamedPipe(hNamedPipe, NULL) != FALSE) {
			while (ReadFile(hNamedPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) {
				buffer[dwRead] = '\0';
				printf("%s\n", &buffer);
			}
		}
		DisconnectNamedPipe(hNamedPipe);
	}
	
	return 0;
}