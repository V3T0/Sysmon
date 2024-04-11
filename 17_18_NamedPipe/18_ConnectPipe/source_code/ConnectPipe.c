#include <windows.h>
#include <stdio.h>

int wmain(int argc, char* argv[]) {
	char buffer[1024];
	DWORD dwWrite;
	HANDLE hNamedPipe = CreateFileA((LPCSTR)"\\\\.\\pipe\\TestPipe",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hNamedPipe == INVALID_HANDLE_VALUE) {
		printf("Invalid Handle: %d", GetLastError());
		return -1;
	}

	scanf_s("Write a message to send to pipe: %s", &buffer);
	
	WriteFile(hNamedPipe,
		buffer,
		strlen(buffer),   // = length of string + terminating '\0' !!!
		&dwWrite,
		NULL);
	CloseHandle(hNamedPipe);

	return 0;
}