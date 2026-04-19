#include <stdio.h>
#include <windows.h>

int main() {
    printf("Hello from the original program!\n");
    printf("This program was packed and should only run after validation.\n\n");

    // Show some system info
    char computerName[MAX_PATH];
    DWORD size = MAX_PATH;
    GetComputerNameA(computerName, &size);

    printf("Running on: %s\n", computerName);
    printf("Time: %lu\n", GetTickCount());

    MessageBoxA(NULL, "Original program executed successfully!", "Test Program", MB_OK | MB_ICONINFORMATION);

    return 0;
}
