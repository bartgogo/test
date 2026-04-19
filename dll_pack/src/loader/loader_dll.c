// Loader DLL - Handles validation and execution
// This DLL is embedded in the packed executable and loaded at startup
// It reads the overlay, loads the validator DLL, and performs validation

#include <windows.h>
#include <stdio.h>

// Overlay configuration
#pragma pack(push, 1)
typedef struct {
    DWORD magic;
    DWORD appid;
    DWORD dll_size;
    DWORD original_ep_rva;
    ULONGLONG image_base;
} OVERLAY_CONFIG;
#pragma pack(pop)

#define OVERLAY_MAGIC 0x5041434B

// Global variables
static OVERLAY_CONFIG g_config;
static HMODULE g_hModule = NULL;
static ULONGLONG g_originalEP = 0;

// Read overlay configuration and DLL from the executable
static BOOL ReadOverlayData(HMODULE hModule) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Read overlay config from end of file
    OVERLAY_CONFIG config;
    SetFilePointer(hFile, -(LONG)sizeof(OVERLAY_CONFIG), NULL, FILE_END);
    DWORD bytesRead;
    ReadFile(hFile, &config, sizeof(config), &bytesRead, NULL);

    if (config.magic != OVERLAY_MAGIC) {
        CloseHandle(hFile);
        return FALSE;
    }

    g_config = config;
    g_originalEP = config.image_base + config.original_ep_rva;

    CloseHandle(hFile);
    return TRUE;
}

// Extract validator DLL to temp file and load it
static HMODULE LoadValidatorDLL(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Seek to DLL data
    DWORD overlaySize = sizeof(OVERLAY_CONFIG) + g_config.dll_size;
    SetFilePointer(hFile, -(LONG)overlaySize, NULL, FILE_END);

    // Read DLL data
    BYTE* dllData = (BYTE*)VirtualAlloc(NULL, g_config.dll_size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dllData) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    ReadFile(hFile, dllData, g_config.dll_size, &bytesRead, NULL);
    CloseHandle(hFile);

    // Write to temp file
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "val", 0, tempFile);

    HANDLE hTemp = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, 0, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        VirtualFree(dllData, 0, MEM_RELEASE);
        return NULL;
    }

    DWORD bytesWritten;
    WriteFile(hTemp, dllData, g_config.dll_size, &bytesWritten, NULL);
    CloseHandle(hTemp);
    VirtualFree(dllData, 0, MEM_RELEASE);

    // Load the DLL
    HMODULE hDll = LoadLibraryA(tempFile);

    // Delete temp file (DLL is loaded in memory)
    DeleteFileA(tempFile);

    return hDll;
}

// Perform validation
static BOOL PerformValidation(void) {
    HMODULE hValidator = LoadValidatorDLL();
    if (!hValidator) {
        MessageBoxA(NULL, "Failed to load validator DLL", "Error", MB_ICONERROR);
        return FALSE;
    }

    typedef BOOL (WINAPI *ValidateFunc)(DWORD);
    ValidateFunc Validate = (ValidateFunc)GetProcAddress(hValidator, "Validate");

    if (!Validate) {
        MessageBoxA(NULL, "Validate function not found", "Error", MB_ICONERROR);
        return FALSE;
    }

    return Validate(g_config.appid);
}

// Jump to original entry point
static void __declspec(noreturn) JumpToOriginalEP(void) {
    // This is a placeholder - actual jump is done via inline assembly
    // The packer will patch this to jump to the correct address
    __debugbreak();
}

// Entry point for the loader DLL
// This is called by a small shellcode stub
__declspec(dllexport) BOOL WINAPI LoaderEntry(void) {
    // Read overlay configuration
    if (!ReadOverlayData(NULL)) {
        MessageBoxA(NULL, "Failed to read overlay data", "Error", MB_ICONERROR);
        return FALSE;
    }

    // Perform validation
    if (!PerformValidation()) {
        // Validation failed - exit
        ExitProcess(1);
    }

    // Validation passed - return TRUE
    // The caller (shellcode) will jump to original EP
    return TRUE;
}

// Get the original entry point address
__declspec(dllexport) ULONGLONG WINAPI GetOriginalEP(void) {
    return g_originalEP;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);
            break;
    }
    return TRUE;
}
