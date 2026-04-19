#include "loader.h"

// Forward declarations
static HMODULE GetKernel32Base(void);
static void* ResolveAPI(HMODULE kernel32, const char* name);

// Main loader entry point
// This is simpler: extract DLL to temp file, load it, validate, then jump to original EP
void __stdcall LoaderEntry(void) {
    // Get kernel32.dll base
    HMODULE kernel32 = GetKernel32Base();
    if (!kernel32) goto fail;

    // Resolve needed APIs
    typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);
    typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
    typedef DWORD (WINAPI *GetModuleFileNameAFunc)(HMODULE, LPSTR, DWORD);
    typedef HANDLE (WINAPI *CreateFileAFunc)(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI *ReadFileFunc)(HANDLE, void*, DWORD, DWORD*, void*);
    typedef BOOL (WINAPI *WriteFileFunc)(HANDLE, const void*, DWORD, DWORD*, void*);
    typedef BOOL (WINAPI *CloseHandleFunc)(HANDLE);
    typedef DWORD (WINAPI *SetFilePointerFunc)(HANDLE, LONG, LONG*, DWORD);
    typedef void (WINAPI *ExitProcessFunc)(UINT);
    typedef DWORD (WINAPI *GetTempPathAFunc)(DWORD, LPSTR);
    typedef DWORD (WINAPI *GetTempFileNameAFunc)(LPCSTR, LPCSTR, UINT, LPSTR);
    typedef BOOL (WINAPI *DeleteFileAFunc)(LPCSTR);

    LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)ResolveAPI(kernel32, "LoadLibraryA");
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)ResolveAPI(kernel32, "GetProcAddress");
    GetModuleFileNameAFunc pGetModuleFileNameA = (GetModuleFileNameAFunc)ResolveAPI(kernel32, "GetModuleFileNameA");
    ExitProcessFunc pExitProcess = (ExitProcessFunc)ResolveAPI(kernel32, "ExitProcess");

    if (!pLoadLibraryA || !pGetProcAddress || !pGetModuleFileNameA || !pExitProcess)
        goto fail;

    CreateFileAFunc pCreateFileA = (CreateFileAFunc)ResolveAPI(kernel32, "CreateFileA");
    ReadFileFunc pReadFile = (ReadFileFunc)ResolveAPI(kernel32, "ReadFile");
    WriteFileFunc pWriteFile = (WriteFileFunc)ResolveAPI(kernel32, "WriteFile");
    CloseHandleFunc pCloseHandle = (CloseHandleFunc)ResolveAPI(kernel32, "CloseHandle");
    SetFilePointerFunc pSetFilePointer = (SetFilePointerFunc)ResolveAPI(kernel32, "SetFilePointer");
    GetTempPathAFunc pGetTempPathA = (GetTempPathAFunc)ResolveAPI(kernel32, "GetTempPathA");
    GetTempFileNameAFunc pGetTempFileNameA = (GetTempFileNameAFunc)ResolveAPI(kernel32, "GetTempFileNameA");
    DeleteFileAFunc pDeleteFileA = (DeleteFileAFunc)ResolveAPI(kernel32, "DeleteFileA");

    if (!pCreateFileA || !pReadFile || !pWriteFile || !pCloseHandle || !pSetFilePointer)
        goto fail;

    // Get our exe path
    char exePath[MAX_PATH];
    pGetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Open our exe to read overlay
    HANDLE hExe = pCreateFileA(exePath, 0x80000000, 1, NULL, 3, 0, NULL); // GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
    if (hExe == (HANDLE)-1) goto fail;

    // Read overlay config from end of file
    OVERLAY_CONFIG config;
    pSetFilePointer(hExe, -(LONG)sizeof(OVERLAY_CONFIG), NULL, 2); // FILE_END
    DWORD bytesRead;
    pReadFile(hExe, &config, sizeof(config), &bytesRead, NULL);

    if (config.magic != OVERLAY_MAGIC) {
        pCloseHandle(hExe);
        pExitProcess(1);
        return;
    }

    // Read DLL data from overlay
    DWORD overlaySize = sizeof(OVERLAY_CONFIG) + config.dll_size;
    pSetFilePointer(hExe, -(LONG)overlaySize, NULL, 2);

    // Allocate memory for DLL
    void* pVirtualAlloc = ResolveAPI(kernel32, "VirtualAlloc");
    typedef void* (WINAPI *VirtualAllocFunc)(void*, size_t, DWORD, DWORD);
    VirtualAllocFunc pVirtualAllocReal = (VirtualAllocFunc)pVirtualAlloc;

    char* dllBuffer = (char*)pVirtualAllocReal(NULL, config.dll_size, 0x3000, 0x40); // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
    if (!dllBuffer) {
        pCloseHandle(hExe);
        pExitProcess(2);
        return;
    }

    pReadFile(hExe, dllBuffer, config.dll_size, &bytesRead, NULL);
    pCloseHandle(hExe);

    // Write DLL to temp file
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];

    if (pGetTempPathA && pGetTempFileNameA) {
        pGetTempPathA(MAX_PATH, tempPath);
        pGetTempFileNameA(tempPath, "val", 0, tempFile);
    } else {
        // Fallback
        for (int i = 0; i < 100; i++) {
            char path[64];
            // Try different temp paths
        }
        pExitProcess(3);
        return;
    }

    HANDLE hTemp = pCreateFileA(tempFile, 0x40000000, 0, NULL, 2, 0, NULL); // GENERIC_WRITE, CREATE_ALWAYS
    if (hTemp == (HANDLE)-1) {
        pExitProcess(4);
        return;
    }

    DWORD bytesWritten;
    pWriteFile(hTemp, dllBuffer, config.dll_size, &bytesWritten, NULL);
    pCloseHandle(hTemp);

    // Load the DLL
    HMODULE hDll = pLoadLibraryA(tempFile);
    if (!hDll) {
        pDeleteFileA(tempFile);
        pExitProcess(5);
        return;
    }

    // Get Validate function
    typedef BOOL (WINAPI *ValidateFunc)(DWORD);
    ValidateFunc Validate = (ValidateFunc)pGetProcAddress(hDll, "Validate");

    if (!Validate) {
        pDeleteFileA(tempFile);
        pExitProcess(6);
        return;
    }

    // Call validate
    BOOL result = Validate(config.appid);

    // Clean up - delete temp file
    // Free library first to ensure file is not locked
    typedef BOOL (WINAPI *FreeLibraryFunc)(HMODULE);
    FreeLibraryFunc pFreeLibrary = (FreeLibraryFunc)ResolveAPI(kernel32, "FreeLibrary");
    if (pFreeLibrary) {
        // Note: we may want to keep the DLL loaded, so skip free
        // pFreeLibrary(hDll);
    }

    if (!result) {
        pDeleteFileA(tempFile);
        pExitProcess(7);
        return;
    }

    // Delete temp file (DLL is loaded in memory)
    pDeleteFileA(tempFile);

    // Success - jump to original entry point
    // Original EP = config.original_ep_rva + image_base
    // The image base is passed in config
    DWORD_PTR imageBase = (DWORD_PTR)config.image_base;
    DWORD_PTR originalEP = imageBase + config.original_ep_rva;

    // Jump to original entry point
    __asm {
        jmp [originalEP]
    }

    return;

fail:
    // Simple fail - just exit
    __asm {
        push 1
        call [pExitProcess]
    }
}

// Get kernel32.dll base from PEB (x86)
static HMODULE GetKernel32Base(void) {
    // Access PEB
    void* peb = NULL;
    __asm {
        mov eax, fs:[0x30]
        mov [peb], eax
    }

    // PEB->Ldr is at offset 0x0C
    void* ldr = *(void**)((char*)peb + 0x0C);

    // Ldr->InLoadOrderModuleList is at offset 0x0C
    void* listHead = (char*)ldr + 0x0C;
    void* current = *(void**)listHead; // Flink

    // Walk the list - kernel32 is usually 3rd
    for (int i = 0; i < 20 && current != listHead; i++) {
        // LDR_DATA_TABLE_ENTRY structure
        // DllBase is at offset 0x18
        void* dllBase = *(void**)((char*)current + 0x18);

        // BaseDllName is at offset 0x2C (UNICODE_STRING)
        // Length at 0x2C, Buffer at 0x30
        unsigned short length = *(unsigned short*)((char*)current + 0x2C);
        wchar_t* buffer = *(wchar_t**)((char*)current + 0x30);

        // Check for kernel32.dll (length = 24 bytes = 12 chars * 2)
        if (length == 24 && buffer != NULL) {
            // Simple check for 'k' or 'K'
            wchar_t c0 = buffer[0];
            wchar_t c1 = buffer[1];
            wchar_t c2 = buffer[2];
            wchar_t c3 = buffer[3];
            wchar_t c4 = buffer[4];
            wchar_t c5 = buffer[5];

            if ((c0 == L'k' || c0 == L'K') &&
                (c1 == L'e' || c1 == L'E') &&
                (c2 == L'r' || c2 == L'R') &&
                (c3 == L'n' || c3 == L'N') &&
                (c4 == L'e' || c4 == L'E') &&
                (c5 == L'l' || c5 == L'L')) {
                return (HMODULE)dllBase;
            }
        }

        current = *(void**)current; // Flink
    }

    return NULL;
}

// Resolve API by name from kernel32
static void* ResolveAPI(HMODULE kernel32, const char* name) {
    if (!kernel32 || !name) return NULL;

    // Get export directory
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)kernel32;
    if (dos->e_magic != 0x5A4D) return NULL; // MZ

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((char*)kernel32 + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL; // PE\0\0

    IMAGE_DATA_DIRECTORY* exportDir = &nt->OptionalHeader.DataDirectory[0]; // Export directory
    if (!exportDir->VirtualAddress) return NULL;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((char*)kernel32 + exportDir->VirtualAddress);

    DWORD* names = (DWORD*)((char*)kernel32 + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((char*)kernel32 + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((char*)kernel32 + exports->AddressOfFunctions);

    // Find the function name
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* funcName = (char*)((char*)kernel32 + names[i]);
        const char* searchName = name;

        // Compare strings
        while (*funcName && *searchName && *funcName == *searchName) {
            funcName++;
            searchName++;
        }

        if (*funcName == 0 && *searchName == 0) {
            // Found! Return function address
            DWORD rva = functions[ordinals[i]];
            return (void*)((char*)kernel32 + rva);
        }
    }

    return NULL;
}
