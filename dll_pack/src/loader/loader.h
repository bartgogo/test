#ifndef LOADER_H
#define LOADER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Overlay magic number "PACK"
#define OVERLAY_MAGIC 0x5041434B

// Overlay configuration structure (placed at end of packed exe)
#pragma pack(push, 1)
typedef struct {
    DWORD magic;            // OVERLAY_MAGIC
    DWORD appid;            // Application ID to validate
    DWORD dll_size;         // Size of embedded DLL
    DWORD original_ep_rva;  // Original entry point RVA
    DWORD image_base;       // Image base address
    BYTE  dll_data[1];      // Start of DLL data (variable length)
} OVERLAY_CONFIG;
#pragma pack(pop)

// Loader entry point - this will be the new entry point
void __stdcall LoaderEntry(void);

// Get overlay config - finds overlay at end of module
OVERLAY_CONFIG* GetOverlayConfig(HMODULE hModule);

#ifdef __cplusplus
}
#endif

#endif // LOADER_H
