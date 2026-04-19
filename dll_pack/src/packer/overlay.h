#ifndef OVERLAY_H
#define OVERLAY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Overlay magic number "PACK"
#define OVERLAY_MAGIC 0x5041434B
#define OVERLAY_VERSION 1

// Loader runtime policy
#define LOADER_MODE_FULL   1
#define LOADER_MODE_COMPAT 2

// Overlay configuration (placed at end of file)
#pragma pack(push, 1)
typedef struct {
    DWORD magic;            // OVERLAY_MAGIC
    DWORD version;          // Overlay format version
    DWORD loader_mode;      // LOADER_MODE_*
    DWORD appid;            // Application ID
    DWORD dll_size;         // Size of embedded DLL
    DWORD original_ep_rva;  // Original entry point RVA
    DWORD image_base;       // Image base
    DWORD reserved;         // Reserved for future feature flags
} OVERLAY_CONFIG;
#pragma pack(pop)

// Read DLL file into buffer
int Overlay_ReadDLL(const char* filename, BYTE** data, DWORD* size);

// Create overlay data (DLL + config)
BYTE* Overlay_Create(DWORD appid, DWORD originalEP, DWORD imageBase,
                     const BYTE* dllData, DWORD dllSize, DWORD* outSize);

// Append overlay to PE file
int Overlay_Append(const char* peFile, const BYTE* overlay, DWORD overlaySize);

#ifdef __cplusplus
}
#endif

#endif // OVERLAY_H
