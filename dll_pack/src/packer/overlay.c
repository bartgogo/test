#include "overlay.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int Overlay_ReadDLL(const char* filename, BYTE** data, DWORD* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Error: Cannot open DLL file %s\n", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    *data = (BYTE*)malloc(*size);
    if (!*data) {
        fclose(f);
        printf("Error: Cannot allocate memory for DLL\n");
        return -1;
    }

    fread(*data, 1, *size, f);
    fclose(f);

    return 0;
}

BYTE* Overlay_Create(DWORD appid, DWORD originalEP, DWORD imageBase,
                     const BYTE* dllData, DWORD dllSize, DWORD* outSize) {
    // Overlay structure: [DLL data][CONFIG]
    *outSize = dllSize + sizeof(OVERLAY_CONFIG);

    BYTE* overlay = (BYTE*)malloc(*outSize);
    if (!overlay) {
        return NULL;
    }

    // Copy DLL data
    memcpy(overlay, dllData, dllSize);

    // Setup config at end
    OVERLAY_CONFIG* config = (OVERLAY_CONFIG*)(overlay + dllSize);
    memset(config, 0, sizeof(OVERLAY_CONFIG));
    config->magic = OVERLAY_MAGIC;
    config->version = OVERLAY_VERSION;
    config->loader_mode = LOADER_MODE_FULL;
    config->appid = appid;
    config->dll_size = dllSize;
    config->original_ep_rva = originalEP;
    config->image_base = imageBase;

    return overlay;
}

int Overlay_Append(const char* peFile, const BYTE* overlay, DWORD overlaySize) {
    // This function is no longer needed as we integrate overlay during PE modification
    // Keeping for compatibility
    FILE* f = fopen(peFile, "ab");
    if (!f) {
        printf("Error: Cannot open PE file for append\n");
        return -1;
    }

    fwrite(overlay, 1, overlaySize, f);
    fclose(f);

    return 0;
}
