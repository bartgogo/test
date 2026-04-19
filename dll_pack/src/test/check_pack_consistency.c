#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "../packer/overlay.h"

typedef struct {
    BYTE* data;
    long size;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    BOOL is64;
} PE_FILE;

static int LoadPE(const char* path, PE_FILE* out) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("Error: Cannot open %s\n", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    out->size = ftell(f);
    fseek(f, 0, SEEK_SET);
    out->data = (BYTE*)malloc((size_t)out->size);
    if (!out->data) {
        fclose(f);
        printf("Error: OOM while reading %s\n", path);
        return -1;
    }
    if (fread(out->data, 1, (size_t)out->size, f) != (size_t)out->size) {
        fclose(f);
        free(out->data);
        printf("Error: Failed reading %s\n", path);
        return -1;
    }
    fclose(f);

    out->dos = (IMAGE_DOS_HEADER*)out->data;
    if (out->dos->e_magic != IMAGE_DOS_SIGNATURE) {
        free(out->data);
        printf("Error: Invalid DOS signature: %s\n", path);
        return -1;
    }
    out->nt = (IMAGE_NT_HEADERS*)(out->data + out->dos->e_lfanew);
    if (out->nt->Signature != IMAGE_NT_SIGNATURE) {
        free(out->data);
        printf("Error: Invalid NT signature: %s\n", path);
        return -1;
    }
    out->is64 = (out->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    return 0;
}

static void FreePE(PE_FILE* pe) {
    if (pe->data) {
        free(pe->data);
        pe->data = NULL;
    }
}

static IMAGE_DATA_DIRECTORY GetDir(const PE_FILE* pe, DWORD index) {
    if (pe->is64) {
        const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)pe->nt;
        return nt64->OptionalHeader.DataDirectory[index];
    }
    return pe->nt->OptionalHeader.DataDirectory[index];
}

static WORD GetDllChars(const PE_FILE* pe) {
    if (pe->is64) {
        const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)pe->nt;
        return nt64->OptionalHeader.DllCharacteristics;
    }
    return pe->nt->OptionalHeader.DllCharacteristics;
}

static int CheckOverlay(const PE_FILE* packed, DWORD expectedAppId, DWORD expectedLoaderMode) {
    if (packed->size < (long)sizeof(OVERLAY_CONFIG)) {
        printf("Error: packed file too small for overlay config\n");
        return -1;
    }

    const OVERLAY_CONFIG* cfg = (const OVERLAY_CONFIG*)(packed->data + packed->size - sizeof(OVERLAY_CONFIG));
    printf("Overlay: magic=0x%08X version=%lu mode=%lu appid=%lu dll_size=%lu\n",
           cfg->magic, cfg->version, cfg->loader_mode, cfg->appid, cfg->dll_size);

    if (cfg->magic != OVERLAY_MAGIC) {
        printf("Error: overlay magic mismatch\n");
        return -1;
    }
    if (cfg->version != OVERLAY_VERSION) {
        printf("Error: overlay version mismatch (%lu)\n", cfg->version);
        return -1;
    }
    if (cfg->loader_mode != expectedLoaderMode) {
        printf("Error: loader mode mismatch (%lu)\n", cfg->loader_mode);
        return -1;
    }
    if (cfg->appid != expectedAppId) {
        printf("Error: appid mismatch (%lu)\n", cfg->appid);
        return -1;
    }
    if (cfg->dll_size == 0 || cfg->dll_size > (DWORD)packed->size) {
        printf("Error: invalid dll size in overlay (%lu)\n", cfg->dll_size);
        return -1;
    }
    if (cfg->original_ep_rva == 0) {
        printf("Error: invalid original EP RVA in overlay\n");
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Usage: %s <input.exe> <packed.exe> <expected_appid> <expected_loader_mode>\n", argv[0]);
        return 1;
    }

    const char* inputPath = argv[1];
    const char* packedPath = argv[2];
    DWORD expectedAppId = (DWORD)strtoul(argv[3], NULL, 10);
    DWORD expectedLoaderMode = (DWORD)strtoul(argv[4], NULL, 10);

    PE_FILE input = {0};
    PE_FILE packed = {0};
    int rc = 1;

    if (LoadPE(inputPath, &input) != 0) goto done;
    if (LoadPE(packedPath, &packed) != 0) goto done;

    IMAGE_DATA_DIRECTORY inImport = GetDir(&input, IMAGE_DIRECTORY_ENTRY_IMPORT);
    IMAGE_DATA_DIRECTORY outImport = GetDir(&packed, IMAGE_DIRECTORY_ENTRY_IMPORT);
    IMAGE_DATA_DIRECTORY inReloc = GetDir(&input, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    IMAGE_DATA_DIRECTORY outReloc = GetDir(&packed, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    IMAGE_DATA_DIRECTORY inTls = GetDir(&input, IMAGE_DIRECTORY_ENTRY_TLS);
    IMAGE_DATA_DIRECTORY outTls = GetDir(&packed, IMAGE_DIRECTORY_ENTRY_TLS);

    if (inImport.VirtualAddress != outImport.VirtualAddress || inImport.Size != outImport.Size) {
        printf("Error: import directory changed unexpectedly\n");
        goto done;
    }
    if (inReloc.VirtualAddress != outReloc.VirtualAddress || inReloc.Size != outReloc.Size) {
        printf("Error: relocation directory changed unexpectedly\n");
        goto done;
    }
    if (inTls.VirtualAddress != outTls.VirtualAddress || inTls.Size != outTls.Size) {
        printf("Error: TLS directory changed unexpectedly\n");
        goto done;
    }

    WORD inChars = GetDllChars(&input);
    WORD outChars = GetDllChars(&packed);

    if ((inChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != (outChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
        printf("Error: DEP(NX_COMPAT) flag changed unexpectedly\n");
        goto done;
    }
    if (outChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        printf("Error: ASLR(DYNAMIC_BASE) should be disabled in packed file\n");
        goto done;
    }

    if (CheckOverlay(&packed, expectedAppId, expectedLoaderMode) != 0) {
        goto done;
    }

    printf("Consistency checks passed.\n");
    rc = 0;

done:
    FreePE(&input);
    FreePE(&packed);
    return rc;
}
