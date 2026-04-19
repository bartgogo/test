// Packer with TLS Callback approach
// This is a cleaner method that doesn't require complex shellcode
//
// TLS (Thread Local Storage) callbacks are executed BEFORE the main entry point
// We use this to perform validation before the program starts

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "pe_parser.h"
#include "overlay.h"

// Overlay magic
#define OVERLAY_MAGIC 0x5041434B

void PrintUsage(const char* prog) {
    printf("PE Packer v2.0 - TLS Callback Method\n\n");
    printf("Usage: %s -in <input.exe> -out <output.exe> -appid <id> [-dll <validator.dll>]\n\n", prog);
    printf("Options:\n");
    printf("  -in <file>     Input executable to pack\n");
    printf("  -out <file>    Output packed executable\n");
    printf("  -appid <num>   Application ID for validation (100-1000 valid)\n");
    printf("  -dll <file>    Validator DLL (default: validator.dll)\n");
    printf("\nThis packer uses TLS callbacks for validation.\n");
}

// x64 shellcode for TLS callback that performs validation
// This is called before main() executes
static unsigned char TLS_CALLBACK_CODE[] = {
    // TLS callback prologue
    // This code will be placed in a new section and called by the PE loader

    // push rbp
    0x55,
    // mov rbp, rsp
    0x48, 0x89, 0xE5,
    // sub rsp, 0x40
    0x48, 0x83, 0xEC, 0x40,

    // Get kernel32 base from PEB
    0x65, 0x48, 0xA1, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]
    0x48, 0x8B, 0x40, 0x18,                     // mov rax, [rax+0x18]
    0x48, 0x8B, 0x40, 0x20,                     // mov rax, [rax+0x20]
    0x48, 0x8B, 0x00,                           // mov rax, [rax]
    0x48, 0x8B, 0x00,                           // mov rax, [rax]
    0x48, 0x8B, 0x00,                           // mov rax, [rax]
    0x48, 0x8B, 0x40, 0x20,                     // mov rax, [rax+0x20]
    // rax = kernel32 base

    // Save kernel32 base
    0x49, 0x89, 0xC7,                           // mov r15, rax

    // For now, just return (no validation in this stub)
    // Full implementation would resolve APIs and call Validate

    // epilogue
    0x48, 0x83, 0xC4, 0x40,                     // add rsp, 0x40
    0x5D,                                       // pop rbp
    0xC3,                                       // ret
};

// Generate simple jump shellcode for x64
static unsigned char* GenerateJumpShellcode64(ULONGLONG targetAddress, size_t* outSize) {
    *outSize = 12;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    // mov rax, imm64
    sc[0] = 0x48;
    sc[1] = 0xB8;
    *(ULONGLONG*)(sc + 2) = targetAddress;

    // jmp rax
    sc[10] = 0xFF;
    sc[11] = 0xE0;

    return sc;
}

// Generate simple jump shellcode for x86
static unsigned char* GenerateJumpShellcode32(DWORD targetAddress, size_t* outSize) {
    *outSize = 7;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    // mov eax, imm32
    sc[0] = 0xB8;
    *(DWORD*)(sc + 1) = targetAddress;

    // jmp eax
    sc[5] = 0xFF;
    sc[6] = 0xE0;

    return sc;
}

int main(int argc, char* argv[]) {
    char* inputFile = NULL;
    char* outputFile = NULL;
    char* dllFile = "validator.dll";
    DWORD appId = 0;

    // Parse command line
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (strcmp(argv[i], "-appid") == 0 && i + 1 < argc) {
            appId = (DWORD)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-dll") == 0 && i + 1 < argc) {
            dllFile = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (!inputFile || !outputFile || appId == 0) {
        printf("Error: Missing required parameters\n\n");
        PrintUsage(argv[0]);
        return 1;
    }

    printf("PE Packer v2.0\n");
    printf("==============\n\n");
    printf("Input:    %s\n", inputFile);
    printf("Output:   %s\n", outputFile);
    printf("AppID:    %lu\n", appId);
    printf("DLL:      %s\n\n", dllFile);

    // Read DLL file
    BYTE* dllData = NULL;
    DWORD dllSize = 0;
    if (Overlay_ReadDLL(dllFile, &dllData, &dllSize) != 0) {
        printf("Error: Failed to read DLL file\n");
        return 1;
    }
    printf("DLL size: %lu bytes\n", dllSize);

    // Initialize PE context
    PE_CONTEXT pe;
    if (PE_Init(&pe, inputFile) != 0) {
        free(dllData);
        return 1;
    }
    printf("PE size:  %zu bytes\n", pe.size);

    // Check architecture
    BOOL is64bit = (pe.nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    ULONGLONG originalEP64 = 0;
    DWORD originalEP32 = 0;
    ULONGLONG imageBase64 = 0;
    DWORD imageBase32 = 0;

    if (is64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)pe.nt;
        originalEP64 = nt64->OptionalHeader.AddressOfEntryPoint;
        imageBase64 = nt64->OptionalHeader.ImageBase;
        printf("Architecture: 64-bit\n");
        printf("Original EP: 0x%llX\n", originalEP64);
        printf("Image Base:  0x%llX\n", imageBase64);
    } else {
        originalEP32 = pe.nt->OptionalHeader.AddressOfEntryPoint;
        imageBase32 = pe.nt->OptionalHeader.ImageBase;
        printf("Architecture: 32-bit\n");
        printf("Original EP: 0x%X\n", originalEP32);
        printf("Image Base:  0x%X\n", imageBase32);
    }

    // Generate jump shellcode
    size_t shellcodeSize = 0;
    unsigned char* shellcode = NULL;

    if (is64bit) {
        shellcode = GenerateJumpShellcode64(imageBase64 + originalEP64, &shellcodeSize);
    } else {
        shellcode = GenerateJumpShellcode32(imageBase32 + originalEP32, &shellcodeSize);
    }

    if (!shellcode) {
        printf("Error: Failed to generate shellcode\n");
        free(dllData);
        PE_Free(&pe);
        return 1;
    }
    printf("Shellcode size: %zu bytes\n", shellcodeSize);

    // Add loader section
    DWORD sectionSize = 0x1000;  // 4KB
    printf("Adding loader section...\n");

    if (PE_AddSection(&pe, ".vstub", sectionSize,
                      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) != 0) {
        printf("Error: Failed to add section\n");
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }

    // Get new section
    IMAGE_SECTION_HEADER* newSection = &pe.sections[pe.numSections - 1];
    DWORD newSectionRVA = newSection->VirtualAddress;
    printf("New section RVA: 0x%X\n", newSectionRVA);

    // Modify entry point
    if (is64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)pe.nt;
        nt64->OptionalHeader.AddressOfEntryPoint = newSectionRVA;
        // Disable ASLR
        nt64->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    } else {
        pe.nt->OptionalHeader.AddressOfEntryPoint = newSectionRVA;
        pe.nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }
    printf("New entry point: 0x%X\n", newSectionRVA);
    printf("Disabled ASLR\n");

    // Copy shellcode to new section
    memcpy(pe.data + newSection->PointerToRawData, shellcode, shellcodeSize);

    // Create overlay
    DWORD overlaySize = dllSize + sizeof(OVERLAY_CONFIG);
    BYTE* overlay = (BYTE*)malloc(overlaySize);
    if (!overlay) {
        printf("Error: Failed to allocate overlay\n");
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }

    // Copy DLL data
    memcpy(overlay, dllData, dllSize);

    // Setup config
    OVERLAY_CONFIG* config = (OVERLAY_CONFIG*)(overlay + dllSize);
    config->magic = OVERLAY_MAGIC;
    config->appid = appId;
    config->dll_size = dllSize;
    config->original_ep_rva = is64bit ? (DWORD)originalEP64 : originalEP32;
    config->image_base = is64bit ? (DWORD)imageBase64 : imageBase32;

    // Expand file for overlay
    size_t newSize = pe.size + overlaySize;
    BYTE* newData = (BYTE*)realloc(pe.data, newSize);
    if (!newData) {
        printf("Error: Failed to expand file\n");
        free(overlay);
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }
    pe.data = newData;

    // Append overlay
    memcpy(pe.data + pe.size, overlay, overlaySize);
    pe.size = newSize;
    printf("Overlay size: %lu bytes\n", overlaySize);

    // Save output
    printf("\nSaving packed executable...\n");
    if (PE_Save(&pe, outputFile) != 0) {
        printf("Error: Failed to save file\n");
        free(overlay);
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }

    printf("\n========================================\n");
    printf("Success! Packed executable created.\n");
    printf("Output: %s\n", outputFile);
    printf("Total size: %zu bytes\n", pe.size);
    printf("========================================\n\n");

    printf("NOTE: Current implementation uses pass-through stub.\n");
    printf("To enable full validation:\n");
    printf("1. The loader needs to read overlay from end of file\n");
    printf("2. Extract and load the validator DLL\n");
    printf("3. Call Validate(appid) function\n");
    printf("4. Only proceed if validation passes\n");

    // Cleanup
    free(overlay);
    free(shellcode);
    free(dllData);
    PE_Free(&pe);

    return 0;
}
