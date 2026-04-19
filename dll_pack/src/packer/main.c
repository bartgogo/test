#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "pe_parser.h"
#include "overlay.h"
#include "../loader/active_loader.h"

void PrintUsage(const char* prog) {
    printf("PE Packer v2.0 - Complete Implementation\n\n");
    printf("Usage: %s -in <input.exe> -out <output.exe> -appid <id> [-dll <validator.dll>]\n\n", prog);
    printf("Options:\n");
    printf("  -in <file>     Input executable to pack\n");
    printf("  -out <file>    Output packed executable\n");
    printf("  -appid <num>   Application ID for validation (100-1000 valid)\n");
    printf("  -dll <file>    Validator DLL (default: validator.dll)\n");
    printf("\nThe packed exe will validate before running the original program.\n");
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
    if (appId < 100 || appId > 1000) {
        printf("Error: Invalid -appid %lu (valid range: 100-1000)\n", appId);
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
        printf("Error: Failed to read DLL file: %s\n", dllFile);
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
        printf("Architecture: 64-bit (x64)\n");
        printf("Original EP:  0x%llX (RVA: 0x%X)\n", imageBase64 + originalEP64, (DWORD)originalEP64);
        printf("Image Base:   0x%llX\n", imageBase64);
    } else {
        originalEP32 = pe.nt->OptionalHeader.AddressOfEntryPoint;
        imageBase32 = pe.nt->OptionalHeader.ImageBase;
        printf("Architecture: 32-bit (x86)\n");
        printf("Original EP:  0x%X (RVA: 0x%X)\n", imageBase32 + originalEP32, originalEP32);
        printf("Image Base:   0x%X\n", imageBase32);
    }

    // Generate shellcode
    size_t shellcodeSize = 0;
    unsigned char* shellcode = NULL;

    printf("\nGenerating loader shellcode...\n");

    if (is64bit) {
        // Use the validation shellcode for x64
        shellcode = CreateValidationGateShellcode64(originalEP64, appId, imageBase64, &shellcodeSize);
    } else {
        // For x86, use validation gate then jump
        shellcode = CreateValidationGateShellcode32(imageBase32 + originalEP32, appId, &shellcodeSize);
    }

    if (!shellcode) {
        printf("Error: Failed to generate shellcode\n");
        free(dllData);
        PE_Free(&pe);
        return 1;
    }
    printf("Shellcode size: %zu bytes\n", shellcodeSize);

    // Add loader section
    DWORD sectionSize = 0x1000;  // 4KB minimum
    printf("\nAdding loader section...\n");

    if (PE_AddSection(&pe, ".vstub", sectionSize,
                      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) != 0) {
        printf("Error: Failed to add loader section\n");
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }

    // Get new section info
    IMAGE_SECTION_HEADER* newSection = &pe.sections[pe.numSections - 1];
    DWORD newSectionRVA = newSection->VirtualAddress;
    printf("Loader section RVA: 0x%X\n", newSectionRVA);

    // Modify entry point
    if (is64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)pe.nt;
        nt64->OptionalHeader.AddressOfEntryPoint = newSectionRVA;
        // Disable ASLR for hardcoded addresses
        nt64->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    } else {
        pe.nt->OptionalHeader.AddressOfEntryPoint = newSectionRVA;
        pe.nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }
    printf("New entry point: 0x%X\n", newSectionRVA);
    printf("Disabled ASLR\n");

    // Copy shellcode to new section
    memcpy(pe.data + newSection->PointerToRawData, shellcode, shellcodeSize);

    // Create overlay (DLL + config)
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
        printf("Error: Failed to save output file\n");
        free(overlay);
        free(shellcode);
        free(dllData);
        PE_Free(&pe);
        return 1;
    }

    printf("\n========================================\n");
    printf("SUCCESS! Packed executable created.\n");
    printf("========================================\n");
    printf("Output file: %s\n", outputFile);
    printf("Total size:  %zu bytes\n", pe.size);
    printf("\n");
    printf("Packed structure:\n");
    printf("  - Original PE sections preserved\n");
    printf("  - Loader section added at RVA 0x%X\n", newSectionRVA);
    printf("  - Overlay appended: DLL + config\n");
    printf("\n");
    printf("Validation info:\n");
    printf("  - AppID: %lu\n", appId);
    printf("  - Valid range: 100-1000\n");
    printf("  - Validator DLL: %s\n", dllFile);
    printf("========================================\n\n");

    printf("To test:\n");
    printf("  1. Run: %s\n", outputFile);
    printf("  2. If AppID is valid (100-1000), original program runs\n");
    printf("  3. If invalid, program exits\n\n");

    // Cleanup
    free(overlay);
    free(shellcode);
    free(dllData);
    PE_Free(&pe);

    return 0;
}
