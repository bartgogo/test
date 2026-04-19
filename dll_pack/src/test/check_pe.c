#include <stdio.h>
#include <windows.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("Error: Cannot open file\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    BYTE* data = (BYTE*)malloc(fileSize);
    fread(data, 1, fileSize, f);
    fclose(f);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        return 1;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        return 1;
    }

    printf("File size: %ld bytes\n", fileSize);
    printf("PE offset: 0x%X\n", dos->e_lfanew);

    WORD magic = nt->OptionalHeader.Magic;
    printf("PE Magic: 0x%X (%s)\n", magic,
           magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "64-bit" :
           magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "32-bit" : "Unknown");

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)nt;
        printf("Image Base: 0x%llX\n", nt64->OptionalHeader.ImageBase);
        printf("Entry Point RVA: 0x%X\n", nt64->OptionalHeader.AddressOfEntryPoint);
        printf("Entry Point VA: 0x%llX\n", nt64->OptionalHeader.ImageBase + nt64->OptionalHeader.AddressOfEntryPoint);
        printf("Number of Sections: %d\n", nt64->FileHeader.NumberOfSections);
        printf("Size of Image: 0x%X\n", nt64->OptionalHeader.SizeOfImage);
        printf("Size of Headers: 0x%X\n", nt64->OptionalHeader.SizeOfHeaders);

        printf("\nSections:\n");
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
            char name[9] = {0};
            memcpy(name, section[i].Name, 8);
            printf("  [%d] %-8s VA: 0x%08X  Raw: 0x%08X  Size: 0x%08X  Char: 0x%08X\n",
                   i, name, section[i].VirtualAddress, section[i].PointerToRawData,
                   section[i].SizeOfRawData, section[i].Characteristics);
        }

        // Check entry point section
        DWORD epRVA = nt64->OptionalHeader.AddressOfEntryPoint;
        for (int i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
            DWORD start = section[i].VirtualAddress;
            DWORD end = start + section[i].Misc.VirtualSize;
            if (epRVA >= start && epRVA < end) {
                printf("\nEntry point is in section: %s\n", section[i].Name);
                DWORD fileOffset = section[i].PointerToRawData + (epRVA - section[i].VirtualAddress);
                printf("File offset of entry point: 0x%X\n", fileOffset);
                printf("First bytes at entry point:\n  ");
                for (int j = 0; j < 16; j++) {
                    printf("%02X ", data[fileOffset + j]);
                }
                printf("\n");
                break;
            }
        }
    }

    free(data);
    return 0;
}
