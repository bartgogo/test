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
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);

    WORD magic = nt->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)nt;

        printf("DllCharacteristics: 0x%04X\n", nt64->OptionalHeader.DllCharacteristics);

        if (nt64->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            printf("ASLR (DynamicBase): ENABLED\n");
        } else {
            printf("ASLR (DynamicBase): DISABLED\n");
        }

        if (nt64->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
            printf("NX Compatible (DEP): ENABLED\n");
        } else {
            printf("NX Compatible (DEP): DISABLED\n");
        }

        // Check relocs
        DWORD relocDirRVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocDirSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        printf("Relocation Directory: RVA=0x%X, Size=0x%X\n", relocDirRVA, relocDirSize);
    }

    free(data);
    return 0;
}
