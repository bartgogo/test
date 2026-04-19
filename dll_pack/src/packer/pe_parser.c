#include "pe_parser.h"
#include <stdlib.h>
#include <string.h>

// Helper to get optional header values regardless of PE bitness
static DWORD GetFileAlignment(PE_CONTEXT* ctx) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        return nt64->OptionalHeader.FileAlignment;
    }
    return ctx->nt->OptionalHeader.FileAlignment;
}

static DWORD GetSectionAlignment(PE_CONTEXT* ctx) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        return nt64->OptionalHeader.SectionAlignment;
    }
    return ctx->nt->OptionalHeader.SectionAlignment;
}

static DWORD GetSizeOfHeaders(PE_CONTEXT* ctx) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        return nt64->OptionalHeader.SizeOfHeaders;
    }
    return ctx->nt->OptionalHeader.SizeOfHeaders;
}

static void SetSizeOfImage(PE_CONTEXT* ctx, DWORD value) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.SizeOfImage = value;
    } else {
        ctx->nt->OptionalHeader.SizeOfImage = value;
    }
}

static void SetSizeOfHeaders(PE_CONTEXT* ctx, DWORD value) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.SizeOfHeaders = value;
    } else {
        ctx->nt->OptionalHeader.SizeOfHeaders = value;
    }
}

static void AddToSizeOfInitializedData(PE_CONTEXT* ctx, DWORD value) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.SizeOfInitializedData += value;
    } else {
        ctx->nt->OptionalHeader.SizeOfInitializedData += value;
    }
}

static void AddToSizeOfCode(PE_CONTEXT* ctx, DWORD value) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.SizeOfCode += value;
    } else {
        ctx->nt->OptionalHeader.SizeOfCode += value;
    }
}

int PE_Init(PE_CONTEXT* ctx, const char* filename) {
    memset(ctx, 0, sizeof(PE_CONTEXT));

    // Open and read file
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    ctx->size = ftell(f);
    fseek(f, 0, SEEK_SET);

    ctx->data = (BYTE*)malloc(ctx->size);
    if (!ctx->data) {
        fclose(f);
        printf("Error: Cannot allocate memory\n");
        return -1;
    }

    fread(ctx->data, 1, ctx->size, f);
    fclose(f);

    // Parse DOS header
    ctx->dos = (IMAGE_DOS_HEADER*)ctx->data;
    if (ctx->dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid DOS signature\n");
        free(ctx->data);
        return -1;
    }

    // Parse NT headers
    ctx->nt = (IMAGE_NT_HEADERS*)(ctx->data + ctx->dos->e_lfanew);
    if (ctx->nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature\n");
        free(ctx->data);
        return -1;
    }

    // Verify PE magic
    WORD magic = ctx->nt->OptionalHeader.Magic;
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("Error: Unknown PE magic: 0x%X\n", magic);
        free(ctx->data);
        return -1;
    }

    // Parse sections
    ctx->sections = IMAGE_FIRST_SECTION(ctx->nt);
    ctx->numSections = ctx->nt->FileHeader.NumberOfSections;

    return 0;
}

void PE_Free(PE_CONTEXT* ctx) {
    if (ctx->data) {
        free(ctx->data);
        ctx->data = NULL;
    }
    memset(ctx, 0, sizeof(PE_CONTEXT));
}

DWORD PE_Align(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

DWORD PE_GetImageBase(PE_CONTEXT* ctx) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        return (DWORD)nt64->OptionalHeader.ImageBase;
    }
    return ctx->nt->OptionalHeader.ImageBase;
}

DWORD PE_GetEntryPoint(PE_CONTEXT* ctx) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        return nt64->OptionalHeader.AddressOfEntryPoint;
    }
    return ctx->nt->OptionalHeader.AddressOfEntryPoint;
}

void PE_SetEntryPoint(PE_CONTEXT* ctx, DWORD rva) {
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.AddressOfEntryPoint = rva;
    } else {
        ctx->nt->OptionalHeader.AddressOfEntryPoint = rva;
    }
}

IMAGE_SECTION_HEADER* PE_GetLastSection(PE_CONTEXT* ctx) {
    if (ctx->numSections == 0) return NULL;
    return &ctx->sections[ctx->numSections - 1];
}

// Maximum number of sections we can add
#define MAX_SECTIONS 96

int PE_AddSection(PE_CONTEXT* ctx, const char* name, DWORD size, DWORD characteristics) {
    if (ctx->numSections >= MAX_SECTIONS) {
        printf("Error: Maximum sections reached (%d)\n", MAX_SECTIONS);
        return -1;
    }

    // Calculate header sizes based on PE bitness
    DWORD ntHeadersSize;
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ntHeadersSize = sizeof(IMAGE_NT_HEADERS64);
    } else {
        ntHeadersSize = sizeof(IMAGE_NT_HEADERS32);
    }

    // Check if there's space in the headers for another section
    IMAGE_SECTION_HEADER* headerEnd = (IMAGE_SECTION_HEADER*)((BYTE*)ctx->sections +
        (ctx->numSections + 1) * sizeof(IMAGE_SECTION_HEADER));
    DWORD headerEndOffset = (BYTE*)headerEnd - ctx->data;

    DWORD headersEnd = GetSizeOfHeaders(ctx);

    if (headerEndOffset > headersEnd) {
        printf("Error: Not enough space in headers for new section\n");
        printf("Header end offset: 0x%X, Headers end: 0x%X\n", headerEndOffset, headersEnd);
        return -1;
    }

    // Get alignments
    DWORD fileAlignment = GetFileAlignment(ctx);
    DWORD sectionAlignment = GetSectionAlignment(ctx);

    // Get last section to calculate offsets
    IMAGE_SECTION_HEADER* lastSection = PE_GetLastSection(ctx);

    DWORD newSectionRVA;
    DWORD newSectionFileOffset;
    DWORD lastSectionEnd;

    if (lastSection) {
        // New section starts after last section (aligned)
        DWORD lastSectionEndRVA = lastSection->VirtualAddress + lastSection->Misc.VirtualSize;
        newSectionRVA = PE_Align(lastSectionEndRVA, sectionAlignment);

        lastSectionEnd = lastSection->PointerToRawData + lastSection->SizeOfRawData;
        newSectionFileOffset = PE_Align(lastSectionEnd, fileAlignment);
    } else {
        // First section (shouldn't happen for valid PE)
        newSectionRVA = sectionAlignment;
        newSectionFileOffset = PE_Align(GetSizeOfHeaders(ctx), fileAlignment);
        lastSectionEnd = GetSizeOfHeaders(ctx);
    }

    // Calculate new section size
    DWORD newSectionFileSize = PE_Align(size, fileAlignment);
    DWORD newSize = newSectionFileOffset + newSectionFileSize;

    // Reallocate buffer
    BYTE* newData = (BYTE*)realloc(ctx->data, newSize);
    if (!newData) {
        printf("Error: Cannot reallocate memory\n");
        return -1;
    }

    // Update pointers after realloc
    ctx->data = newData;
    ctx->dos = (IMAGE_DOS_HEADER*)ctx->data;
    ctx->nt = (IMAGE_NT_HEADERS*)(ctx->data + ctx->dos->e_lfanew);
    ctx->sections = IMAGE_FIRST_SECTION(ctx->nt);

    // Fill gap between last section and new section with zeros
    if (lastSectionEnd < newSectionFileOffset) {
        memset(ctx->data + lastSectionEnd, 0, newSectionFileOffset - lastSectionEnd);
    }

    // Initialize new section with zeros
    memset(ctx->data + newSectionFileOffset, 0, newSectionFileSize);

    // Setup new section header
    IMAGE_SECTION_HEADER* newSection = &ctx->sections[ctx->numSections];
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));

    // Copy name (max 8 chars)
    strncpy((char*)newSection->Name, name, 8);
    newSection->VirtualAddress = newSectionRVA;
    newSection->Misc.VirtualSize = size;
    newSection->SizeOfRawData = newSectionFileSize;
    newSection->PointerToRawData = newSectionFileOffset;
    newSection->Characteristics = characteristics;

    // Update PE headers
    ctx->nt->FileHeader.NumberOfSections++;
    ctx->numSections++;

    // Update size of image
    SetSizeOfImage(ctx, PE_Align(newSectionRVA + size, sectionAlignment));

    // Update size of initialized data if applicable
    if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        AddToSizeOfInitializedData(ctx, newSectionFileSize);
    }

    // Update size of code if applicable
    if (characteristics & IMAGE_SCN_CNT_CODE) {
        AddToSizeOfCode(ctx, newSectionFileSize);
    }

    ctx->size = newSize;

    return 0;
}

void PE_CalcChecksum(PE_CONTEXT* ctx) {
    // Checksum calculation is complex for PE files
    // For now, just set to 0 (Windows loader ignores it for most files)
    if (ctx->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt;
        nt64->OptionalHeader.CheckSum = 0;
    } else {
        ctx->nt->OptionalHeader.CheckSum = 0;
    }
}

int PE_Save(PE_CONTEXT* ctx, const char* filename) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        printf("Error: Cannot create file %s\n", filename);
        return -1;
    }

    size_t written = fwrite(ctx->data, 1, ctx->size, f);
    fclose(f);

    if (written != ctx->size) {
        printf("Error: Failed to write complete file\n");
        return -1;
    }

    return 0;
}
