#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// PE file context
typedef struct {
    BYTE* data;           // Raw file data
    size_t size;          // File size
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sections;
    WORD numSections;
} PE_CONTEXT;

// Initialize PE context from file
int PE_Init(PE_CONTEXT* ctx, const char* filename);

// Free PE context
void PE_Free(PE_CONTEXT* ctx);

// Add a new section to PE
int PE_AddSection(PE_CONTEXT* ctx, const char* name, DWORD size, DWORD characteristics);

// Recalculate PE checksum
void PE_CalcChecksum(PE_CONTEXT* ctx);

// Save PE to file
int PE_Save(PE_CONTEXT* ctx, const char* filename);

// Get original entry point RVA
DWORD PE_GetEntryPoint(PE_CONTEXT* ctx);

// Set entry point RVA
void PE_SetEntryPoint(PE_CONTEXT* ctx, DWORD rva);

// Get image base
DWORD PE_GetImageBase(PE_CONTEXT* ctx);

// Align value to alignment
DWORD PE_Align(DWORD value, DWORD alignment);

// Get last section
IMAGE_SECTION_HEADER* PE_GetLastSection(PE_CONTEXT* ctx);

#ifdef __cplusplus
}
#endif

#endif // PE_PARSER_H
