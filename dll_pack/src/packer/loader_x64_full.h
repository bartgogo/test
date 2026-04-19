// Simple x64 Shellcode - Jump only
// This is the simplest possible loader that just jumps to the original EP

#ifndef X64_LOADER_FULL_H
#define X64_LOADER_FULL_H

#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Simple x64 shellcode: mov rax, addr; jmp rax
// Size: 12 bytes
static unsigned char* CreateShellcode(
    ULONGLONG originalEP,
    DWORD appid,
    DWORD dllSize,
    ULONGLONG imageBase,
    size_t* outSize
) {
    *outSize = 12;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    ULONGLONG targetAddr = originalEP + imageBase;

    // mov rax, imm64
    sc[0] = 0x48;
    sc[1] = 0xB8;
    *(ULONGLONG*)(sc + 2) = targetAddr;

    // jmp rax
    sc[10] = 0xFF;
    sc[11] = 0xE0;

    return sc;
}

// Simple jump shellcode for x86
static unsigned char* CreateJumpShellcode32(DWORD targetAddress, size_t* outSize) {
    *outSize = 7;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    sc[0] = 0xB8;                       // mov eax, imm32
    *(DWORD*)(sc + 1) = targetAddress;
    sc[5] = 0xFF;                       // jmp eax
    sc[6] = 0xE0;

    return sc;
}

#endif // X64_LOADER_FULL_H
