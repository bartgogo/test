// Simple x64 Shellcode - Jump only
// This is the simplest possible loader that just jumps to the original EP

#ifndef X64_LOADER_FULL_H
#define X64_LOADER_FULL_H

#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Simple x64 shellcode: mov rax, addr; jmp rax
// Size: 33 bytes
static unsigned char* CreateShellcode(
    ULONGLONG originalEP,
    DWORD appid,
    ULONGLONG imageBase,
    size_t* outSize
) {
    *outSize = 33;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    ULONGLONG targetAddr = originalEP + imageBase;

    // mov eax, appid
    sc[0] = 0xB8;
    *(DWORD*)(sc + 1) = appid;
    // cmp eax, 100
    sc[5] = 0x3D;
    *(DWORD*)(sc + 6) = 100;
    // jb fail
    sc[10] = 0x72;
    sc[11] = 0x13;
    // cmp eax, 1000
    sc[12] = 0x3D;
    *(DWORD*)(sc + 13) = 1000;
    // ja fail
    sc[17] = 0x77;
    sc[18] = 0x0C;
    // mov rax, target
    sc[19] = 0x48;
    sc[20] = 0xB8;
    *(ULONGLONG*)(sc + 21) = targetAddr;
    // jmp rax
    sc[29] = 0xFF;
    sc[30] = 0xE0;
    // fail: ud2 (invalid opcode, terminate execution path)
    sc[31] = 0x0F;
    sc[32] = 0x0B;

    return sc;
}

// Simple jump shellcode for x86
static unsigned char* CreateJumpShellcode32(DWORD targetAddress, DWORD appid, size_t* outSize) {
    *outSize = 28;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    sc[0] = 0xB8;                       // mov eax, appid
    *(DWORD*)(sc + 1) = appid;
    sc[5] = 0x3D;                       // cmp eax, 100
    *(DWORD*)(sc + 6) = 100;
    sc[10] = 0x72;                      // jb fail
    sc[11] = 0x0E;
    sc[12] = 0x3D;                      // cmp eax, 1000
    *(DWORD*)(sc + 13) = 1000;
    sc[17] = 0x77;                      // ja fail
    sc[18] = 0x07;
    sc[19] = 0xB8;                      // mov eax, target
    *(DWORD*)(sc + 20) = targetAddress;
    sc[24] = 0xFF;                      // jmp eax
    sc[25] = 0xE0;
    sc[26] = 0x0F;                      // fail: ud2
    sc[27] = 0x0B;

    return sc;
}

#endif // X64_LOADER_FULL_H
