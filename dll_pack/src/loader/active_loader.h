// Active runtime loader stubs used by packer.
// Runtime chain: stub -> AppID policy validate -> original EP.

#ifndef ACTIVE_LOADER_H
#define ACTIVE_LOADER_H

#include <windows.h>
#include <stdlib.h>
#include <string.h>

// x64 validation-gate shellcode generator.
// Shellcode layout is immediate-instruction based: appId compare range check,
// then absolute jump to OEP. Runtime behavior is strict:
// - appId in [100,1000] => jump to original entry point
// - otherwise => execute ud2 and terminate current execution path
static unsigned char* CreateValidationGateShellcode64(
    ULONGLONG originalEP,
    DWORD appId,
    ULONGLONG imageBase,
    size_t* outSize
) {
    *outSize = 33;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    ULONGLONG targetAddr = originalEP + imageBase;

    // mov eax, appid
    sc[0] = 0xB8;
    *(DWORD*)(sc + 1) = appId;
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
    // fail: ud2 (invalid opcode -> raises undefined-instruction exception, typically terminating process)
    sc[31] = 0x0F;
    sc[32] = 0x0B;

    return sc;
}

// x86 validation-gate shellcode generator.
// Shellcode layout is immediate-instruction based: appId compare range check,
// then jump to OEP via EAX. Runtime behavior is strict:
// - appId in [100,1000] => jump to original entry point
// - otherwise => execute ud2 and terminate current execution path
static unsigned char* CreateValidationGateShellcode32(DWORD targetAddress, DWORD appId, size_t* outSize) {
    *outSize = 28;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    sc[0] = 0xB8;                       // mov eax, appid
    *(DWORD*)(sc + 1) = appId;
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
    sc[26] = 0x0F;                      // fail: ud2 (undefined instruction, process typically terminates)
    sc[27] = 0x0B;

    return sc;
}

// x64 compatibility fallback shellcode (no validation).
static unsigned char* CreateCompatJumpShellcode64(
    ULONGLONG originalEP,
    ULONGLONG imageBase,
    size_t* outSize
) {
    *outSize = 12;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    ULONGLONG targetAddr = originalEP + imageBase;
    sc[0] = 0x48;
    sc[1] = 0xB8; // mov rax, imm64
    *(ULONGLONG*)(sc + 2) = targetAddr;
    sc[10] = 0xFF; // jmp rax
    sc[11] = 0xE0;
    return sc;
}

// x86 compatibility fallback shellcode (no validation).
static unsigned char* CreateCompatJumpShellcode32(DWORD targetAddress, size_t* outSize) {
    *outSize = 7;
    unsigned char* sc = (unsigned char*)malloc(*outSize);
    if (!sc) return NULL;

    sc[0] = 0xB8; // mov eax, imm32
    *(DWORD*)(sc + 1) = targetAddress;
    sc[5] = 0xFF; // jmp eax
    sc[6] = 0xE0;
    return sc;
}

#endif // ACTIVE_LOADER_H
