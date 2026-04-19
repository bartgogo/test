// shellcode_generator.c - Generates x64 position-independent shellcode
// Compile and run this to generate shellcode bytes
// Then embed the bytes into the packer

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Overlay structure
#pragma pack(push, 1)
typedef struct {
    DWORD magic;
    DWORD appid;
    DWORD dll_size;
    DWORD original_ep_rva;
    ULONGLONG image_base;
} OVERLAY_CONFIG;
#pragma pack(pop)

#define OVERLAY_MAGIC 0x5041434B

// This function will be compiled and its bytes extracted as shellcode
// It performs:
// 1. Get kernel32 base
// 2. Resolve APIs
// 3. Read overlay
// 4. Load DLL and validate
// 5. Jump to original EP or exit

// The shellcode entry point
// This must be position-independent code
void __declspec(naked) ShellcodeEntry(void) {
    __asm {
        // === PROLOGUE ===
        // Save non-volatile registers
        push rbx
        push rbp
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        sub rsp, 0x100         // Local variable space
        mov rbp, rsp

        // === GET CURRENT LOCATION ===
        call get_eip
get_eip:
        pop rsi                 // rsi = address of get_eip label
        sub rsi, 5              // Adjust to start of our data

        // rsi now points to start of shellcode
        // Data at [rsi+0]: original EP (8 bytes)
        // Data at [rsi+8]: appid (4 bytes)
        // Data at [rsi+12]: dll_size (4 bytes)
        // Data at [rsi+16]: image_base (8 bytes)

        // === GET KERNEL32 BASE FROM PEB ===
        mov rax, gs:[0x60]      // PEB
        mov rax, [rax+0x18]     // Ldr
        mov rax, [rax+0x20]     // InMemoryOrderModuleList
        mov rax, [rax]          // exe
        mov rax, [rax]          // ntdll
        mov rax, [rax]          // kernel32
        mov rax, [rax+0x20]     // DllBase
        mov r15, rax            // r15 = kernel32 base

        // === GET EXPORT DIRECTORY ===
        movsxd rax, dword ptr [r15+0x3C]   // e_lfanew
        add rax, r15                        // NT headers
        mov eax, [rax+0x88]                 // Export Dir RVA
        test eax, eax
        jz error_exit
        add rax, r15                        // Export Dir VA
        mov r14, rax                        // r14 = Export Dir

        // === RESOLVE LoadLibraryA ===
        // We search for "LoadLibraryA" in exports
        mov rbx, [r14+0x20]     // AddressOfNames RVA
        add rbx, r15            // VA
        mov r8, rbx             // r8 = names

        mov rcx, [r14+0x24]     // AddressOfNameOrdinals RVA
        add rcx, r15            // VA
        mov r9, rcx             // r9 = ordinals

        mov rdx, [r14+0x1C]     // AddressOfFunctions RVA
        add rdx, r15            // VA
        mov r10, rdx            // r10 = functions

        mov r11d, [r14+0x18]    // NumberOfNames
        xor ecx, ecx            // counter = 0

search_loadlibrary:
        mov eax, [r8+rcx*4]     // Name RVA
        add rax, r15            // Name VA
        cmp dword ptr [rax], 'daoL'     // "Load"
        jne next_name1
        cmp dword ptr [rax+4], 'rbiL'   // "Libr"
        jne next_name1
        cmp word ptr [rax+8], 'yr'      // "ry"
        jne next_name1
        cmp byte ptr [rax+10], 'A'      // "A"
        je found_loadlibrary

next_name1:
        inc ecx
        cmp ecx, r11d
        jl search_loadlibrary
        jmp error_exit

found_loadlibrary:
        movzx eax, word ptr [r9+rcx*2]  // ordinal
        mov eax, [r10+rax*4]             // Function RVA
        add rax, r15                     // Function VA
        mov [rbp+0x08], rax              // Save LoadLibraryA

        // === RESOLVE GetProcAddress ===
        xor ecx, ecx

search_getprocaddr:
        mov eax, [r8+rcx*4]
        add rax, r15
        cmp dword ptr [rax], 'PteG'      // "GetP"
        jne next_name2
        cmp dword ptr [rax+4], 'Acor'    // "rocA"
        jne next_name2
        cmp dword ptr [rax+8], 'sSerdd'  // "ddrA"
        jne next_name2
        cmp word ptr [rax+12], 'ss'      // "ss"
        je found_getprocaddr

next_name2:
        inc ecx
        cmp ecx, r11d
        jl search_getprocaddr
        jmp error_exit

found_getprocaddr:
        movzx eax, word ptr [r9+rcx*2]
        mov eax, [r10+rax*4]
        add rax, r15
        mov [rbp+0x10], rax              // Save GetProcAddress

        // === RESOLVE ExitProcess ===
        xor ecx, ecx

search_exitprocess:
        mov eax, [r8+rcx*4]
        add rax, r15
        cmp dword ptr [rax], 'tixE'      // "Exit"
        jne next_name3
        cmp dword ptr [rax+4], 'ssecorP' // "Procs"
        je found_exitprocess

next_name3:
        inc ecx
        cmp ecx, r11d
        jl search_exitprocess
        jmp error_exit

found_exitprocess:
        movzx eax, word ptr [r9+rcx*2]
        mov eax, [r10+rax*4]
        add rax, r15
        mov [rbp+0x18], rax              // Save ExitProcess

        // === GET MODULE FILENAME ===
        // Need to resolve GetModuleFileNameA
        xor ecx, ecx

search_getmodulefilename:
        mov eax, [r8+rcx*4]
        add rax, r15
        cmp dword ptr [rax], 'MteG'      // "GetM"
        jne next_name4
        cmp dword ptr [rax+4], 'ludo'    // "odul"
        jne next_name4
        cmp dword ptr [rax+8], 'NeliF'   // "FileN"
        je found_getmodulefilename

next_name4:
        inc ecx
        cmp ecx, r11d
        jl search_getmodulefilename
        jmp error_exit

found_getmodulefilename:
        movzx eax, word ptr [r9+rcx*2]
        mov eax, [r10+rax*4]
        add rax, r15
        mov [rbp+0x20], rax              // Save GetModuleFileNameA

        // === GET CURRENT EXE PATH ===
        // Call GetModuleFileNameA(NULL, buffer, MAX_PATH)
        // Buffer at [rbp+0x30] (260 bytes)
        mov rcx, 0                       // hModule = NULL
        lea rdx, [rbp+0x30]              // buffer
        mov r8, 260                      // MAX_PATH
        call [rbp+0x20]                  // GetModuleFileNameA

        // === OPEN FILE TO READ OVERLAY ===
        // Need CreateFileA, ReadFile, SetFilePointer, CloseHandle
        // ... (simplified for now)

        // === FOR NOW: JUST JUMP TO ORIGINAL EP ===
        // This is the pass-through version

        // Restore stack and registers
        add rsp, 0x100
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbp
        pop rbx

        // Load original EP from data section
        mov rax, [rsi]        // Original EP (first 8 bytes of data)
        jmp rax

error_exit:
        // Exit with error code 1
        mov rcx, 1
        call [rbp+0x18]       // ExitProcess
    }
}

// Extract shellcode bytes from the compiled function
void ExtractShellcode(void) {
    printf("Extracting shellcode bytes...\n\n");

    // Find the function boundaries
    unsigned char* start = (unsigned char*)ShellcodeEntry;

    // We need to find the end - this is tricky
    // For now, just print the first 512 bytes
    printf("unsigned char SHELLCODE[] = {\n");
    for (int i = 0; i < 512; i++) {
        if (i % 16 == 0) printf("    ");
        printf("0x%02X", start[i]);
        if (i < 511) printf(", ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n};\n");
}

int main(void) {
    printf("Shellcode Generator\n");
    printf("===================\n\n");

    // The actual shellcode generation would require
    // disassembling the ShellcodeEntry function
    // This is complex and tool-dependent

    printf("To generate proper shellcode:\n");
    printf("1. Compile this file\n");
    printf("2. Use a disassembler or debugger to extract the bytes\n");
    printf("3. Or use a tool like 'objdump -d' to get the assembly\n\n");

    printf("Alternative: Use pre-assembled shellcode from loader.asm\n");

    return 0;
}
