; loader.asm - x86 position-independent loader shellcode
; This code is designed to be embedded in a PE file and will:
; 1. Find kernel32.dll base address
; 2. Resolve required API functions
; 3. Read overlay data from end of file
; 4. Write embedded DLL to temp file
; 5. Load the DLL
; 6. Call Validate function
; 7. Jump to original entry point or exit

BITS 32

; Structure definitions
struc OVERLAY_CONFIG
    .magic          resd 1  ; 0x5041434B "PACK"
    .appid          resd 1  ; Application ID
    .dll_size       resd 1  ; DLL file size
    .original_ep    resd 1  ; Original entry point RVA
    .image_base     resd 1  ; Image base address
endstruc

; Constants
OVERLAY_MAGIC    equ 0x5041434B
MEM_COMMIT       equ 0x1000
MEM_RESERVE      equ 0x2000
PAGE_READWRITE   equ 0x04
PAGE_EXECUTE_READWRITE equ 0x40
GENERIC_READ     equ 0x80000000
GENERIC_WRITE    equ 0x40000000
FILE_SHARE_READ  equ 0x01
OPEN_EXISTING    equ 3
CREATE_ALWAYS    equ 2
FILE_END         equ 2

; ============================================
; Entry point - execution starts here
; ============================================
global _start

_start:
    ; Save all registers
    pushad

    ; Get current location (call/pop technique)
    call get_eip
get_eip:
    pop esi                     ; ESI = address of get_eip label

    ; Calculate offsets to data
    ; We'll store data at the end of shellcode

    ; ==========================================
    ; Find kernel32.dll base from PEB
    ; ==========================================
    mov eax, [fs:0x30]          ; PEB address
    mov eax, [eax + 0x0C]       ; PEB->Ldr
    mov eax, [eax + 0x0C]       ; Ldr->InLoadOrderModuleList.Flink

    ; Walk module list (exe, ntdll, kernel32)
    mov eax, [eax]              ; exe
    mov eax, [eax]              ; ntdll
    mov eax, [eax]              ; kernel32
    mov eax, [eax + 0x18]       ; kernel32 base

    mov edi, eax                ; EDI = kernel32 base
    push edi                    ; Save kernel32 base

    ; ==========================================
    ; Resolve LoadLibraryA
    ; ==========================================
    call get_loadlibrary
    db "LoadLibraryA", 0
get_loadlibrary:
    pop ebx                     ; EBX = "LoadLibraryA" string
    push ebx                    ; Function name
    push edi                    ; kernel32 base
    call resolve_api            ; Returns address in EAX
    mov [esi + offset_loadlibrary], eax

    ; ==========================================
    ; Resolve GetProcAddress
    ; ==========================================
    call get_getprocaddr
    db "GetProcAddress", 0
get_getprocaddr:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_getprocaddr], eax

    ; ==========================================
    ; Resolve GetModuleFileNameA
    ; ==========================================
    call get_getmodulefilename
    db "GetModuleFileNameA", 0
get_getmodulefilename:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_getmodulefilename], eax

    ; ==========================================
    ; Resolve CreateFileA
    ; ==========================================
    call get_createfile
    db "CreateFileA", 0
get_createfile:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_createfile], eax

    ; ==========================================
    ; Resolve ReadFile
    ; ==========================================
    call get_readfile
    db "ReadFile", 0
get_readfile:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_readfile], eax

    ; ==========================================
    ; Resolve WriteFile
    ; ==========================================
    call get_writefile
    db "WriteFile", 0
get_writefile:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_writefile], eax

    ; ==========================================
    ; Resolve CloseHandle
    ; ==========================================
    call get_closehandle
    db "CloseHandle", 0
get_closehandle:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_closehandle], eax

    ; ==========================================
    ; Resolve SetFilePointer
    ; ==========================================
    call get_setfilepointer
    db "SetFilePointer", 0
get_setfilepointer:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_setfilepointer], eax

    ; ==========================================
    ; Resolve VirtualAlloc
    ; ==========================================
    call get_virtualalloc
    db "VirtualAlloc", 0
get_virtualalloc:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_virtualalloc], eax

    ; ==========================================
    ; Resolve GetTempPathA
    ; ==========================================
    call get_gettemppath
    db "GetTempPathA", 0
get_gettemppath:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_gettemppath], eax

    ; ==========================================
    ; Resolve GetTempFileNameA
    ; ==========================================
    call get_gettempfilename
    db "GetTempFileNameA", 0
get_gettempfilename:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_gettempfilename], eax

    ; ==========================================
    ; Resolve DeleteFileA
    ; ==========================================
    call get_deletefile
    db "DeleteFileA", 0
get_deletefile:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_deletefile], eax

    ; ==========================================
    ; Resolve ExitProcess
    ; ==========================================
    call get_exitprocess
    db "ExitProcess", 0
get_exitprocess:
    pop ebx
    push ebx
    push edi
    call resolve_api
    mov [esi + offset_exitprocess], eax

    pop edi                     ; Restore kernel32 base

    ; ==========================================
    ; Get our module file name
    ; ==========================================
    push 260                    ; MAX_PATH
    lea ebx, [esi + exe_path]
    push ebx
    push 0                      ; NULL = current module
    call [esi + offset_getmodulefilename]

    ; ==========================================
    ; Open our file to read overlay
    ; ==========================================
    push 0                      ; hTemplateFile
    push 0                      ; dwFlagsAndAttributes
    push OPEN_EXISTING          ; dwCreationDisposition
    push 0                      ; lpSecurityAttributes
    push FILE_SHARE_READ        ; dwShareMode
    push GENERIC_READ           ; dwDesiredAccess
    lea ebx, [esi + exe_path]
    push ebx                    ; lpFileName
    call [esi + offset_createfile]
    mov [esi + h_file], eax

    ; Check if file opened successfully
    cmp eax, -1                 ; INVALID_HANDLE_VALUE
    je exit_error

    ; ==========================================
    ; Read overlay config from end of file
    ; ==========================================
    push FILE_END               ; dwMoveMethod
    push 0                      ; lpDistanceToMoveHigh
    push -20                    ; lDistanceToMove (size of OVERLAY_CONFIG)
    push eax                    ; hFile
    call [esi + offset_setfilepointer]

    lea ebx, [esi + overlay_config]
    push 0                      ; lpOverlapped
    lea ecx, [esi + bytes_read]
    push ecx                    ; lpNumberOfBytesRead
    push 20                     ; nNumberOfBytesToRead
    push ebx                    ; lpBuffer
    push [esi + h_file]         ; hFile
    call [esi + offset_readfile]

    ; Verify magic
    mov eax, [esi + overlay_config + OVERLAY_CONFIG.magic]
    cmp eax, OVERLAY_MAGIC
    jne exit_error

    ; ==========================================
    ; Read DLL from overlay
    ; ==========================================
    ; Calculate position: -(dll_size + config_size)
    mov eax, [esi + overlay_config + OVERLAY_CONFIG.dll_size]
    add eax, 20                 ; config size
    neg eax                     ; negative

    push FILE_END
    push 0
    push eax
    push [esi + h_file]
    call [esi + offset_setfilepointer]

    ; Allocate memory for DLL
    push PAGE_READWRITE
    push MEM_COMMIT | MEM_RESERVE
    push [esi + overlay_config + OVERLAY_CONFIG.dll_size]
    push 0
    call [esi + offset_virtualalloc]
    mov [esi + dll_buffer], eax

    ; Read DLL
    push 0
    lea ebx, [esi + bytes_read]
    push ebx
    push [esi + overlay_config + OVERLAY_CONFIG.dll_size]
    push eax
    push [esi + h_file]
    call [esi + offset_readfile]

    ; Close file
    push [esi + h_file]
    call [esi + offset_closehandle]

    ; ==========================================
    ; Write DLL to temp file
    ; ==========================================
    ; Get temp path
    push 260
    lea ebx, [esi + temp_path]
    push ebx
    call [esi + offset_gettemppath]

    ; Get temp file name
    push 0                      ; lpTempFileName
    push 0                      ; dwUnique
    lea ebx, [esi + temp_prefix]
    push ebx                    ; lpPrefixString
    lea ebx, [esi + temp_path]
    push ebx                    ; lpPathName
    lea ebx, [esi + temp_file]
    push ebx                    ; lpTempFileName
    call [esi + offset_gettempfilename]

    ; Create temp file
    push 0
    push 0
    push CREATE_ALWAYS
    push 0
    push 0
    push GENERIC_WRITE
    lea ebx, [esi + temp_file]
    push ebx
    call [esi + offset_createfile]
    mov [esi + h_tempfile], eax

    ; Write DLL to temp file
    push 0
    lea ebx, [esi + bytes_written]
    push ebx
    push [esi + overlay_config + OVERLAY_CONFIG.dll_size]
    push [esi + dll_buffer]
    push eax
    call [esi + offset_writefile]

    ; Close temp file
    push [esi + h_tempfile]
    call [esi + offset_closehandle]

    ; ==========================================
    ; Load DLL
    ; ==========================================
    lea ebx, [esi + temp_file]
    push ebx
    call [esi + offset_loadlibrary]
    mov [esi + h_dll], eax

    test eax, eax
    jz exit_error

    ; ==========================================
    ; Get Validate function
    ; ==========================================
    call get_validate_name
    db "Validate", 0
get_validate_name:
    pop ebx
    push ebx                    ; "Validate"
    push eax                    ; hDll
    call [esi + offset_getprocaddr]
    mov [esi + p_validate], eax

    test eax, eax
    jz exit_error

    ; ==========================================
    ; Call Validate(appid)
    ; ==========================================
    push [esi + overlay_config + OVERLAY_CONFIG.appid]
    call eax

    test eax, eax
    jz exit_validation_failed

    ; ==========================================
    ; Validation passed - clean up and jump
    ; ==========================================
    ; Delete temp file
    lea ebx, [esi + temp_file]
    push ebx
    call [esi + offset_deletefile]

    ; Restore registers
    popad

    ; Jump to original entry point
    mov eax, [esi + overlay_config + OVERLAY_CONFIG.image_base]
    add eax, [esi + overlay_config + OVERLAY_CONFIG.original_ep]
    jmp eax

exit_validation_failed:
    ; Validation failed
    lea ebx, [esi + temp_file]
    push ebx
    call [esi + offset_deletefile]

    push 1
    call [esi + offset_exitprocess]

exit_error:
    popad
    push 1
    ; Find ExitProcess if we haven't resolved it
    jmp $

; ==========================================
; Function: resolve_api
; Resolves API by name from module
; Input: module base in [esp+4], name in [esp+8]
; Output: address in EAX
; ==========================================
resolve_api:
    push ebp
    mov ebp, esp
    push ebx, ecx, edx, esi, edi

    mov edi, [ebp + 8]          ; module base
    mov ebx, [ebp + 12]         ; function name

    ; Get export directory
    mov eax, [edi + 0x3C]       ; e_lfanew
    add eax, edi
    mov eax, [eax + 0x78]       ; Export Dir RVA
    add eax, edi                ; Export Dir VA

    ; Get table addresses
    mov ecx, [eax + 0x20]       ; AddressOfNames RVA
    add ecx, edi                ; AddressOfNames VA
    mov edx, [eax + 0x24]       ; AddressOfNameOrdinals RVA
    add edx, edi
    mov esi, [eax + 0x1C]       ; AddressOfFunctions RVA
    add esi, edi
    mov ebp, [eax + 0x18]       ; NumberOfNames

    xor eax, eax                ; counter

.search_loop:
    mov edi, [ecx + eax * 4]    ; Name RVA
    add edi, [ebp - 28]         ; module base (on stack)

    ; Compare names
    push eax, ecx
    mov esi, ebx                ; target name
.compare_loop:
    mov al, [edi]
    mov cl, [esi]
    cmp al, cl
    jne .name_mismatch
    test al, al
    jz .name_found
    inc edi
    inc esi
    jmp .compare_loop

.name_mismatch:
    pop ecx, eax
    inc eax
    cmp eax, ebp
    jl .search_loop
    jmp .not_found

.name_found:
    pop ecx, eax
    ; Get ordinal
    movzx eax, word [edx + eax * 2]
    ; Get function address
    mov eax, [esi + eax * 4]
    add eax, [ebp - 28]
    jmp .done

.not_found:
    xor eax, eax

.done:
    pop edi, esi, edx, ecx, ebx
    pop ebp
    ret 8

; ==========================================
; Data section (patched at pack time)
; ==========================================

; Offsets (relative to shellcode start)
offset_loadlibrary     equ 0
offset_getprocaddr     equ 4
offset_getmodulefilename equ 8
offset_createfile      equ 12
offset_readfile        equ 16
offset_writefile       equ 20
offset_closehandle     equ 24
offset_setfilepointer  equ 28
offset_virtualalloc    equ 32
offset_gettemppath     equ 36
offset_gettempfilename equ 40
offset_deletefile      equ 44
offset_exitprocess     equ 48

; Variables
exe_path:
    times 260 db 0
temp_path:
    times 260 db 0
temp_file:
    times 260 db 0
temp_prefix:
    db "val", 0

h_file:
    dd 0
h_tempfile:
    dd 0
dll_buffer:
    dd 0
h_dll:
    dd 0
p_validate:
    dd 0
bytes_read:
    dd 0
bytes_written:
    dd 0

overlay_config:
    istruc OVERLAY_CONFIG
        at OVERLAY_CONFIG.magic, dd 0
        at OVERLAY_CONFIG.appid, dd 0
        at OVERLAY_CONFIG.dll_size, dd 0
        at OVERLAY_CONFIG.original_ep, dd 0
        at OVERLAY_CONFIG.image_base, dd 0
    iend

; End of shellcode
