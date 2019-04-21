format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

struct PROCESSENTRY32
       dwSize                  dd ?
       cntUsage                dd ?
       th32ProcessID           dd ?
       th32DefaultHeapID       dd ?
       th32ModuleID            dd ?
       cntThreads              dd ?
       th32ParentProcessID     dd ?
       pcPriClassBase          dd ?
       dwFlags                 dd ?
       szExeFile               rb MAX_PATH
ends

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 3
    je inject
    cinvoke printf, <'Wrong amount of Command line arguments!', 0>
    retn

inject:
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    cinvoke strlen, dllPath
    inc eax
    mov [dllPathLength], eax
    mov esi, [argv]
    invoke CreateToolhelp32Snapshot, 0x2, 0
    mov [snapshot], eax
    mov [processEntry.dwSize], sizeof.PROCESSENTRY32
    invoke Process32First, [snapshot], processEntry
    cmp eax, 1
    jne error
    loop1:
        invoke Process32Next, [snapshot], processEntry
        cmp eax, 1
        jne error
        mov esi, [argv]
        cinvoke strcmp, dword [esi + 4], processEntry.szExeFile
        test eax, eax
        jnz loop1

    invoke CloseHandle, [snapshot]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, [processEntry.th32ProcessID]
    mov [processHandle], eax
    invoke VirtualAllocEx, [processHandle], NULL, dllPathLength, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], eax
    invoke WriteProcessMemory, [processHandle], [allocatedMemory], dllPath, [dllPathLength], NULL
    invoke CreateRemoteThread, [processHandle], NULL, 0, [LoadLibraryA], [allocatedMemory], 0, NULL
    invoke WaitForSingleObject, eax, 0xFFFFFFFF
    invoke VirtualFreeEx, [processHandle], [allocatedMemory], dllPathLength, MEM_RELEASE
    invoke CloseHandle, [processHandle]
    cinvoke printf, <'Succesfully injected!', 0>
    retn

error:
    cinvoke printf, <'Injection failed!', 0>
    retn

section '.bss' data readable writable

argc dd ?
argv dd ?
env dd ?
dllPath rb MAX_PATH
dllPathLength dd ?
processEntry PROCESSENTRY32 ?
snapshot dd ?
processHandle dd ?
allocatedMemory dd ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'

import kernel32, \
       GetFullPathNameA, 'GetFullPathNameA', \
       LoadLibraryA, 'LoadLibraryA', \
       OpenProcess, 'OpenProcess', \
       VirtualAllocEx, 'VirtualAllocEx', \
       VirtualFreeEx, 'VirtualFreeEx', \
       WriteProcessMemory, 'WriteProcessMemory', \
       CreateRemoteThread, 'CreateRemoteThread', \
       CloseHandle, 'CloseHandle', \
       WaitForSingleObject, 'WaitForSingleObject', \
       CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot', \
       Process32First, 'Process32First', \
       Process32Next, 'Process32Next'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       strlen, 'strlen', \
       strcmp, 'strcmp'
