        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)

;       include C libraries
        includelib      msvcrtd
        includelib      oldnames
        includelib      kernel32
        includelib      legacy_stdio_definitions.lib    ;for scanf, printf, ...

        .data                   ;initialized data
message     db      "drgat test 1 32 bit",0dh,0ah,0
message_end db 0
        .data?                  ;uinitialized data
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 
       ; extrn   printf:near

        GetStdHandle PROTO STDCALL :DWORD
        ExitProcess PROTO STDCALL :DWORD
        
        WriteFile proto,                  
            hFile:dword, lpBuffer:near32,      ;A handle to the device
            nNumberOfCharsToWrite:dword,       ;The maximum number of bytes to be written.
            lpNumberOfbytesWritten:near32,     ;A pointer to the variable that receives the number of bytes written
            lpOverlapped:near32 

        public  main

main:    

        ;basic blocks 0-2
	    ;sequential nodes 0-2
        mov     ebp, esp
        sub     esp, 4	
        push    -11
        call   GetStdHandle ;call node 3 + jump node 4 + external node 5
	
	    ;basic blocks 3-6
	    ;sequential nodes 6-12
        mov     ebx, eax    
        push    0
        lea     eax, [ebp-4]
        push    eax
        push    (message_end - message)
        push    offset  message
        push    ebx
        call    writefile ;call node 13 + jump node 14 + external node 15

        ;basic blocks 7-9
	    ;sequential node 16
        push    0
        call    ExitProcess ;call node 17 + jump node 18 + external node 19 [20th node, connected by 19th edge]

        ; never here
        hlt



end main

        end