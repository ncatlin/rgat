        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)

        .data                   ;initialized data
message1     db      "consoleprint long test message 1",0dh,0ah,0
message1_end db 0               
message2     db      "consoleprint short msg 2",0dh,0ah,0
message2_end db 0
        .data?                  ;uinitialized data
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 

        GetStdHandle PROTO STDCALL :DWORD
        ExitProcess PROTO STDCALL :DWORD
        
        WriteFile proto,                  
            hFile:dword, lpBuffer:near32,      ;A handle to the device
            nNumberOfCharsToWrite:dword,       ;The maximum number of bytes to be written.
            lpNumberOfbytesWritten:near32,     ;A pointer to the variable that receives the number of bytes written
            lpOverlapped:near32 

        public  main

main:    

        ;basic block 0
	    ;5x nodes [0-3 + extern]
        mov     ebp, esp
        sub     esp, 4	
        push    -11
        ;this is technically 2 instructions but the .idata thunk is ignored for layout readability
        ; it is 2 nodes, however - the call and the GetStdHandle extern
        call   GetStdHandle 
	

	    ;basic block 2 (the GetStdHandle .idata thunk is block 1)
	    ;9x nodes [5-12 + writefile]
        mov     ebx, eax    
        push    0
        lea     eax, [ebp-4]
        push    eax
        push    (message1_end - message1)
        push    offset  message1
        push    ebx
        call    Writefile

        ;basic block 4
        ; 3x nodes [14,15,GetStdHandle]
        push    -11
        call   GetStdHandle


        ;basic block 6
	    ;9x nodes [17-24 + writefile]
        mov     ebx, eax    
        push    0
        lea     eax, [ebp-4]
        push    eax
        push    (message2_end - message2)
        push    offset  message2
        push    ebx
        call    Writefile


        ;basic blocks 8
	    ;3x nodes [26,27, exitprocess]
        push    0
        call    ExitProcess 

        ;stats 
        ; 29 nodes (including node 0)
        ; 28 edges
        ; 0 exceptions
        ; 5 seperate external nodes
        ; 24 instructions [29 nodes - 5 externals]
        ;   29 instructions would also be acceptable, as that would be counting the jmp dword ptr [xxxx] thunks
        

end main

        end