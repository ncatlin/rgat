        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)

;       include C libraries

        .data                   ;initialized data

; This tests rgats ability to deal with instrumented -> uninstrumented -> instrumented 
; code transitions in a non-image buffer
;0:  31 c0                   xor    eax,eax
;2:  31 db                   xor    ebx,ebx
;4:  8b 44 24 04             mov    eax,DWORD PTR [esp+0x4]
;8:  53                      push   ebx
;9:  ff d0                   call   eax
;b:  89 c1                   mov    ecx,eax
;d:  31 d2                   xor    edx,edx
;f:  b8 23 01 00 00          mov    eax,0x123
;14: c3                      ret
test_code     db     31h,0C0h,31h,0DBh,8bh,44h,24h,04h,53h,0ffh,0d0h,89h,0C1h,31h,0D2h,0B8h,23h,01h,00h,00h,0C3h
test_code_end db 0
        .data?                  ;uinitialized data
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 
       ; extrn   printf:near

       VirtualAlloc proto,  lpAddress:dword, dwSize:dword,  flAllocationType:dword,  flProtect:near32 
       VirtualFree proto,  lpAddress:dword, dwSize:dword, dwFreeType:dword
       
        GetStdHandle PROTO STDCALL :DWORD
        ExitProcess PROTO STDCALL :DWORD

        
        public  main

main:    

        ;basic block 0
	    ;5x nodes [0-3 + extern]
        mov     ebp, esp
        sub     esp, 40	

        push    40h ; WRX
        push    1000h ; MEM_COMMIT
        push   1000h ; one page, please
        push    0 ; any address
        call   VirtualAlloc 
	
        push eax

	    lea esi, test_code
        mov edi, eax
        mov ecx,  (test_code_end - test_code)
        rep movsb

        push GetStdHandle
        call eax

        pop edx

        push 8000h ; release
        push 0 ; release => this must be 0
        push edx ;our buffer
        call VirtualFree

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