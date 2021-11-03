        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)
		.data                   ;initialized data
message     db      "teststring",0dh,0ah,0
message_end db 0
        .data?         
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 


		        GetStdHandle PROTO STDCALL :DWORD
        ExitProcess PROTO STDCALL :DWORD
        
        WriteFile proto,  hFile:dword, lpBuffer:near32,      ;A handle to the device
            nNumberOfCharsToWrite:dword,       ;The maximum number of bytes to be written.
            lpNumberOfbytesWritten:near32,     ;A pointer to the variable that receives the number of bytes written
            lpOverlapped:near32 

        public  main
		
        includelib      msvcrtd
        includelib      oldnames
        includelib      kernel32
        includelib      legacy_stdio_definitions.lib    ;for scanf, printf, ...
main:    

	; exec count now 0
	; block 0, node 0, execs once
	mov ecx, 5

	; exec count now 1
	;block 1, nodes 1-5, execs 100 times 
loop1:
	mov eax, 20 ;node 1
	mov ebx, 10
	xchg eax, ebx

	dec ecx
	jnz loop1 ;node 5, [->1 (x99), ->6 (x1)]
	
reptest:
    mov ecx, 5
    lea esi, [message+5]
    lea edi, [message+6]
    rep movsb
    
    ; https://trello.com/c/I89DMjjh/160-repxx-handling-with-ecx-0
    ; this is currently recorded as executing once, (same as ecx=1 && fail on first char)
    ; the 'rep' is evaluated and the 'movsb' is noot
    ; i'm not sure if this is exactly the best behaviour as with ecx=0 it doesnt actually execute
    ; but i do want it to actually be displayed that it exists.
    ; could do a special case where we grey out the prefixed instruction or something but exact exec counts like this are going out of scope
    mov ecx, 0
    lea esi, [message+5]
    lea edi, [message+6]
    rep movsb


    mov ecx, 5
    lea edi, [message]
    mov al, 't'
    repne scasb
    
    mov ecx, 5
    lea edi, [message]
    mov al, 'z'
    repne scasb

    mov ecx, 5
    lea edi, [message]
    mov al, 't'
    repe scasb
    
    mov ecx, 5
    lea edi, [message]
    mov al, 'z'
    repe scasb
    
    mov ecx, 5
    lea edi, [message]
    mov al, 't'
    repz scasb
    
    mov ecx, 5
    lea edi, [message]
    mov al, 'z'
    repnz scasb


	
cpuidtest:
    mov eax, 0
    cpuid
    mov eax, 0
    rdtsc
    mov eax, 0


    

final:

    push    0
    call    ExitProcess 
	
	; exec count now 50,555,516


end main

        end