        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)
		        .data                   ;initialized data
message     db      "delmefff",0dh,0ah,0
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
	mov ecx, 100 
	mov esi, ecx

	push -12

	;block 6
	;this tests how api calls are handled inside a deinstrumented loop
loop1:
	mov eax, 20 ;node 3
	mov ebx, 10
	xchg eax, ebx

	push    -11
    call   GetStdHandle ;7,8.  block 1 is the thunk here
	
	;block 2
	;
    mov     ebx, eax    ;9 
    push    0
    lea     eax, [ebp-4] ;11
    push    eax
    push    (message_end - message)
    push    offset  message
    push    ebx ;15
    call    writefile ;16,17      block 3 is the thunk here

	;block 4
	mov ecx, esi
	dec ecx
	mov esi, ecx
	jnz loop1 ;node 5, [->1 (x99), ->6 (x1)]
	
	call GetStdHandle ;block 5

	;block 7
	; exec count now 501
	mov ecx, 1000 ;node 6
	push ecx
	
	jmp loop2

	;block 8
	; exec count now 503
	;node 8-12, execs 1000 times
	;test how api calls are handled at the base of a deinstrumented loop
loop2:

	pop ecx
	dec ecx
	jz loop2end ;node 12, [->8 (x999), ->13 (x1)]       


	;block 9
	mov eax, 20 
	mov ebx, 10
	xchg eax, ebx
	
	push ecx
	push 1
	call GetStdHandle ;block 10 in here 

	jmp loop2        
	
loop2end:
	; exec count now 5503
	mov ecx, 10000
	push ecx
	push 2
	jmp loop3


	
	; exec count now 5505
	;node 15-19, execs 10000 times
	; this tests how api calls are handed at the top of a deinstrumented loop
loop3:
	call GetStdHandle 
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	pop ecx
	dec ecx
	push ecx
	
	push 2
	jnz loop3  ;node 19 [->15 (x9999), ->20 (x1)]  
	
	pop eax
	; exec count now 55505
	mov ecx, 100000
	jmp loop4


	
	; exec count now 55507
	;node 22-26, execs 100000 times
loop4:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop4    ;node 24 [->22 (x99999), ->27 (x1)]  
	
	; exec count now 55507
	mov ecx, 10000000
	jmp loop5


	; exec count now 555509
	;node 29-33, execs 10000000 times
loop5:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop5    ;node 33 [->29 (x999999), ->34 (x1)]  
	
	; exec count now 50555509
	; block ID 11
	inc ecx  ;node 34
	inc ecx  ;node 35
	inc ecx  ;node 36
	inc ecx  ;node 37
	jmp final  ;node 38

	;these should not execute or appear on the graph
	inc esi    
	inc esi
	inc esi
	inc esi
	
	; exec count now 50555514
final:

	xor   ecx, ecx		
	ret    ;node 40 - ret to basethreadinitthunk
	
	; exec count now 50,555,516


end main

        end