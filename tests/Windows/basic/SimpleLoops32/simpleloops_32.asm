        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)
		.data                   ;initialized data
        .data?         
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 

        public  main
		
main:    

	; exec count now 0
	; block 0, node 0, execs once
	mov ecx, 100

	; exec count now 1
	;block 1, nodes 1-5, execs 100 times 
loop1:
	mov eax, 20 ;node 1
	mov ebx, 10
	xchg eax, ebx

	dec ecx
	jnz loop1 ;node 5, [->1 (x99), ->6 (x1)]
	
	; exec count now 501
	mov ecx, 1000 ;node 6
	jmp loop2

	
	; exec count now 503
	;node 8-12, execs 1000 times
loop2:
	mov eax, 20 
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop2  ;node 12, [->8 (x999), ->13 (x1)]             
	
	; exec count now 5503
	mov ecx, 10000
	jmp loop3

	
	; exec count now 5505
	;node 15-19, execs 10000 times
loop3:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop3  ;node 19 [->15 (x9999), ->20 (x1)]  
	
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