        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)
		.data                   ;initialized data
        .data?         
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 

        public  main  

main:

	mov ebx, 17

level1:			;17 executions each below here
	mov eax, 0
	inc eax
	inc eax
	inc eax
	inc eax
	dec eax
	dec eax
	xchg eax, ebx
	xchg eax, ebx
	
	mov ecx, 47
	
level2:			;799 executions each below here
	inc eax
	inc eax
	inc eax
	
	mov edx, 347
	
level3:			;277253 executions each below here
	inc eax
	dec eax
	dec eax
	xchg eax, ecx
	xchg eax, ecx
	
	mov edi, 997

level4:			;276421241 executions each below here
	xor esi, 10
	xor esi, 20
	xor esi, esi
	dec edi
	jnz level4
	
	dec edx
	jnz level3
	
	dec ecx
	jnz level2
	
	dec ebx
	jnz level1
	
	;basic blocks 6-9
	xor   ecx, ecx		;sequential node 14
	ret    
	
end main

        end