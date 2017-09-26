;basic sanity check with a few external calls

	global main

    section .text
main:

	mov rcx, 100
loop1:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	jnz loop1
	
	mov rcx, 1000
	jmp loop2
loop2:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	jnz loop2               

	mov rcx, 10000
	jmp loop3
loop3:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	jnz loop3    
	
	mov rcx, 100000
	jmp loop4
loop4:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	jnz loop4    
	
	mov rcx, 10000000
	jmp loop5
loop5:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	jnz loop5    
	
	;this is so the end of the loop is not the last basic block
	inc rcx
	inc rcx
	inc rcx
	inc rcx
	jmp end
	inc rsi
	inc rsi
	inc rsi
	inc rsi
end:
	
	;basic blocks 6-9
	xor   RCX, RCX		;sequential node 14
	ret    
