;basic sanity check with a few external calls

	global main

    section .text
main:

	mov rbx, 17

level1:			;17 executions each below here
	mov rax, 0
	inc rax
	inc rax
	inc rax
	inc rax
	dec rax
	dec rax
	xchg rax, rbx
	xchg rax, rbx
	
	mov rcx, 47
	
level2:			;799 executions each below here
	inc rax
	inc rax
	inc rax
	
	mov rdx, 347
	
level3:			;277253 executions each below here
	inc rax
	dec rax
	dec rax
	xchg rax, rcx
	xchg rax, rcx
	
	mov rdi, 997

level4:			;276421241 executions each below here
	xor rsi, 10
	xor rsi, 20
	xor rsi, rsi
	dec rdi
	jnz level4
	
	dec rdx
	jnz level3
	
	dec rcx
	jnz level2
	
	dec rbx
	jnz level1
	
	;basic blocks 6-9
	xor   RCX, RCX		;sequential node 14
	ret    
