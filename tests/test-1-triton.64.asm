;basic sanity check with a few external calls


	;extern __getmainargs

    section .text
	
global main
main:

	mov rax, 20
	add rax, rcx
	cmp rax, 80
	je success1
	jmp fail

global success1
success1:
	add rax, rdx
	cmp rax, 90
	je success2
	jmp fail

success2:	
	mul rax

global fail
fail:
	;basic blocks 6-9
	xor   RCX, RCX		;sequential node 14
	ret    
