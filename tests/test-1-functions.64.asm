;basic sanity check with a few external calls

	global main

    section .text
main:

	mov rcx, 100
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx
	dec rcx
	dec rcx
	dec rcx
	
	mov rcx, 1000
	call func1
	inc eax
	call func2
	dec eax
	call func3
	dec eax
	call func4
	
	
end:
	
	;basic blocks 6-9
	xor   RCX, RCX		;sequential node 14
	ret  	
	
	
	
	
	
func1:
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	mov rax, 20
	mov rbx, 10
	xchg rax, rbx
	dec rcx           
	mov rcx, 10000
	ret

func2:
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	inc rax
	ret

func3:
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	ret
	
func4:
	call func2
	call func3
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	dec rax
	ret
