;basic sanity check with a few external calls

	global main

    section .text
main:

	mov ecx, 100
loop1:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop1
	
	mov ecx, 1000
	jmp loop2
loop2:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop2               

	mov ecx, 10000
	jmp loop3
loop3:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop3    
	
	mov ecx, 100000
	jmp loop4
loop4:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop4    
	
	mov ecx, 10000000
	jmp loop5
loop5:
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	jnz loop5    
	
	inc ecx
	inc ecx
	inc ecx
	inc ecx
	jmp end
	inc esi
	inc esi
	inc esi
	inc esi
end:

	xor   ecx, ecx		
	ret    
