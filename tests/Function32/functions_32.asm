
    .686p                   ;enable instructions
    .xmm                    ;enable instructions
    .model flat, stdcall           ;use C naming convention (stdcall is default)
    .code                   ;code 
	

	public main
main:
	;basic block 1 (10 instructions)
	mov ecx, 100
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx
	dec ecx
	dec ecx
	dec ecx
	mov ecx, 1000
	call func1
	;+ 31 instructions -> now 41 done

	inc eax
	call func2
	; 41 + 2 + 29 -> now now 72 done

	dec eax
	call func3
	; 72 + 2 + 8 -> now now 82 done

	dec eax
	call func4
	; 82 + 2 + 47 -> now 131 done

		

	xor   ecx, ecx
	ret  ; total = 133 instructions
	
	
	;31 instructions
func1 proc stdcall
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	mov eax, 20
	mov ebx, 10
	xchg eax, ebx
	dec ecx           
	mov ecx, 10000
	ret
func1 endp

	;29 instructions
func2 proc stdcall
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	ret
func2 endp

	; 8 instructions
func3 proc stdcall
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	ret
func3 endp
	
	;47 instructions
func4 proc stdcall
	call func2  ;1 + 29 -> 30
	call func3  ;1 + 8  -> 9
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	dec eax
	ret  ;30 + 9 + 8 -> 47
func4 endp

END