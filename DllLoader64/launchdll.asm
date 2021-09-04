; This is rgat's DLL Launcher binary 
; It loads a target DLL from a command line argument and runs and optional export
; It's designed to be lightweight to avoid cluttering up graphs with non-target instructions


.data?         


extrn LoadLibraryA: PROC  
extrn GetStdHandle: PROC  
extrn GetProcAddress: PROC  
extrn GetCommandLineA: PROC  
extrn ExitProcess: PROC  
extrn WriteFile: PROC  

includelib      kernel32
        
.code                   ;code 

main proc  

    sub rsp, 28h  
    call GetCommandLineA
    mov rdi, rax

    ; skip past loader module name to first space
    inc rdi
    mov rcx, -1
    mov rax, ' '
    repne scasb
    mov r13, rdi ; r13 = target library path
    
    ; null terminate the dll name for loadlibrary
    mov rcx, 0ffffffffh
    mov rax, ','
    repnz scasb ;//todo handle repnz!
    mov rax, rdi
    sub rax, 1
    mov byte ptr [rax], 0
    mov r12, rdi  ; r12 = start of ordinal 
    
    ; load the library or exit if not found
    mov rdi, r13
    mov rcx, rdi
    call LoadLibraryA
    cmp rax, 0
    je done_failure

    mov r14, rax ; r14 = target library handle
    mov rdi, r12
    ; find end of supplied ordinal
    mov ecx, 0ffffffffh
    mov rax, '$'
    repnz scasb [rdi]
    not ecx
    dec ecx  ; stringlen
    jz done_success 

    mov rsi, r12
    mov ebx, ecx
    dec ebx ; index of lowest order character 
    
; upper case hex string to int
;rsi = input string
;rdi = output result value
;rax = byte being worked on 
;rbx = index of last char
;ecx = working variable
;rdx = current index

    xor rax, rax
    xor rdx, rdx
    xor rdi, rdi
    mov edx, ebx

str_to_int_top:
    mov al, byte ptr [rsi+rdx] ; working byte = string[index]

    cmp rax, '9'
    jg subhexchar
    sub rax, '0' ; convert [0-9] to its value
    jmp convert_char
subhexchar:
    sub rax, 55  ;convert [A-F] to its value
    
convert_char:
    mov ecx, ebx  ; index of last char
    sub ecx, edx  ; subtract current char index
    shl ecx, 2    ; * 4
    shl rax, cl   ; shift working value to its true magnitude
    add rdi, rax  ; update the result with its value
    
    dec edx
    jns str_to_int_top ; stop after processing index 0

    cmp rdi, 0
    je done_success
        
    mov rcx, r14
    mov rdx, rdi
    call GetProcAddress
    
    test rax, rax
    jz done_failure

    call rax

done_success:

    add rsp, 28h  
	mov rax, 1	
	ret    ;node 40 - ret to basethreadinitthunk
	
done_failure:
    add rsp, 28h  
    mov rax, 0
    ret

main endp


end