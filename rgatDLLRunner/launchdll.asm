; This is rgat's DLL Launcher binary 
; It loads a target DLL from a command line argument and runs and optional export
; It's designed to be lightweight to avoid cluttering up graphs with non-target instructions

        .686p                   ;enable instructions
        .xmm                    ;enable instructions
        .model flat, stdcall           ;use C naming convention (stdcall is default)
		        .data                   ;initialized data
message     db      "delmefff",0dh,0ah,0
message_end db 0
        .data?         
        .stack  4096            ;stack (optional, linker will default)

        .code                   ;code 


        LoadLibraryA   proto, 
			lpLibFileName: near32  


        GetStdHandle PROTO STDCALL :DWORD

        GetProcAddress proto,                  
            hModule: dword, 
			lpLibFileName: near32 

        GetCommandLineA proto

        ExitProcess PROTO STDCALL :DWORD
        
        WriteFile proto,                  
            hFile:dword, lpBuffer:near32,      ;A handle to the device
            nNumberOfCharsToWrite:dword,       ;The maximum number of bytes to be written.
            lpNumberOfbytesWritten:near32,     ;A pointer to the variable that receives the number of bytes written
            lpOverlapped:near32 


        public  main
		
        includelib      kernel32
main:    





    call GetCommandLineA
    mov edi, eax

    ; skip past loader module name to first space
inc edi
    mov ecx, 0ffffffffh
    mov eax, ' '
    ;cmp al, byte ptr [edi]
    repne scasb
    push edi  ;dll name for loadlibray
    
    ; replace comma after target library name with a null
    mov ecx, 0ffffffffh
    mov eax, ','
    repnz scasb ;//todo handle repnz!
    mov eax, edi
    sub eax, 1
    mov byte ptr [eax], 0
     
    ; load the library or exit if not found
    call LoadLibraryA
    cmp eax, 0
    je done_failure

    push eax ; library base
    push edi ; start of export ordinal for the getprocaddress later

    ; find end of supplied ordinal
    mov ecx, 0ffffffffh
    mov eax, '$'
    repnz scasb [edi]
    not ecx
    dec ecx  ; stringlen
    jz done_success 

    pop esi
    mov ebx, ecx
    dec ebx ; index of lowest order character 
    
; upper case hex string to int
;esi = input string
;edi = output result value
;eax = byte being worked on 
;ebx = index of last char
;ecx = working variable
;edx = current index

    xor eax, eax
    xor edi, edi
    mov edx, ebx

str_to_int_top:
    mov al, byte ptr [esi+edx] ; working byte = string[index]

    cmp eax, '9'
    jg subhexchar
    sub eax, '0' ; convert [0-9] to its value
    jmp convert_char
subhexchar:
    sub eax, 55  ;convert [A-F] to its value
    
convert_char:
    mov ecx, ebx  ; index of last char
    sub ecx, edx  ; subtract current char index
    shl ecx, 2    ; * 4
    shl eax, cl   ; shift working value to its true magnitude
    add edi, eax  ; update the result with its value
    
    dec edx
    jns str_to_int_top ; stop after processing index 0

    pop eax  ; library

    cmp edi, 0
    je done_success
        
    push edi ; ordinal
    push eax ; library
    call GetProcAddress
    
    test eax, eax
    jz done_failure

    call eax

done_success:
	mov eax, 1	
	ret    ;node 40 - ret to basethreadinitthunk
	
done_failure:
    mov eax, 0
    ret


end main

        end