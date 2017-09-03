;basic sanity check with a few external calls

 global _main
    extern  _GetStdHandle@4
    extern  _WriteFile@20
    extern  _ExitProcess@4

    section .text
_main:

	;basic blocks 0-2
	;sequential nodes 0-2
    mov     ebp, esp
    sub     esp, 4	
    push    -11
    call    _GetStdHandle@4 ;call node 3 + jump node 4 + external node 5
	
	;basic blocks 3-6
	;sequential nodes 6-12
    mov     ebx, eax    
    push    0
    lea     eax, [ebp-4]
    push    eax
    push    (message_end - message)
    push    message
    push    ebx
    call    _WriteFile@20 ;call node 13 + jump node 14 + external node 15

    ;basic blocks 7-9
	;sequential node 16
    push    0
    call    _ExitProcess@4 ;call node 17 + jump node 18 + external node 19

    ; never here
    hlt

	section .data
message:
    db      'drgat test 1 32 bit', 10
message_end: