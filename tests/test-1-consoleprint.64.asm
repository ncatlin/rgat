;basic sanity check with a few external calls

	global main
    extern  GetStdHandle
    extern  WriteFile
    extern  ExitProcess

    section .text
main:
	;basic blocks 0-2
	 mov   RCX, -11 	;sequential node 0
	 call  GetStdHandle ;call node 1 + jmp node 2 + extern node 3
	 
	 ;basic blocks 3-5
	 ;sequential nodes 4-10
	 mov   qword [REL tmp], RAX
	 mov   RDI, 21
	 mov   RCX, qword [REL tmp]         
	 lea   RDX, [REL Message]                       
	 mov   R8, RDI                                 
	 lea   R9, [REL tmp]                        	
	 mov   qword [RSP + 4 * 8], 0                
	 call  WriteFile   ;call node 11 + jmp node 12 + extern node 13                  

	 ;basic blocks 6-9
	 xor   RCX, RCX		;sequential node 14
	 call  ExitProcess 	;call node 15 + jmp node 16 + extern node 17              
	 
section .data                                  
	 Message db "drgat test 1 64 bit", 0Dh, 0Ah, 0
	 

section .bss                                 
	alignb 4
	tmp resq 1