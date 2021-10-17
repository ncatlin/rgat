;basic sanity check with a few external calls

;initialised data
.data
	 Message db "drgat test 1 64 bit", 0Dh, 0Ah, 0

;bss/unitialised data
.data? 
	 tmp db 0

extrn  GetStdHandle: PROC
extrn  WriteFile: PROC
extrn  ExitProcess: PROC
	
includelib      kernel32
        
.code                   ;code 

main proc
	; node 0 -> jmp main
	
	 mov   RCX, -11 	;node 1
	 call  GetStdHandle ;node 2 + node 3
	 

	 ;sequential nodes 4-11
	 mov   qword ptr [tmp], RAX 
	 mov   RDI, 21  
	 mov   RCX, qword ptr [tmp]         
	 lea   RDX, [Message]                       
	 mov   R8, RDI                                 
	 lea   R9, [tmp]                        	
	 mov   qword ptr [RSP + 4 * 8], 0                
	 call  WriteFile   ;call node 11 + extern node 12              

	 ;basic blocks 6-9
	 xor   RCX, RCX		;sequential node 13
	 call  ExitProcess 	;call node 14 
	  
main endp


end