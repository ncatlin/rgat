@echo off

set TESTSPATH="C:\Users\nia\Source\Repos\rgat\release\output\tests"
set NASMPATH="C:\Users\nia\AppData\Local\bin\NASM\nasm.exe"
set LINKERPATH="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX64\x64\link.exe"
set LIBS32="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.15063.0\um\x86"
set LIBS64="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.15063.0\um\x64"

;---------------------------
cd TESTSPATH
for %%f in (*.86.asm) do (
            echo "assembling %%~nf.asm"
            call :assemble32 "%%~nf"
    )

for %%f in (*.64.asm) do (
            echo "assembling %%~nf.asm"
            call :assemble64 "%%~nf"
    )
	
goto end
;-----------------------------

:assemble32
%NASMPATH% -fwin32 %1.asm
%LINKERPATH% %1.obj /subsystem:console /entry:main  /libpath:%LIBS32% /nodefaultlib kernel32.lib user32.lib /largeaddressaware:no
goto:EOF

;-----------------------------
:assemble64
%NASMPATH% -fwin64 %1.asm
%LINKERPATH% %1.obj /subsystem:console /entry:main  /libpath:%LIBS64% /nodefaultlib kernel32.lib user32.lib
goto:EOF

;-----------------------------
:end