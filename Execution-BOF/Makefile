all: stubs bof

stubs:
	@$(MAKE) --no-print-directory -C execute-donut/pipe_shellcode

bof: stubs
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[!] _bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-assembly.x64.o execute-assembly/inlineExecute-Assembly.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x64.o) && echo '[+] execute-assembly (x64)' || echo '[!] execute-assembly (x64) build failed'
	@(i686-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-assembly.x32.o execute-assembly/inlineExecute-Assembly.c && i686-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x32.o) && echo '[+] execute-assembly (x86)' || echo '[!] execute-assembly (x86) build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-donut.x64.o execute-donut/execute-donut.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-donut.x64.o) && echo '[+] execute-donut (x64)' || echo '[!] execute-donut (x64) build failed'
	@(i686-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-donut.x32.o execute-donut/execute-donut.c && i686-w64-mingw32-strip --strip-unneeded _bin/execute-donut.x32.o) && echo '[+] execute-donut (x86)' || echo '[!] execute-donut (x86) build failed'

	@$(MAKE) --no-print-directory -C No-Consolation
	@cp No-Consolation/_bin/*.o _bin/


clean:
	@(rm -rf _bin)
	@$(MAKE) --no-print-directory -C execute-donut/pipe_shellcode clean