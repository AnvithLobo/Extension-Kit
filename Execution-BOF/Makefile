all: stubs bof

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[!] _bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -I ../_include -c -o _bin/execute-assembly.x64.o execute-assembly/inlineExecute-Assembly.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x64.o) && echo '[+] execute-assembly' || echo '[!] execute-assembly build failed'

	# x64 Build
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-donut.main.x64.o execute-donut/execute-donut.c)
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/syscalls.x64.o execute-donut/syscalls.c)
	@(x86_64-w64-mingw32-gcc -w -c -o _bin/syscalls_asm.x64.o execute-donut/syscalls_x64.S)
	@(x86_64-w64-mingw32-ld -r -o _bin/execute-donut.x64.o _bin/execute-donut.main.x64.o _bin/syscalls.x64.o _bin/syscalls_asm.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-donut.x64.o) && echo '[+] execute-donut (x64)' || echo '[!] execute-donut (x64) build failed'

	# x86 Build
	@(i686-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/execute-donut.main.x32.o execute-donut/execute-donut.c)
	@(i686-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -O0 -s -I ../_include -c -o _bin/syscalls.x32.o execute-donut/syscalls.c)
	@(i686-w64-mingw32-gcc -w -c -o _bin/syscalls_asm.x32.o execute-donut/syscalls_x86.S)
	@(i686-w64-mingw32-ld -r -o _bin/execute-donut.x32.o _bin/execute-donut.main.x32.o _bin/syscalls.x32.o _bin/syscalls_asm.x32.o && i686-w64-mingw32-strip --strip-unneeded _bin/execute-donut.x32.o) && echo '[+] execute-donut (x86)' || echo '[!] execute-donut (x86) build failed'

	@$(MAKE) --no-print-directory -C No-Consolation
	@cp No-Consolation/_bin/*.o _bin/


stubs:
	@$(MAKE) --no-print-directory -C execute-donut/pipe_shellcode

clean:
	@(rm -rf _bin)
	@$(MAKE) --no-print-directory -C execute-donut/pipe_shellcode clean