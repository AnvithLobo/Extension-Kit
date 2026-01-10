all: stub_x64.bin stub_x86.bin

stub_x64.bin: stub_x64.asm
	nasm -f bin stub_x64.asm -o stub_x64.bin

stub_x86.bin: stub_x86.asm
	nasm -f bin stub_x86.asm -o stub_x86.bin

clean:
	rm -f *.bin
