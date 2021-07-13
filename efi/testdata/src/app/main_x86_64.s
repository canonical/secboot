/*
    A simple EFI application that just returns 0 with no dependencies
    other than the assembler and linker.
*/

	.text
	.align 4

	.globl _start
_start:
    mov $0, %rax
.exit:	
  	ret
