 	.data
	.ascii NAME
dummy:
	.long	0

 	// hand-craft a dummy .reloc section so EFI knows it's a relocatable executable:
#define IMAGE_REL_ABSOLUTE	0
 	.section .reloc, "a"
label1:
	.long	dummy-label1				// Page RVA
 	.long	10					// Block Size (2*4+2)
	.word	(IMAGE_REL_ABSOLUTE<<12) +  0		// reloc for dummy
