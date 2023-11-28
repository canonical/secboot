	.section mods, "a", %progbits
	.balignl 8, 0
.Lgrub_module_info:
	.4byte 0x676d696d
	.balignl 8, 0
	.8byte .Lgrub_modules_start - .Lgrub_module_info
	.8byte .Lgrub_modules_end - .Lgrub_module_info
.Lgrub_modules_start:
#ifdef GRUB_PREFIX
.Lgrub_prefix_start:
	.4byte 3
	.4byte .Lgrub_prefix_end - .Lgrub_prefix_start
	.ascii GRUB_PREFIX
	.byte 0
.Lgrub_prefix_end:
#endif
.Lgrub_modules_end:
