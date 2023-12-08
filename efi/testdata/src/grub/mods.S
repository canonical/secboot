#define GRUB_MODULE_MAGIC 0x676d696d

	.section mods, "a", %progbits
#if defined(__x86_64__)
	.balignl 8, 0
.Lgrub_module_info:
	.4byte GRUB_MODULE_MAGIC
	.balignl 8, 0
	.8byte .Lgrub_modules_start - .Lgrub_module_info
	.8byte .Lgrub_modules_end - .Lgrub_module_info
#elif defined(__i386__)
	.balignl 4, 0
.Lgrub_module_info:
	.4byte GRUB_MODULE_MAGIC
	.4byte .Lgrub_modules_start - .Lgrub_module_info
	.4byte .Lgrub_modules_end - .Lgrub_module_info
#else
# error "unrecognized target"
#endif
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
