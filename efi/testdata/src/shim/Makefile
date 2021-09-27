TOPDIR	?= $(shell pwd)
TOPDIR	= $(abspath $(TOPDIR))
VPATH	= $(TOPDIR)

COMPILER	?= gcc
CC			= $(CROSS_COMPILE)$(COMPILER)
LD			= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH	?= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed s,i[3456789]86,ia32,)

ifneq ($(origin VENDOR_CERT_FILE), undefined)
	CERT_CFLAGS = -DVENDOR_CERT_FILE=\"$(VENDOR_CERT_FILE)\"
endif
cert.o: cert.S
	$(CC) $(CFLAGS) $(CERT_CFLAGS) -c -o $@ $<

data.o: data.S
	$(CC) $(CFLAGS) -DNAME=\"$(NAME)\" -c -o $@ $<

sbat_data.o: /dev/null | $(TOPDIR)/shim_sbat.csv
	$(CC) $(CFLAGS) -x c -c -o $@ /dev/null
	objcopy --add-section .sbat=$(TOPDIR)/shim_sbat.csv \
		--set-section-flags .sbat=contents,alloc,load,readonly,data \
		$@

NAME	?= mockshim

OBJS    = main_$(ARCH).o data.o cert.o
ifneq ($(origin WITH_SBAT), undefined)
		OBJS += sbat_data.o
endif

TARGET  = $(NAME).efi

LDFLAGS	= -nostdlib -znocombreloc -T $(TOPDIR)/elf_$(ARCH)_efi.lds -shared -Bsymbolic

$(NAME).so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@

%.efi: %.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel -j .rela -j .reloc -j .vendor_cert -j .sbat --target=efi-app-$(ARCH) $^ $@
