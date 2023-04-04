TOPDIR	?= $(shell pwd)
TOPDIR	= $(abspath $(TOPDIR))
VPATH	= $(TOPDIR)

COMPILER	?= gcc
CC		= $(CROSS_COMPILE)$(COMPILER)
LD		= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH	?= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed s,i[3456789]86,ia32,)

NAME		= mockshim
SHIM_VERSION	?= 15.7
SHIM_COMMIT	?= $(shell echo $(SHIM_VERSION) | openssl dgst -sha1 | cut -d ' ' -f2)

SBAT_CSV	?= sbat.csv

CPPFLAGS += -DSHIM_VERSION=\"$(SHIM_VERSION)\" -DSHIM_COMMIT=\"$(SHIM_COMMIT)\"
ifneq ($(origin VENDOR_CERT_FILE), undefined)
	CPPFLAGS += -DVENDOR_CERT_FILE=\"$(VENDOR_CERT_FILE)\"
endif
ifneq ($(origin SBAT_VAR_PREVIOUS), undefined)
	CPPFLAGS += -DSBAT_VAR_PREVIOUS=\"$(SBAT_VAR_PREVIOUS)\"
endif
ifneq ($(origin SBAT_VAR_LATEST), undefined)
	CPPFLAGS += -DSBAT_VAR_LATEST=\"$(SBAT_VAR_LATEST)\"
endif

sbat.csv: $(TOPDIR)/sbat.csv.in
	sed -e 's/%SHIM_VERSION%/$(SHIM_VERSION)/' $< > $@

sbat_data.o: $(SBAT_CSV)
	$(CC) $(CFLAGS) -x c -c -o $@ /dev/null
	objcopy --add-section .sbat=$< \
		--set-section-flags .sbat=contents,alloc,load,readonly,data \
		$@

OBJS    = main_$(ARCH).o cert.o data.o version.o
ifneq ($(origin WITH_SBAT), undefined)
	OBJS += sbat_data.o
endif
ifneq ($(origin WITH_SBATLEVEL), undefined)
	OBJS += sbat_vars.o
endif

TARGET  = $(NAME).efi

LDFLAGS	= -nostdlib -znocombreloc -T $(TOPDIR)/elf_$(ARCH)_efi.lds -shared -Bsymbolic

$(NAME).so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@

%.efi: %.so
	$(OBJCOPY) -j .text -j .data -j .reloc -j .vendor_cert -j .data.ident -j .sbat -j .sbatlevel --target=efi-app-$(ARCH) $^ $@
