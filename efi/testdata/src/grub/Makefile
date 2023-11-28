TOPDIR	?= $(shell pwd)
TOPDIR	= $(abspath $(TOPDIR))
VPATH	= $(TOPDIR)

COMPILER	?= gcc
CC		= $(CROSS_COMPILE)$(COMPILER)
LD		= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH	?= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed s,i[3456789]86,ia32,)

NAME		?= mock
SBAT_CSV	?= $(TOPDIR)/sbat.csv

CPPFLAGS += -DNAME=\"$(NAME)\"
ifneq ($(origin GRUB_PREFIX), undefined)
	CPPFLAGS += -DGRUB_PREFIX=\"$(GRUB_PREFIX)\"
endif

sbat_data.o: $(SBAT_CSV)
	$(CC) $(CFLAGS) -x c -c -o $@ /dev/null
	objcopy --add-section .sbat=$< \
		--set-section-flags .sbat=contents,alloc,load,readonly,data \
		$@

OBJS    = main_$(ARCH).o data.o mods.o
ifneq ($(origin WITH_SBAT), undefined)
	OBJS += sbat_data.o
endif
TARGET  = $(NAME).efi

LDFLAGS	= -nostdlib -znocombreloc -T $(TOPDIR)/elf_$(ARCH)_efi.lds -shared -Bsymbolic

$(NAME).so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@

%.efi: %.so
	$(OBJCOPY) -j .text -j .data -j .reloc -j .sbat -jmods --target=efi-app-$(ARCH) $^ $@
