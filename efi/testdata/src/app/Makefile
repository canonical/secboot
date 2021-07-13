TOPDIR	?= $(shell pwd)
TOPDIR	= $(abspath $(TOPDIR))
VPATH	= $(TOPDIR)

COMPILER	?= gcc
CC			= $(CROSS_COMPILE)$(COMPILER)
LD			= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH	?= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed s,i[3456789]86,ia32,)

data.o: data.S
	$(CC) $(CFLAGS) -DNAME=\"$(NAME)\" -c -o $@ $<

NAME	?= mock
OBJS    = main_$(ARCH).o data.o
TARGET  = $(NAME).efi

LDFLAGS	= -nostdlib -znocombreloc -T $(TOPDIR)/elf_$(ARCH)_efi.lds -shared -Bsymbolic

$(NAME).so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@

%.efi: %.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel -j .rela -j .reloc --target=efi-app-$(ARCH) $^ $@
