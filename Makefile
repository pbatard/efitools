EFIFILES = HelloWorld.efi LockDown.efi Loader.efi ReadVars.efi UpdateVars.efi \
	KeyTool.efi HashTool.efi SetNull.efi ShimReplace.efi
EFILIBS = gnu-efi/$(ARCH)/lib/libefi.a gnu-efi/$(ARCH)/gnuefi/libgnuefi.a \
	lib/asn1/libasn1-efi.a lib/lib-efi.a
BINARIES = cert-to-efi-sig-list sig-list-to-certs sign-efi-sig-list \
	hash-to-efi-sig-list efi-readvar efi-updatevar cert-to-efi-hash-list \
	flash-var

ifeq ($(ARCH),x86_64)
EFIFILES += PreLoader.efi
endif

MSGUID = 77FA9ABD-0359-4D32-BD60-28F4E78F784B

KEYS = PK KEK DB
EXTRAKEYS = DB1 DB2
EXTERNALKEYS = ms-uefi ms-kek

ALLKEYS = $(KEYS) $(EXTRAKEYS) $(EXTERNALKEYS)

KEYAUTH = $(ALLKEYS:=.auth)
KEYUPDATEAUTH = $(ALLKEYS:=-update.auth) $(ALLKEYS:=-pkupdate.auth)
KEYBLACKLISTAUTH = $(ALLKEYS:=-blacklist.auth)
KEYHASHBLACKLISTAUTH = $(ALLKEYS:=-hash-blacklist.auth)

OLD_CFLAGS:=$(CFLAGS)
OLD_LDFLAGS:=$(LDFLAGS)

export TOPDIR	:= $(shell pwd)/

include Make.rules

EFISIGNED = $(patsubst %.efi,%-signed.efi,$(EFIFILES))

all: $(EFISIGNED) $(BINARIES) $(MANPAGES) noPK.auth $(KEYAUTH) \
	$(KEYUPDATEAUTH) $(KEYBLACKLISTAUTH) $(KEYHASHBLACKLISTAUTH)

# Don't build files that contain private data when publishing EFI binaries
efi: $(filter-out LockDown.efi PreLoader.efi,$(EFIFILES))

install: all
	$(INSTALL) -m 755 -d $(MANDIR)
	$(INSTALL) -m 644 $(MANPAGES) $(MANDIR)
	$(INSTALL) -m 755 -d $(EFIDIR)
	$(INSTALL) -m 755 $(EFIFILES) $(EFIDIR)
	$(INSTALL) -m 755 -d $(BINDIR)
	$(INSTALL) -m 755 $(BINARIES) $(BINDIR)
	$(INSTALL) -m 755 mkusb.sh $(BINDIR)/efitool-mkusb
	$(INSTALL) -m 755 -d $(DOCDIR)
	$(INSTALL) -m 644 README COPYING $(DOCDIR)

gnu-efi/$(ARCH)/gnuefi/libgnuefi.a gnu-efi/$(ARCH)/lib/libefi.a:
	@mkdir -p gnu-efi/lib gnu-efi/gnuefi
	$(MAKE) -C gnu-efi CC="$(CC)" TOPDIR=$(TOPDIR)/gnu-efi CFLAGS="$(CFLAGS) -fshort-wchar" \
		-f $(TOPDIR)/gnu-efi/Makefile lib gnuefi inc

lib/lib.a lib/lib-efi.a: FORCE
	$(MAKE) -C lib $(notdir $@)

lib/asn1/libasn1.a lib/asn1/libasn1-efi.a: FORCE
	$(MAKE) -C lib/asn1 $(notdir $@)

.SUFFIXES: .crt

.KEEP: PK.crt KEK.crt DB.crt PK.key KEK.key DB.key PK.esl DB.esl KEK.esl \
	$(EFIFILES)

LockDown.o: PK.h KEK.h DB.h
PreLoader.o: hashlist.h

PK.h: PK.auth

KEK.h: KEK.auth

DB.h: DB.auth

noPK.esl:
	> noPK.esl

noPK.auth: noPK.esl PK.crt sign-efi-sig-list
	./sign-efi-sig-list -t "$(shell date --date='1 second' +'%Y-%m-%d %H:%M:%S')" -c PK.crt -k PK.key PK $< $@

ms-%.esl: ms-%.crt cert-to-efi-sig-list
	./cert-to-efi-sig-list -g $(MSGUID) $< $@

hashlist.h: HashTool.hash
	cat $^ > /tmp/tmp.hash
	./xxdi.pl /tmp/tmp.hash > $@
	rm -f /tmp/tmp.hash


Loader.so: $(EFILIBS)
ReadVars.so: $(EFILIBS)
UpdateVars.so: $(EFILIBS)
LockDown.so: $(EFILIBS)
KeyTool.so: $(EFILIBS)
HashTool.so: $(EFILIBS)
PreLoader.so: $(EFILIBS)
HelloWorld.so: $(EFILIBS)
ShimReplace.so: $(EFILIBS)

cert-to-efi-sig-list: cert-to-efi-sig-list.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

sig-list-to-certs: sig-list-to-certs.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

sign-efi-sig-list: sign-efi-sig-list.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

hash-to-efi-sig-list: hash-to-efi-sig-list.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a

cert-to-efi-hash-list: cert-to-efi-hash-list.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

efi-keytool: efi-keytool.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a

efi-readvar: efi-readvar.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

efi-updatevar: efi-updatevar.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a -lcrypto

flash-var: flash-var.o lib/lib.a
	$(CC) $(ARCH3264) -o $@ $< $(OLD_CFLAGS) $(OLD_LDFLAGS) lib/lib.a

clean-gnu-efi:
	@if [ -d gnu-efi ] ; then \
		$(MAKE) -C gnu-efi CC="$(CC)" HOSTCC="$(HOSTCC)" TOPDIR=$(TOPDIR)/gnu-efi -f $(TOPDIR)/gnu-efi/Makefile clean ; \
	fi

clean: clean-gnu-efi
	rm -f PK.* KEK.* DB.* $(EFIFILES) $(EFISIGNED) $(BINARIES) *.o *.so
	rm -f noPK.*
	rm -f doc/*.1
	$(MAKE) -C lib clean
	$(MAKE) -C lib/asn1 clean

FORCE:
