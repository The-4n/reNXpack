include config.mk

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE) lib
	$(MAKE) renxpack

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

renxpack: sha.o aes.o extkeys.o pki.o utils.o nsp.o nca.o cnmt.o main.o filepath.o ConvertUTF.o rsa.o pfs0.o ticket.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

aes.o: aes.h types.h

extkeys.o: extkeys.h types.h settings.h

filepath.o: filepath.c types.h

main.o: main.c pki.h types.h version.h

pki.o: pki.h aes.h types.h

nsp.o: nsp.h

cnmt.o: cnmt.h

nca.o: nca.h aes.h sha.h bktr.h filepath.h types.h npdm.h ivfc.h romfs.h

pfs0.o: pfs0.h

sha.o: sha.h types.h

utils.o: utils.h types.h

ConvertUTF.o: ConvertUTF.h

rsa.o: rsa.h rsa_keys.h

ticket.o: ticket.h

clean:
	rm -f *.o renxpack renxpack.exe

clean_full:
	rm -f *.o renxpack renxpack.exe
	cd mbedtls && $(MAKE) clean

dist: clean_full
	$(eval NXREPACKVER = $(shell grep '\bRENXPACK_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir renxpack-$(NXREPACKVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls renxpack-$(NXREPACKVER)
	tar czf renxpack-$(NXREPACKVER).tar.gz renxpack-$(NXREPACKVER)
	rm -r renxpack-$(NXREPACKVER)

