CC ?= clang

PKG_CONFIG ?= pkg-config
OPENSSL ?= openssl

# export PKG_CONFIG_PATH = /usr/local/opt/libressl/lib/pkgconfig
PKG_CONFIG_PATH ?= /usr/local/opt/openssl/lib/pkgconfig

CERT_FILES = certs/cert.pem certs/bad_root_ca.pem

ROOT_CA_SUBJ = "/CN=Legit Certs Root CA/OU=Legit Certs/"
CA_SUBJ = "/CN=Legit Certs Signing CA/OU=Legit Certs/"
BAD_CA_SUBJ = "/CN=Bad Certs Root CA/OU=Bad Certs/"
CERT_SUBJ = "/CN=Joe Schmoe/OU=Acme Corp/"

create_key = $(OPENSSL) genrsa 2048
create_ss_ca = $(OPENSSL) req -new -x509 -subj $(2) -key $(1)
create_ca = $(OPENSSL) req -new  -key $(3) -subj $(4) | $(OPENSSL) x509 -CA $(1) -CAkey $(2) -req -set_serial $(5) -extensions v3_ca -extfile ./certs/openssl.cnf
sign = $(OPENSSL) dgst -sha256 -sign $(1) certs/signme.txt

CFLAGS = -Wall \
	-pedantic -std=c11 \
	$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs --cflags openssl)

x509: x509.c
	$(CC) -g $^ -o $@ $(CFLAGS)

run: x509
	./x509

.PHONY: certs
certs: $(CERT_FILES)

.PHONY: clean-all
clean-all: clean clean-certs

.PHONY: clean
clean:
	rm -f x509 x509.dSYM

.PHONY: clean-certs
clean-certs:
	rm -f certs/*.pem certs/signme.txt.*

# Internal targets:

certs/signme.txt.root_ca.sig: certs/root_ca.key.pem
	$(call sign,$^) > $@

certs/root_ca.key.pem: certs/
	@$(call create_key) > $@
certs/root_ca.pem: certs/root_ca.key.pem
	@$(call create_ss_ca,$^,$(ROOT_CA_SUBJ)) > $@
certs/ca.key.pem: certs/
	@$(call create_key) > $@
certs/ca.pem: certs/ca.key.pem certs/root_ca.pem
	$(call create_ca,certs/root_ca.pem,certs/root_ca.key.pem,certs/ca.key.pem,$(CA_SUBJ),2) > $@
certs/cert.key.pem: certs/
	@$(call create_key) > $@
certs/cert.pem: certs/cert.key.pem certs/ca.pem
	$(call create_ca,certs/ca.pem,certs/ca.key.pem,certs/cert.key.pem,$(CERT_SUBJ),3) > $@


certs/bad_root_ca.key.pem: certs/
	@$(call create_key) > $@
certs/bad_root_ca.pem: certs/bad_root_ca.key.pem
	@$(call create_ss_ca,$^,$(BAD_CA_SUBJ)) > $@


