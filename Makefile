CC=gcc

define c
	@echo $(CC) $3
	@$(CC) -O3 $1 -o $3 src/$2
endef


all:
	$(call c,RSA-Library/rsa.c,genkey.c,genkey)
	$(call c,,genstore.c,genstore)
	$(call c,RSA-Library/rsa.c SHA256/sha256_digest.c,sign.c,sign)
	$(call c,RSA-Library/rsa.c SHA256/sha256_digest.c,verify.c,verify)
