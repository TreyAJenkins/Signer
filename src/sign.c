#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../RSA-Library/rsa.h"
#include "../SHA256/sha256_digest.h"

#define STRINGIFY(x) #x
#define MACRO(x)     STRINGIFY(x)

struct Preamble {
    char header[11];
    char authority[9];
    long long signature[64];
    char footer[11];
};

struct Keyfile {
    char header[10];
    char authority[9];
    //NOTE: PRIVATE AND PUBLIC KEY CLASSES ARE SWAPPED!!!
    struct private_key_class public;
    struct public_key_class private;
};


int main(int argc, char const *argv[]) {
    #ifdef DEBUG
    printf("+--------------------+\n| Build ID: %s |\n+--------------------+\n\n", MACRO(BUILDID));
    #endif

    int outloc = 2;

    if (argc < 3) {
        printf("Usage:\n\t%s [KEYFILE] [FILE] (OUTPUT)\n", argv[0]);
        exit(0);
    }
    if (argc > 3) {
        outloc = 3;
    }


    struct Preamble *preamble=malloc(sizeof(struct Preamble));
    struct Keyfile *keyfile=malloc(sizeof(struct Keyfile));

    strcpy(preamble->header, "TEXTOSXSIG");
    strcpy(preamble->footer, "TEXTOSXSIG");

    FILE * kfile= fopen(argv[1], "rb");
    if (kfile != NULL) {
        if (!fread(keyfile, sizeof(struct Keyfile), 1, kfile)) {
            printf("Error reading file\n");
            exit(3);
        };
        fclose(kfile);
    }

    strcpy(preamble->authority, keyfile->authority);

    if (strncmp(keyfile->header, "TeXTKEYS", 8) != 0) {
        printf("Invalid keyfile\n");
        exit(1);
    }

    FILE * file = fopen(argv[2], "rb");
    char* buffer;
    int size;
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        fseek(file, 0, SEEK_SET);

        buffer = malloc(size+1);

        if (!fread(buffer, size, 1, file)) {
            printf("Error reading file\n");
            exit(2);
        };

        fclose(kfile);
    } else {
        printf("Nonexistant file\n");
        exit(2);
    }

    struct sha256_base *handler = sha256_init();

    struct sha256_message *mesg = sha256_message_create_from_buffer(buffer, size*8, handler);
    sha256_message_preprocess(mesg);
    sha256_message_digest(mesg, handler);

    //free(buffer);

    char hash_arr[64];
    hash_arr[64] = '\0';
    char *hash_string = sha256_message_get_hash(mesg);
    strncpy(hash_arr, hash_string, 64);

    printf("HASH.....: %s\n", hash_arr);

    struct public_key_class pk[1];
    pk->modulus = keyfile->private.modulus;
    pk->exponent = keyfile->private.exponent;

    long long *encrypted = rsa_encrypt(hash_arr, 64, pk);
    if (!encrypted){
        fprintf(stderr, "Error in encryption!\n");
        return 1;
    }

    //preamble->signature = (long long) encrypted;

    //printf("%lld\n", preamble->signature);

    //printf("LONG LONG: ");
    for(int i=0; i < 64; i++){
        //printf("%lld ", (long long)encrypted[i]);
        preamble->signature[i] = (long long) encrypted[i];
    }
    //printf("\n");

    struct private_key_class pki[1];
    pki->modulus = keyfile->public.modulus;
    pki->exponent = keyfile->public.exponent;
    char *decrypted = rsa_decrypt(preamble->signature, 512, pki);

    printf("Decrypted: %s\n\n", decrypted);

    FILE * ofile;
    if (outloc == 2) {
        ofile = fopen(argv[outloc], "ab");
    } else {
        ofile = fopen(argv[outloc], "wb");
    }
    if (file != NULL) {
        if (outloc != 2) {
            fwrite(buffer, size, 1, ofile);
        }
        fwrite(preamble, sizeof(struct Preamble), 1, ofile);
        fclose(ofile);
    }

    free(buffer);
    sha256_free(handler);
    free(hash_string);
    free(keyfile);
    free(preamble);

    return 0;
}
