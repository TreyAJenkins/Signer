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
    struct public_key_class public;
    struct private_key_class private;
};


int main(int argc, char const *argv[]) {
    #ifdef DEBUG
    printf("+--------------------+\n| Build ID: %s |\n+--------------------+\n\n", MACRO(BUILDID));
    #endif

    if (argc < 3) {
        printf("Usage:\n\t%s [KEYSTORE] [FILE]\n", argv[0]);
        exit(0);
    }


    struct Preamble *preamble=malloc(sizeof(struct Preamble));

    FILE * file= fopen(argv[2], "rb");
    unsigned int size;
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        if (size < sizeof(struct Preamble)) {
            printf("Invalid file\n");
            free(preamble);
            exit(2);
        }
        fseek(file, (sizeof(struct Preamble)*-1), SEEK_END);
        if (!fread(preamble, sizeof(struct Preamble), 1, file)) {
            printf("Error reading file\n");
            exit(3);
        };
        //fclose(file);
    } else {
        printf("File is null\n");
        exit(2);
    }

    if (strcmp(preamble->header,preamble->footer) == 0 && strncmp(preamble->header, "TEXTOSXSIG", 10) == 0) {} else {
        printf("File not signed\n");
        printf("Header: %s\nFooter: %s\n", preamble->header,preamble->footer);
        fclose(file);
        exit(4);
    }


    struct Keyfile *keyfile = malloc(sizeof(struct Keyfile));
    int foundKey = 0;

    FILE * keystore = fopen(argv[1], "rb");
    unsigned int ksize;
    if (keystore != NULL) {
        fseek(keystore, 0, SEEK_END);
        ksize = ftell(keystore);

        fseek(keystore, 0, SEEK_SET);

        for (int i = 0; i < (ksize / sizeof(struct Keyfile)); i++) {
            //fseek(keystore, (sizeof(struct Keyfile) * i), SEEK_SET);

            printf("Searching position '%li' for '%s' ... ", sizeof(struct Keyfile) * i, preamble->authority);

            if (! fread(keyfile, sizeof(struct Keyfile), 1, keystore)) {
                printf("Error reading keystore file\n");
                exit(3);
            }

            if (strncmp(keyfile->header, "TeXTKEYS", 8) != 0) {
                printf("Error parsing keystore at position: %li\n", sizeof(struct Keyfile) * i);
                fclose(keystore);
                exit(2);
            }


            if (strcmp(keyfile->authority, preamble->authority) == 0) {
                printf("[FOUND]\n");
                foundKey = 1;
                break;
            }
            printf("[NOT FOUND]\n");

        }

        if (foundKey == 0) {
            printf("Could not find '%s' in keyfile!\n", preamble->authority);
            fclose(keystore);
            exit(0);
        }

        fclose(keystore);
    } else {
        printf("Keystore file is null\n");
        exit(2);
    }


    size = size - sizeof(struct Preamble);
    char* buffer;
    buffer = malloc(size+1);
    fseek(file, 0, SEEK_SET);

    if (!fread(buffer, size, 1, file)) {
        printf("P2, Error reading file\n");
        fclose(file);
        exit(2);
    };
    fclose(file);

    struct sha256_base *handler = sha256_init();
    struct sha256_message *mesg = sha256_message_create_from_buffer(buffer, size*8, handler);
    sha256_message_preprocess(mesg);
    sha256_message_digest(mesg, handler);
    free(buffer);
    char hash_arr[64];
    hash_arr[64] = '\0';
    char *hash_string = sha256_message_get_hash(mesg);
    strncpy(hash_arr, hash_string, 64);
    sha256_free(handler);



    struct private_key_class pki[1];
    pki->modulus = keyfile->public.modulus;
    pki->exponent = keyfile->public.exponent;
    char *decrypted = rsa_decrypt(preamble->signature, 512, pki);

    int valid = 0;
    if (strcmp(hash_string, decrypted) == 0) {
        valid = 1;
    }

    printf("Authority...: %s\nCalculated..: %s\nSignature...: %s\n\n", preamble->authority, hash_string, decrypted);

    free(preamble);
    free(hash_string);
    free(keyfile);

    if (valid) {
        printf("VALID SIGNATURE FROM %s\n", keyfile->authority);
        return 0;
    } else {
        printf("INVALID SIGNATURE\n");
        return 1;
    }

    return 0;
}
