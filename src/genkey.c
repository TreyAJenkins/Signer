#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../RSA-Library/rsa.h"

#define STRINGIFY(x) #x
#define MACRO(x)     STRINGIFY(x)

/*struct PublicKey {
    long long modulus;
    long long exponent;
};

struct PrivateKey {
    long long modulus;
    long long exponent;
};*/

struct Keyfile {
    char header[10];
    char authority[9];
    /*struct PublicKey public;
    struct PrivateKey private;*/
    struct public_key_class public;
    struct private_key_class private;
};

int main(int argc, char const *argv[]) {
    #ifdef DEBUG
    printf("+--------------------+\n| Build ID: %s |\n+--------------------+\n\n", MACRO(BUILDID));
    #endif

    if (argc < 3) {
        printf("Usage:\n\t%s [AUTHORITY] [OUTPUT]\n", argv[0]);
        exit(0);
    }

    struct Keyfile *keyfile = malloc(sizeof(struct Keyfile));

    strcpy(keyfile->header, "TeXTKEYS");
    strncpy(keyfile->authority, argv[1], 8);

    rsa_gen_keys(&keyfile->public, &keyfile->private, PRIME_SOURCE_FILE);

    printf("%s\n  |\n  |--Public\n    |--Modulus: %lli\n    |--Exponent: %lli\n  |--Private\n    |--Modulus: %lli\n    |--Exponent: %lli\n",
    keyfile->authority, keyfile->public.modulus, keyfile->public.exponent, keyfile->private.modulus, keyfile->private.exponent);


    struct public_key_class pub[1];
    pub->modulus = keyfile->public.modulus;
    pub->exponent = keyfile->public.exponent;
    char message[] = "123abc";
    long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
    if (!encrypted){
        fprintf(stderr, "Error in encryption!\n");
        return 1;
    }

    if ((long long) encrypted[0] < 1) {
        printf("Generated bad key, try again\n");
        exit(10);
    }
    //printf("GOOD KEY\n");

    printf("LONG LONG: ");
    for(int i=0; i < 6; i++){
        printf("%lld ", (long long)encrypted[i]);
        //preamble->signature[i] = (long long) encrypted[i];
    }
    printf("\n");

    FILE * file= fopen(argv[2], "wb");
    if (file != NULL) {
        fwrite(keyfile, sizeof(struct Keyfile), 1, file);
        fclose(file);
    }


    free(keyfile);

    return 0;
}
