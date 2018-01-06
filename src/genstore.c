#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct PublicKey {
    long long modulus;
    long long exponent;
};

struct PrivateKey {
    long long modulus;
    long long exponent;
};

struct Keyfile {
    char header[10];
    char authority[9];
    struct PublicKey public;
    struct PrivateKey private;
};

int main(int argc, char const *argv[]) {
  if (argc < 3) {
      printf("Usage:\n\t%s [KEYFILE] [KEYSTORE]\n", argv[0]);
      exit(0);
  }

  struct Keyfile *keyfile=malloc(sizeof(struct Keyfile));

  FILE * kfile= fopen(argv[1], "rb");
  if (kfile != NULL) {
      if (!fread(keyfile, sizeof(struct Keyfile), 1, kfile)) {
          printf("Error reading file\n");
          exit(3);
      };
      fclose(kfile);
  }

  if (strncmp(keyfile->header, "TeXTKEYS", 8) != 0) {
      printf("Invalid keyfile\n");
      exit(1);
  }

  keyfile->private.modulus = 0;
  keyfile->private.exponent = 0;

  FILE * file= fopen(argv[2], "ab");
  if (file != NULL) {
      fwrite(keyfile, sizeof(struct Keyfile), 1, file);
      fclose(file);
  }

  return 0;
}
