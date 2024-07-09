/*
 * tests/aes.c: tests for ../aes.h
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/tests/aes.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../aes.h"
#include <stdio.h>
#include <string.h>

void print_buffer(const unsigned char a[], int length)
{
  int i;
  for (i=0; i<length; i++) {
    printf("0x%02X ", a[i]);
  };
}

void print_result(const char* test, const unsigned char plain[], int size_plain, const unsigned char key[], const unsigned char x[], const unsigned char h[])
{
  printf("---------%s---------\n", test);
  printf("  plaintext: [ ");
  print_buffer(plain, size_plain);
  printf("]\n  key: [ ");
  print_buffer(key, 16);
  printf("]\n  converted: [ ");
  print_buffer(x, 16);
  printf("]\n  expected: [ ");
  print_buffer(h, 16);
  printf("]\n");
}

/*
 * Tests the aes_encrypt function with the example values in
 * [AES] Advanced Encryption Standard (AES), FIPS 197, Nov 26 2001.
 *       http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
int main(int argc, char **argv) {
  {
    const struct {
      const char* msg;
      unsigned char plaintext[16];
      unsigned char key[16];
      unsigned char ciphertext[16];
    } vectors[] = {
      { /* [AES] Appendix B Cipher Example */
        "[AES] Appendix B Cipher Example",
        {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34},
        {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
        {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32}
      },{ /* [AES] Appendix C Example Vectors C.1 AES-128 (Nk=4, Nr=10) */
        "[AES] Appendix C Example Vectors C.1 AES-128 (Nk=4, Nr=10)",
        {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a}
      }
    };
    unsigned char ciphertext[16];
    unsigned i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
      aes_encrypt(ciphertext, vectors[i].plaintext, vectors[i].key);
      print_result(vectors[i].msg, vectors[i].plaintext, sizeof(vectors[i].plaintext), vectors[i].key, ciphertext, vectors[i].ciphertext);
      if (memcmp(ciphertext, vectors[i].ciphertext, 16)) {
        fprintf(stderr, "aes_encrypt() failed for test vector %u\n", i);
        return 1;
      }
    }
  }

  return 0;
}
