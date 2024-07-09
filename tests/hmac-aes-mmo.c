/*
 * tests/aes-mmo.c: tests for ../aes-mmo.h
 * 
 */

#include "../aes.h"
#include "../aes-mmo.h"
#include "../hmac-aes-mmo.h"
#include <stdio.h>
#include <string.h>
#include <stdio.h>

void print_buffer(const unsigned char a[], int length)
{
  int i;
  for (i=0; i<length; i++) {
    printf("0x%02X ", a[i]);
  };
}

void print_result(const char* test, const unsigned char input[], int length, const unsigned char key[], const unsigned char calculated[], const unsigned char expected[])
{
  printf("---------%s---------\n", test);
  printf("  input: [ ");
  print_buffer(input, length);
  printf("]\n  key: [ ");
  print_buffer(key, 16);
  printf("]\n  converted: [ ");
  print_buffer(calculated, 16);
  printf("]\n  expected: [ ");
  print_buffer(expected, 16);
  printf("]\n");
}

int main(int argc, char **argv) {
    /* C.6.1 Test Vector Set 1 */
    {
        const unsigned char plaintext[] = {0xC0};
        const unsigned char key[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};
        const unsigned char ciphertext_expected[16] = {0x45,0x12,0x80,0x7B,0xF9,0x4C,0xB3,0x40,0x0F,0x0E,0x2C,0x25,0xFB,0x76,0xE9,0x99};
        unsigned char ciphertext_calculated[16];

        hmac_aes_mmo(ciphertext_calculated, plaintext, sizeof(plaintext), key);
        print_result("C.6.1 Test Vector Set 1", plaintext, sizeof(plaintext), key, ciphertext_calculated, ciphertext_expected);
        if (memcmp(ciphertext_expected, ciphertext_calculated, 16)) {
            fputs("aes_mmo() failed test vector\n", stderr);
            return 1;
        }
    }

    /* [ZigbeeDirect] mimic 'sl_zb_sec_man_hmac_aes_mmo' Test 1*/
    {
        const unsigned char plaintext[] = {
            0x4B,0x43,0x5F,0x32,0x5F,0x55,0xFE,0xD5,0x4B,0xFE,0xFF,0xE2,0x0A,0x68,0x8A,0xAB,
            0x84,0xA7,0xD9,0x4E,0x8D,0xE6,0xF0,0x6F,0x2E,0xEF,0x32,0x70,0xF8,0x45,0xBD,0x5C,
            0xFA,0x77,0x6E,0xDC,0xEE,0x62,0x79,0x75,0x95,0x96,0x51,0xC6,0xE8,0x18,0x00,0x00,
            0x00,0xFE,0xFF,0x00,0x00,0x02,0xE3,0x85,0xF3,0x82,0xFD,0xD8,0xD1,0x76,0xD6,0x29,
            0xE1,0x9A,0x5F,0x28,0xC5,0x90,0xE0,0xC8,0xB5,0x80,0x70,0x19,0xDE,0x3E,0xEE,0xC0,
            0x06,0x4C,0x87,0x2C,0xD3,0x59};
        const unsigned char key[16] = {0x4A,0xD3,0x1E,0xB7,0x97,0x7D,0x55,0xD1,0x10,0x70,0x50,0x41,0x95,0xB7,0xFA,0x08};
        const unsigned char ciphertext_expected[16] = {0x41,0x15,0x62,0xA5,0xBE,0x3E,0xDB,0xCE,0x03,0x4C,0xBD,0x7C,0x71,0x52,0x90,0xC7};
        unsigned char ciphertext_calculated[16];

        hmac_aes_mmo(ciphertext_calculated, plaintext, sizeof(plaintext), key);
        print_result("[ZigbeeDirect] mimic 'sl_zb_sec_man_hmac_aes_mmo'", plaintext, sizeof(plaintext), key, ciphertext_calculated, ciphertext_expected);
        if (memcmp(ciphertext_expected, ciphertext_calculated, 16)) {
            fputs("aes_mmo() failed test vector\n", stderr);
            return 1;
        }
    }

    /* [ZigbeeDirect] mimic 'sl_zb_sec_man_hmac_aes_mmo' Test 2*/
    {
        const unsigned char di_reverse[8] = {
          0x01, 0x00, 0x00, 0x00, 0x00, 0xee, 0x1f, 0x00
        };
        const unsigned char dr_reverse[8] = {
          0x02, 0x00, 0x00, 0x00, 0x00, 0xee, 0x1f, 0x00
        };
        const unsigned char qi[32] = {
          0x5d, 0x28, 0x29, 0x8c, 0x91, 0x3d, 0x58, 0x8a,
          0x35, 0xe0, 0x1f, 0x79, 0xc9, 0x11, 0x66, 0x10,
          0xb7, 0x9b, 0x38, 0xe9, 0xc6, 0xcf, 0x15, 0x5c,
          0x55, 0xb0, 0x52, 0x9b, 0xbc, 0xcc, 0x85, 0x56
        };
        const unsigned char qr[32] = {
          0x82, 0x77, 0x2f, 0x75, 0x3d, 0xe9, 0x4e, 0xb4,
          0x92, 0x0f, 0xb4, 0x17, 0xd4, 0x67, 0x17, 0x80,
          0x81, 0x74, 0x0c, 0x1a, 0x87, 0x58, 0xfd, 0x3f,
          0x2f, 0x63, 0x02, 0xb5, 0x0b, 0x98, 0x35, 0x6f
        };
        unsigned char plaintext[ 6 +
                                 sizeof(di_reverse) +
                                 sizeof(dr_reverse) +
                                 sizeof(qi) + 
                                 sizeof(qr)
                          ] = { 0 };
        const unsigned char key[16] = {0xaf,0xf1,0x93,0x4b,0xe6,0x9b,0x40,0x11,0x17,0x9d,0x81,0xd9,0xf9,0xa5,0xff,0xeb};
        const unsigned char ciphertext_expected[16] = {0xda,0x21,0xb1,0x04,0xd0,0x73,0x96,0x6f,0x5a,0x38,0x80,0x27,0x2f,0x8a,0xf2,0xf0};
        unsigned char ciphertext_calculated[16];

        // 'KC_2_U'
        plaintext[0] = 0x4B;
        plaintext[1] = 0x43;
        plaintext[2] = 0x5F;
        plaintext[3] = 0x32;
        plaintext[4] = 0x5F;
        plaintext[5] = 0x55;
        // m = xk || di || dr || Qi || Qr || G
        int offset = 6;
        int i;
        for (i=0; i<sizeof(dr_reverse); i++) {
          plaintext[offset+i] = dr_reverse[i];
        }
        offset += sizeof(dr_reverse);
        for (i=0; i<sizeof(qr); i++) {
          plaintext[offset+i] = qr[i];
        }
        offset += sizeof(qr);
        for (i=0; i<sizeof(di_reverse); i++) {
          plaintext[offset+i] = di_reverse[i];
        }
        offset += sizeof(di_reverse);
        for (i=0; i<sizeof(qi); i++) {
          plaintext[offset+i] = qi[i];
        }

        hmac_aes_mmo(ciphertext_calculated, plaintext, sizeof(plaintext), key);
        print_result("[ZigbeeDirect] mimic 'sl_zb_sec_man_hmac_aes_mmo'", plaintext, sizeof(plaintext), key, ciphertext_calculated, ciphertext_expected);
        if (memcmp(ciphertext_expected, ciphertext_calculated, 16)) {
            fputs("aes_mmo() failed test vector\n", stderr);
            return 1;
        }
    }
    return 0;
}