/*
 * tests/aes-mmo.c: tests for ../aes-mmo.h
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/tests/aes-mmo.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../aes.h"
#include "../aes-mmo.h"
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

void print_result(const char* test, const unsigned char m[], int length, const unsigned char x[], const unsigned char h[])
{
  printf("---------%s---------\n", test);
  printf("  input: [ ");
  print_buffer(m, length);
  printf("]\n  converted: [ ");
  print_buffer(x, 16);
  printf("]\n  expected: [ ");
  print_buffer(h, 16);
  printf("]\n");
}

/*
 * Tests the aes_mmo function with the example values in the
 * ZigBee specification, document 05-3474-21, Aug 2015,
 * section C.5 Cryptographic Hash Function.
 */
int main(int argc, char **argv) {
  unsigned char x[16];
  unsigned i;

  /* C.5.1 Test Vector Set 1 */
  {
    const unsigned char m[] = {0xc0};
    const unsigned char h[16] = {0xae,0x3a,0x10,0x2a,0x28,0xd4,0x3e,0xe0,0xd4,0xa0,0x9e,0x22,0x78,0x8b,0x20,0x6c};

    aes_mmo(x, m, sizeof(m));
    print_result("C.5.1 Test Vector Set 1", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 1\n", stderr);
      return 1;
    }
  }

  /* C.5.2 Test Vector Set 2 */
  {
    const unsigned char m[] = {0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf};
    const unsigned char h[16] = {0xa7,0x97,0x7e,0x88,0xbc,0x0b,0x61,0xe8,0x21,0x08,0x27,0x10,0x9a,0x22,0x8f,0x2d};

    aes_mmo(x, m, sizeof(m));
    print_result("C.5.2 Test Vector Set 2", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 2\n", stderr);
      return 1;
    }
  }

  /* C.5.3 Test Vector Set 3 */
  {
    unsigned char m[8191];
    const unsigned char h[] = {0x24,0xec,0x2f,0xe7,0x5b,0xbf,0xfc,0xb3,0x47,0x89,0xbc,0x06,0x10,0xe7,0xf1,0x65};

    for (i = 0; i < sizeof(m); i++) {
      m[i] = i;
    }
    aes_mmo(x, m, sizeof(m));
    //print_result("C.5.3 Test Vector Set 3", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 3\n", stderr);
      return 1;
    }
  }

  /* C.5.4 Test Vector 4 */
  {
    unsigned char m[8192];
    const unsigned char h[] = {0xdc,0x6b,0x06,0x87,0xf0,0x9f,0x86,0x07,0x13,0x1c,0x17,0x0b,0x3b,0xd3,0x15,0x91};

    for (i = 0; i < sizeof(m); i++) {
      m[i] = i;
    }
    aes_mmo(x, m, sizeof(m));
    //print_result("C.5.4 Test Vector 4", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 4\n", stderr);
      return 1;
    }
  }

  /* C.5.5 Test Vector 5 */
  {
    unsigned char m[8201];
    const unsigned char h[] = {0x72,0xc9,0xb1,0x5e,0x17,0x8a,0xa8,0x43,0xe4,0xa1,0x6c,0x58,0xe3,0x36,0x43,0xa3};

    for (i = 0; i < sizeof(m); i++) {
      m[i] = i;
    }
    aes_mmo(x, m, sizeof(m));
    //print_result("C.5.5 Test Vector 5", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 5\n", stderr);
      return 1;
    }
  }

  /* C.5.6 Test Vector 6 */
  {
    unsigned char m[8202];
    const unsigned char h[] = {0xbc,0x98,0x28,0xd5,0x9b,0x2a,0xa3,0x23,0xda,0xf2,0x0b,0xe5,0xf2,0xe6,0x65,0x11};

    for (i = 0; i < sizeof(m); i++) {
      m[i] = i;
    }
    aes_mmo(x, m, sizeof(m));
    //print_result("C.5.6 Test Vector 6", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 6\n", stderr);
      return 1;
    }
  }

  /* GVL: custom test 1 */
  {
    const unsigned char m[] = {0x01};
    const unsigned char h[16] = {0x82, 0xce, 0x43, 0xa1, 0x6d, 0xc6, 0xd3, 0xb6, 0xf4, 0xd1, 0xb3, 0x7e, 0x59, 0x6c, 0x1c, 0x9c};

    aes_mmo(x, m, sizeof(m));
    print_result("GVL: custom test 1", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 7\n", stderr);
      return 1;
    }
  }

  /* GVL: custom test 2: ZigBeeAlliance18 */
  {
    const unsigned char m[] = {0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C, 0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x31, 0x38}; //"ZigBeeAlliance18"
    const unsigned char h[16] = {0x90, 0x2B, 0x44, 0x85, 0xC8, 0x4E, 0xC4, 0xA0, 0x59, 0x44, 0xAB, 0x34, 0x42, 0x92, 0x68, 0x78};

    aes_mmo(x, m, sizeof(m));
    print_result("GVL: custom test 2: ZigBeeAlliance18", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 8\n", stderr);
      return 1;
    }
  }

  /* [ZIGBEE] Zigbee Direct Round 1 Message 2: H(xk || I || G) */
  {
    const unsigned char ai_reverse[8] = {
      0x01, 0x00, 0x00, 0x00, 0x00, 0xee, 0x1f, 0x00
    };
    const unsigned char ar_reverse[8] = {
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
    const unsigned char xk[32] = {
      0x2c, 0x2e, 0x83, 0x1b, 0x07, 0xf6, 0x09, 0x20,
      0x05, 0x70, 0x27, 0xe7, 0x89, 0x52, 0xf1, 0x6a,
      0x54, 0x41, 0xd6, 0x6d, 0x69, 0x4a, 0xdd, 0x3b,
      0xa0, 0x8a, 0x2b, 0xf5, 0x1a, 0xe2, 0x34, 0x28
    };
    const unsigned char G[32] = {
      0x90, 0x2b, 0x44, 0x85, 0xc8, 0x4e, 0xc4, 0xa0,
      0x59, 0x44, 0xab, 0x34, 0x42, 0x92, 0x68, 0x78,
      0x90, 0x2b, 0x44, 0x85, 0xc8, 0x4e, 0xc4, 0xa0,
      0x59, 0x44, 0xab, 0x34, 0x42, 0x92, 0x68, 0x78
    };

    unsigned char m[ sizeof(xk) +
                           sizeof(ai_reverse) +
                           sizeof(ar_reverse) +
                           sizeof(qi) + 
                           sizeof(qr) +
                           sizeof(G)
                          ] = { 0 };
    const unsigned char h[16] = {0xac, 0xb2, 0x8c, 0x1c, 0x8f, 0xf4, 0x2b, 0x0e, 0xbc, 0xf8, 0x47, 0xbd, 0x05, 0xe8, 0xcd, 0xc0};

    // m = xk || di || dr || Qi || Qr || G
    int offset = 0;
    for (i=0; i<sizeof(xk); i++) {
      m[offset+i] = xk[i];
    }
    offset += sizeof(xk);
    for (i=0; i<sizeof(ai_reverse); i++) {
      m[offset+i] = ai_reverse[i];
    }
    offset += sizeof(ai_reverse);
    for (i=0; i<sizeof(qi); i++) {
      m[offset+i] = qi[i];
    }
    offset += sizeof(qi);
    for (i=0; i<sizeof(ar_reverse); i++) {
      m[offset+i] = ar_reverse[i];
    }
    offset += sizeof(ar_reverse);
    for (i=0; i<sizeof(qr); i++) {
      m[offset+i] = qr[i];
    }
    offset += sizeof(qr);
    for (i=0; i<sizeof(G); i++) {
      m[offset+i] = G[i];
    }

    aes_mmo(x, m, sizeof(m));
    print_result("Zigbee Direct Round 1 Message 2: H(xk || I || G)", m, sizeof(m), x, h);
    if (memcmp(x, h, 16)) {
      fputs("aes_mmo() failed test vector 9\n", stderr);
      return 1;
    }
  }

  return 0;
}
