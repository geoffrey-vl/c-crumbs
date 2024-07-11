/*
 * tests/aes-ccm.c: tests for ../aes-ccm.h
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/tests/aes-ccm.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../aes.h"
#include "../aes-ccm.h"
#include <stdio.h>
#include <string.h>


void print_buffer(const unsigned char a[], int length)
{
  int i;
  for (i=0; i<length; i++) {
    printf("0x%02X ", a[i]);
  };
}

void print_result(const char* test, const unsigned char x[], int x_length, const unsigned char ciphertext[], int mac_length, 
                  const unsigned char nonce[], int nonce_length, const unsigned char ad[], int ad_length, 
                  const unsigned char payload[], int payload_length, const unsigned char key[])
{
  printf("---------%s---------\n", test);
  printf("  payload: [ ");
  print_buffer(payload, payload_length);
  printf("]\n  key: [ ");
  print_buffer(key, 16);
  printf("]\n  nonce: [ ");
  print_buffer(nonce, nonce_length);
  printf("]\n  associated data: [ ");
  print_buffer(ad, ad_length);
  printf("]\n  converted ciphertext: [ ");
  print_buffer(x, x_length);
  printf("]\n  expected ciphertext: [ ");
  print_buffer(ciphertext, mac_length);
  printf("]\n");
}

/*
 * Tests the aes_ccm_encrypt/decrypt functions with the values in:
 *
 *    [CCM] Recommendation for Block Cipher Modes of Operation:
 *          The CCM Mode for Authentication and Confidentiality
 *          NIST Special Publication 800-38C, May 2004
 *          Appendix C Example Vectors
 *
 * [ZIGBEE] ZigBee Specification, document 053474r20, Sep 2012
 *          Annex C Test Vectors for Cryptographic Building Blocks
 */
int main(int argc, char **argv) {

  /* [CCM] C.1 Example 1 */
  {
    const unsigned char key[16] = {
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    const unsigned char nonce[7] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    };
    const unsigned char ad[8] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    const unsigned char payload[4] = {
      0x20, 0x21, 0x22, 0x23
    };
    const unsigned char ciphertext[4 + 4] = {
      0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d
    };
    unsigned char x[sizeof(ciphertext)];

    aes_ccm_encrypt(x, 4, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    print_result("[CCM] C.1 Example 1 (encrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed CCM example 1\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 4, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    print_result("[CCM] C.1 Example 1 (decrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed CCM example 1\n", stderr);
      return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed CCM example 1\n", stderr);
      return 1;
    }
  }

  /* [CCM] C.2 Example 2 */
  {
    const unsigned char key[16] = {
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    const unsigned char nonce[8] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    const unsigned char ad[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char payload[16] = {
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    const unsigned char ciphertext[16 + 6] = {
      0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
      0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
      0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd
    };
    unsigned char x[sizeof(ciphertext)];

    aes_ccm_encrypt(x, 6, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    print_result("[CCM] C.2 Example 2 (encrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed CCM example 2\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 6, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    print_result("[CCM] C.2 Example 2 (decrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed CCM example 2\n", stderr);
      return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed CCM example 2\n", stderr);
      return 1;
    }
  }

  /* [CCM] C.3 Example 3 */
  {
    const unsigned char key[16] = {
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    const unsigned char nonce[12] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b
    };
    const unsigned char ad[20] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13
    };
    const unsigned char payload[24] = {
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    const unsigned char ciphertext[24 + 8] = {
      0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
      0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
      0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
      0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51
    };
    unsigned char x[sizeof(ciphertext)];

    aes_ccm_encrypt(x, 8, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    print_result("[CCM] C.3 Example 3 (encrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed CCM example 3\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 8, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    print_result("[CCM] C.3 Example 3 (decrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed CCM example 3\n", stderr);
      return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed CCM example 3\n", stderr);
      return 1;
    }
  }

  /* [CCM] C.4 Example 4 */
  {
    const unsigned char key[16] = {
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    const unsigned char nonce[13] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c
    };
    unsigned char ad[65536];
    const unsigned char payload[32] = {
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    const unsigned char ciphertext[32 + 14] = {
      0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37,
      0x6a, 0x68, 0xc2, 0x96, 0x7e, 0x4d, 0xab, 0x61,
      0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4,
      0x84, 0x82, 0x85, 0x29, 0x46, 0x3c, 0xcf, 0x72,
      0xb4, 0xac, 0x6b, 0xec, 0x93, 0xe8, 0x59, 0x8e,
      0x7f, 0x0d, 0xad, 0xbc, 0xea, 0x5b
    };
    unsigned char x[sizeof(ciphertext)];
    unsigned i;

    for (i = 0; i < sizeof(ad); i++) {
      ad[i] = i;
    }
    aes_ccm_encrypt(x, 14, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    //print_result("[CCM] C.4 (encrypt)", 
    //  x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed CCM example 4\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 14, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    //print_result("[CCM] C.4 (decrypt)", 
    //  x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed CCM example 4\n", stderr);
      return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed CCM example 4\n", stderr);
      return 1;
    }
  }

  /* [ZIGBEE] C.3 CCM* Mode Encryption and Authentication Transformation */
  {
    const unsigned char key[16] = {
      0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
    };
    const unsigned char nonce[13] = {
      0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0x03, 0x02, 0x01, 0x00, 0x06
    };
    const unsigned char ad[8] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    const unsigned char payload[23] = {
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
    };
    const unsigned char ciphertext[23 + 8] = {
      0x1a, 0x55, 0xa3, 0x6a, 0xbb, 0x6c, 0x61, 0x0d,
      0x06, 0x6b, 0x33, 0x75, 0x64, 0x9c, 0xef, 0x10,
      0xd4, 0x66, 0x4e, 0xca, 0xd8, 0x54, 0xa8, 0x0a,
      0x89, 0x5c, 0xc1, 0xd8, 0xff, 0x94, 0x69
    };
    unsigned char x[sizeof(ciphertext)];

    aes_ccm_encrypt(x, 8, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    print_result("[CCM] C.3 (encrypt)", x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed ZigBee example\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 8, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    print_result("[CCM] C.3 (decrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed ZigBee example\n", stderr);
      return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed ZigBee example\n", stderr);
      return 1;
    }
  }

  /* [ZIGBEE DIRECT] B.4 Accessing secure characteristics via AES-CCM-128 */
  {
    // BLE consts
    const unsigned char service_uuid[16] = {
      0x00, 0x00, 0xff, 0xf7, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
    const unsigned char service_instance[1] = {0x00};
    const unsigned char characteristic_uuid[16] = {
      0x70, 0x72, 0x37, 0x7d, 0x00, 0x02, 0x42, 0x1c, 0xb1, 0x63, 0x49, 0x1c, 0x27, 0x33, 0x3a, 0x61};
    const unsigned char characteristic_instance[1] = {0x00};
    // device
    const unsigned char reverse_eui64[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0xee, 0x1f, 0x00};
    // security counters
    const unsigned char frame_counter[4] = {0x02, 0x00, 0x00, 0x00};
    const unsigned char control_field[1] = {0x05};

    const unsigned char payload[45] = {
      0x07, 0x00, 0x03, 0x00, 0x07, 0xd9, 0x1f, 0x00, 0x00, 0x00, 0xae, 0x1f, 0x00, 0x01, 
      0x01, 0x26, 0x90, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x03, 0x0f, 0x5c, 0xd2, 0xf8,
      0xbe, 0xd4, 0xea, 0x50, 0x56, 0xac, 0x02, 0xa8, 0xee, 0x84, 0x1a, 0xa0, 0x86, 0x06, 
      0x01, 0xcd, 0xab};


    const unsigned char key[16] = {
      0xa2, 0xe2, 0xb6, 0x1b, 0xf1, 0xa8, 0x05, 0x81, 0xd0, 0x7f, 0x1f, 0x06, 0x72, 0xd1, 0xd6, 0x24
    };

    // construct nonce
    unsigned char nonce[sizeof(reverse_eui64) + sizeof(frame_counter) + sizeof(control_field)] = {0x00};
    int offset = 0;
    for(int i=0; i<sizeof(reverse_eui64); i++) {
      nonce[offset + i] = reverse_eui64[i];
    }
    offset += sizeof(reverse_eui64);
    for(int i=0; i<sizeof(frame_counter); i++) {
      nonce[offset + i] = frame_counter[i];
    }
    offset += sizeof(frame_counter);
    for(int i=0; i<sizeof(control_field); i++) {
      nonce[offset + i] = control_field[i];
    }
    // construct authentication data
    unsigned char ad[sizeof(service_uuid) + 
                                  sizeof(service_instance) + 
                                  sizeof(characteristic_uuid) +
                                  sizeof(characteristic_instance) ] = {0x00};
    offset = 0;
    for(int i=0; i<sizeof(service_uuid); i++) {
      ad[offset + i] = service_uuid[i];
    }
    offset += sizeof(service_uuid);
    for(int i=0; i<sizeof(service_instance); i++) {
      ad[offset + i] = service_instance[i];
    }
    offset += sizeof(service_instance);
    for(int i=0; i<sizeof(characteristic_uuid); i++) {
      ad[offset + i] = characteristic_uuid[i];
    }
    offset += sizeof(characteristic_uuid);
    for(int i=0; i<sizeof(characteristic_instance); i++) {
      ad[offset + i] = characteristic_instance[i];
    }

    // 0..44 encrypted data, 45..49 integrity code
    const unsigned char ciphertext[45 + 4] = {
      0x23, 0xb7, 0x11, 0xa6, 0x91, 0x6a, 0xba, 0x32, 0x82, 0xb3, 0x7a, 0x7c, 0xb4, 0x4f,
      0x30, 0x18, 0x7c, 0x43, 0xc2, 0x45, 0xd3, 0xbd, 0x6f, 0xf1, 0xaf, 0xe5, 0x9d, 0x0b,
      0x3a, 0x9b, 0x0f, 0xda, 0xc5, 0x26, 0xd3, 0x63, 0x3d, 0xae, 0xdf, 0x73, 0x5d, 0x78,
      0x35, 0xfe, 0x9f,
      0x3f, 0x12, 0xbd, 0xf8};
    unsigned char x[sizeof(ciphertext)];

    aes_ccm_encrypt(x, 4, nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    print_result("[ZIGBEE DIRECT] B.4 Accessing secure characteristics via AES-CCM-128 (encrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (memcmp(x, ciphertext, sizeof(ciphertext))) {
      fputs("aes_ccm_encrypt() failed ZigBee example\n", stderr);
      return 1;
    }

    int mac_err = aes_ccm_decrypt(x, 4, nonce, sizeof(nonce), ad, sizeof(ad), ciphertext, sizeof(ciphertext), key);
    print_result("[ZIGBEE DIRECT] B.4 Accessing secure characteristics via AES-CCM-128 (decrypt)", 
      x, sizeof(x), ciphertext, sizeof(ciphertext), nonce, sizeof(nonce), ad, sizeof(ad), payload, sizeof(payload), key);
    if (mac_err) {
      fputs("aes_ccm_decrypt() tag failed ZigBee example\n", stderr);
      //return 1;
    }
    if (memcmp(x, payload, sizeof(payload))) {
      fputs("aes_ccm_decrypt() payload failed ZigBee example\n", stderr);
      return 1;
    }
  }

  return 0;
}
