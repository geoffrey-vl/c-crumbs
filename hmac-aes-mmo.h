#include <stdlib.h>

#define BLOCK_SIZE 16 // 128 bits

const unsigned char ipad[16] = {0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36};
const unsigned char opad[16] = {0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C};

void xorKeyWithByte(const unsigned char key[BLOCK_SIZE], unsigned char byte, unsigned char result[BLOCK_SIZE]) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        result[i] = key[i] ^ byte;
    }
}

/**
 * @brief 
 * 
 * @param output output data, should be 16-bytes
 * @param input input data to encrypt
 * @param data_length length of the input data
 * @param key 128-bit session key
 */
static void hmac_aes_mmo(unsigned char *output, const unsigned char *input, int data_length, const unsigned char *key) {
  unsigned char key_buff[BLOCK_SIZE];

  // Form the inner key Key1 by XOR-ing the bit string Key and the octet string ipad
  for (int i = 0; i < BLOCK_SIZE; i++) {
    key_buff[i] = key[i] ^ ipad[i];
  }
  // Form the padded message M1 by right-concatenating the bit string Key1 with the bit string M:
  unsigned char* m1 = malloc(data_length + BLOCK_SIZE);
  for(int i=0; i<sizeof(key_buff); i++) {
    m1[i] = key_buff[i];
  }
  int offset = sizeof(key_buff);
  for(int i=0; i<data_length; i++) {
    m1[offset+i] = input[i];
  }
  // Compute the hash value Hash1 of the bit string M1:
  aes_mmo(output, m1, data_length + sizeof(key_buff));
  free(m1);

  // Form the outer key Key2 by XOR-ing the bit string Key and the octet string opad:
  for (int i = 0; i < BLOCK_SIZE; i++) {
    key_buff[i] = key[i] ^ opad[i];
  }
  // Form the padded message M2 by right-concatenating the bit string Key2 with the bit string Hash1:
  unsigned char* m2 = malloc(sizeof(key_buff) + BLOCK_SIZE);
  for(int i=0; i<sizeof(key_buff); i++) {
    m2[i] = key_buff[i];
  }
  offset = sizeof(key_buff);
  for(int i=0; i<BLOCK_SIZE; i++) {
    m2[offset+i] = output[i];
  }
  // Compute the hash value Hash2 of the bit string M2:
  aes_mmo(output, m2, sizeof(key_buff) + BLOCK_SIZE);
  free(m2);
}
