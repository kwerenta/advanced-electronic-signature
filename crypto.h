#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#define AES_256_KEY_SIZE (32)
#define AES_BLOCK_SIZE (16)

#define RSA_KEY_SIZE (4096)

void derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv);
int encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext);

void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file);

#endif
