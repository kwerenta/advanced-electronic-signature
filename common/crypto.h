#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Size of AES-256 key (256 bits = 32 bytes)
 */
#define AES_256_KEY_SIZE (32)
/**
 * @brief Size of single block in AES-256 (16 bytes)
 */
#define AES_BLOCK_SIZE (16)

/**
 * @brief Size of RSA private key used in this application
 */
#define RSA_KEY_SIZE (4096)

/**
 * @brief Derives AES key and initialization vector from PIN
 *
 * AES-256 key has fixed size of 256 bits. This function allows to use variable length PINs that will work with AES
 * encryption.
 *
 * @param pin PIN based on which key and IV will be created
 * @param key Buffer where generated key will be put. **Must** be size of #AES_256_KEY_SIZE
 * @param iv Buffer where generated initialization vector will be put. **Must** be size of #AES_BLOCK_SIZE
 */
void derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv);
/**
 * @brief Encrypts RSA private key of size #RSA_KEY_SIZE using AES-256-CBC and provided PIN as key
 * @param key Private key in form of plain text
 * @param pin PIN that will be used to encrypt private key
 * @param iv Initialization Vector used in AES-256 encryption
 * @param ciphertext Buffer where encrypted private key will be stored
 * @return Length of created ciphertext
 */
int encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext);
/**
 * @brief Decrypts RSA private key using provided PIN
 * @param key Private key in form of cipher texted
 * @param key_len Length of key
 * @param pin PIN that will be used to decrypt private key
 * @param iv Initialization Vector used in AES-256 decryption
 * @param plaintext Buffer where decrypted private key will be stored
 * @return Length of created plaintext
 */
int decrypt_private_key(const uint8_t *key, int key_len, const uint8_t *pin, const uint8_t *iv, uint8_t *plaintext,
                        size_t *plaintext_len);

/**
 * @brief Generates and saves RSA key pair where private key is encrypted
 * @param pin PIN used to encrypt private key
 * @param private_key_file Path to file where encrypted private key will be stored
 * @param public_key_file Path to file where public key will be stored
 */
void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file);
/**
 * @brief Decrypts encrypted RSA private key and loads it into OpenSSL EVP_PKEY structure
 * @param private_key_file Path to encrypted private key file
 * @param pin PIN used to decrypt private key
 * @return EVP_PKEY strcutre with decrypted private key or NULL if failed to decrypt private key. EVP_PKEY should be
 * freed with EVP_PKEY_free() function
 */
void decrypt_and_load_private_key(const char *private_key_file, const char *pin);

#endif
