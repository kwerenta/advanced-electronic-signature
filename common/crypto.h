#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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
 * @param[in] pin PIN in form of plaintext based on which key and IV will be created
 * @param[out] key Buffer where generated key will be put. **Must** be size of #AES_256_KEY_SIZE
 * @param[out] iv Buffer where generated initialization vector will be put. **Must** be size of #AES_BLOCK_SIZE
 * @retval 0 On success
 * @retval PSA_ERROR_CODE On any Mbed TLS function error
 */
int derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv);
/**
 * @brief Internal function that simplifies AES encryption process
 * @param decrypt Boolean that determines wheter it should perform decryption or encryption
 * @param[in] key Key that will be used to decrypt/encrypt input data
 * @param[in] iv Initialization Vector that will be used to decrypt/encrypt input data
 * @param[in] input Data to decrypt/encrypt
 * @param input_len Size of input
 * @param[out] output Buffer where decrypted/encrypted data will be stored
 * @param[in,out] output_len Length of decrypted/encrypted data. It **must be** initialized with size of output buffer
 * @retval 0 On success
 * @retval PSA_ERROR_CODE On any Mbed TLS function error
 */
int perform_aes_cipher_operation(uint8_t decrypt, const uint8_t *key, const uint8_t *iv, const uint8_t *input,
                                 const size_t input_len, uint8_t *output, size_t *output_len);
/**
 * @brief Encrypts RSA private key using AES-256-CBC and provided PIN as key
 * @param[in] pin PIN that will be used to encrypt private key
 * @param[in] iv Initialization Vector used in AES-256 encryption
 * @param[in] key Private key in form of plain text that will be encrypted
 * @param[out] ciphertext Buffer where encrypted private key will be stored
 * @param[in,out] ciphertext_len Length of generated ciphertext. It **must be** initialized with size of ciphertext
 * buffer
 * @retval 0 On success
 * @retval PSA_ERROR_CODE On any Mbed TLS function error
 */
int encrypt_private_key(const uint8_t *pin, const uint8_t *iv, const uint8_t *key, uint8_t *ciphertext,
                        size_t *ciphertext_len);
/**
 * @brief Decrypts RSA private key using provided PIN
 * @param[in] pin PIN that will be used to decrypt private key
 * @param[in] iv Initialization Vector used in AES-256 decryption
 * @param[in] key Private key in form of cipher text that will be decrypted
 * @param key_len Size of key
 * @param[out] plaintext Buffer where decrypted private key will be stored
 * @param[in,out] plaintext_len Length of generated plaintext. It **must be** initialized with size of plaintext buffer
 * @retval 0 On success
 * @retval PSA_ERROR_CODE On any Mbed TLS function error
 */
int decrypt_private_key(const uint8_t *pin, const uint8_t *iv, const uint8_t *key, size_t key_len, uint8_t *plaintext,
                        size_t *plaintext_len);
/**
 * @brief Generates and saves RSA key pair where private key is encrypted
 * @param[in] pin PIN in plaintext form used to encrypt private key
 * @param[in] private_key_file Path to file where encrypted private key will be stored
 * @param[in] public_key_file Path to file where public key will be stored
 */
void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file);
/**
 * @brief Loads encrypted private RSA key from PEM file and decrypts it
 * @param[in] pin PIN in plaintext form used to decrypt private key
 * @param[in] private_key_file Path to encrypted private key file
 * @return Null terminated buffer with decrypted private key or NULL if error occur
 */
uint8_t *load_encrypted_private_key(const char *pin, const char *private_key_file);

/**
 * @brief Computes hash of provided PDF file content
 * @param pdf_file PDF file whose hash will be computed of
 * @paramhash Buffer where computed hash will be stored. Need to be size of PSA_HASH_MAX_SIZE (64).
 * @param size Number of bytes in pdf_file starting from beginning that will be used to compute hash. This function will
 * use whole pdf_file size if 0 is provided.
 */
void compute_pdf_hash(FILE *pdf_file, uint8_t *hash, size_t size);
/**
 * @brief Creates signature of hash with provided private key
 * @param hash Computed hash that will be signed
 * @param private_key Private key that will be used to sign hash
 * @param[out] sign Buffer where signature will be stored. Need to be size of PSA_SIGNATURE_MAX_SIZE (512).
 */
void sign_hash(const uint8_t *hash, const uint8_t *private_key, uint8_t *sign);

/**
 * @brief Creates signature for PDF file and adds it to the end of the file
 * @param pdf_path Path to PDF file that will be signed
 * @param private_key Decrypted private key that will be used to sign hash
 */
void sign_pdf_file(const char *pdf_path, const uint8_t *private_key);

/**
 * @brief Verifies PDF file signature using provided public key
 * @param pdf_path Path to PDF file whose hash will be verified
 * @param public_key_path Path to public key .pem file that will be used for hash verification
 */
void verify_pdf_signature(const char *pdf_path, const char *public_key_path);

#endif
