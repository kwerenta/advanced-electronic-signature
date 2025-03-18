#include "crypto.h"
#include "mbedtls/entropy.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <psa/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * There are some security concerns because the IV is based on the PIN. Generating IV randomly would fix the issue.
 */
int derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv) {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    return status;
  }

  uint8_t hash[PSA_HASH_MAX_SIZE];
  psa_algorithm_t alg = PSA_ALG_SHA_256;
  psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

  status = psa_hash_setup(&operation, alg);
  if (status != PSA_SUCCESS) {
    return status;
  }

  status = psa_hash_update(&operation, (const uint8_t *)pin, strlen(pin));
  if (status != PSA_SUCCESS) {
    psa_hash_abort(&operation);
    return status;
  }

  size_t hash_length;
  status = psa_hash_finish(&operation, hash, PSA_HASH_MAX_SIZE, &hash_length);
  if (status != PSA_SUCCESS) {
    psa_hash_abort(&operation);
    return status;
  }

  // First 32 bytes for the key
  memcpy(key, hash, AES_256_KEY_SIZE);

  // Last 16 bytes for the IV
  memcpy(iv, hash + AES_256_KEY_SIZE - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

  psa_hash_abort(&operation);
  mbedtls_psa_crypto_free();

  return 0;
}

int perform_aes_cipher_operation(uint8_t decrypt, const uint8_t *key, const uint8_t *iv, const uint8_t *input,
                                 const size_t input_len, uint8_t *output, size_t *output_len) {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    return status;
  }

  psa_key_id_t key_id;
  psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

  psa_set_key_usage_flags(&attr, decrypt == 0 ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 256);

  status = psa_import_key(&attr, key, AES_256_KEY_SIZE, &key_id);
  if (status != PSA_SUCCESS) {
    return status;
  }
  psa_reset_key_attributes(&attr);

  status = decrypt == 0 ? psa_cipher_encrypt_setup(&operation, key_id, alg)
                        : psa_cipher_decrypt_setup(&operation, key_id, alg);
  if (status != PSA_SUCCESS) {
    psa_destroy_key(key_id);
    return status;
  }

  status = psa_cipher_set_iv(&operation, iv, AES_BLOCK_SIZE);
  if (status != PSA_SUCCESS) {
    psa_destroy_key(key_id);
    psa_cipher_abort(&operation);
    return status;
  }

  size_t len = 0, total_len = 0;
  status = psa_cipher_update(&operation, input, input_len, output, *output_len, &len);
  if (status != PSA_SUCCESS) {
    psa_destroy_key(key_id);
    psa_cipher_abort(&operation);
    return status;
  }
  total_len = len;

  status = psa_cipher_finish(&operation, output + total_len, *output_len - total_len, &len);
  if (status != PSA_SUCCESS) {
    psa_destroy_key(key_id);
    psa_cipher_abort(&operation);
    return status;
  }
  total_len += len;
  *output_len = total_len;

  psa_cipher_abort(&operation);
  psa_destroy_key(key_id);
  mbedtls_psa_crypto_free();

  return 0;
}

int encrypt_private_key(const uint8_t *pin, const uint8_t *iv, const uint8_t *key, uint8_t *ciphertext,
                        size_t *ciphertext_len) {
  size_t key_len = strlen((char *)key);
  return perform_aes_cipher_operation(0, pin, iv, key, key_len, ciphertext, ciphertext_len);
}

int decrypt_private_key(const uint8_t *pin, const uint8_t *iv, const uint8_t *key, size_t key_len, uint8_t *plaintext,
                        size_t *plaintext_len) {
  return perform_aes_cipher_operation(1, pin, iv, key, key_len, plaintext, plaintext_len);
}

/**
 * This function adds Initialization Vector at the beginning of encrypted private key file, but it isn't neccessary with
 * current implementation of derive_key_iv(). Either it should be removed or derive_key_iv() function should be updated
 * in the future.
 */
void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file) {
  uint8_t key[AES_256_KEY_SIZE], iv[AES_BLOCK_SIZE];
  int ret = derive_key_iv(pin, key, iv);
  if (ret != 0) {
    printf("Failed ot derive key and iv from pin");
    return;
  }

  mbedtls_pk_context key_ctx;
  mbedtls_entropy_context entropy = {0};
  mbedtls_ctr_drbg_context rng_ctx = {0};
  const char *seed = "rsa_gen";

  mbedtls_pk_init(&key_ctx);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng_ctx);

  ret = mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy, (const uint8_t *)seed, strlen(seed));
  if (ret != 0) {
    mbedtls_pk_free(&key_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_ctx);

    printf("Failed to initialize RNG\n");
    return;
  }

  ret = mbedtls_pk_setup(&key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) {
    mbedtls_pk_free(&key_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_ctx);

    printf("Failed to initialize RNG\n");
    return;
  }

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key_ctx), mbedtls_ctr_drbg_random, &rng_ctx, RSA_KEY_SIZE, 65537);
  if (ret != 0) {
    mbedtls_pk_free(&key_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_ctx);

    printf("Failed to generate RSA keypair\n");
    return;
  }

  uint8_t enc_priv_key[RSA_KEY_SIZE * 2] = {0}, priv_key[RSA_KEY_SIZE * 2] = {0}, pub_key[RSA_KEY_SIZE * 2] = {0};

  FILE *private_key_file_fp = fopen(private_key_file, "wb");
  if (private_key_file_fp == NULL) {
    mbedtls_pk_free(&key_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_ctx);

    perror("Failed to open private key file");
    return;
  }

  size_t key_len = RSA_KEY_SIZE * 2;
  mbedtls_pk_write_key_pem(&key_ctx, priv_key, key_len);
  encrypt_private_key(key, iv, priv_key, enc_priv_key, &key_len);

  fwrite(iv, 1, AES_BLOCK_SIZE, private_key_file_fp);
  fwrite(enc_priv_key, 1, key_len, private_key_file_fp);
  fclose(private_key_file_fp);

  FILE *public_key_fp = fopen(public_key_file, "wb");
  if (private_key_file_fp == NULL) {
    mbedtls_pk_free(&key_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_ctx);

    perror("Failed to open public key file");
    return;
  }

  mbedtls_pk_write_pubkey_pem(&key_ctx, pub_key, RSA_KEY_SIZE * 2);
  fwrite(pub_key, 1, strlen((char *)pub_key), public_key_fp);
  fclose(public_key_fp);

  mbedtls_pk_free(&key_ctx);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&rng_ctx);
}

uint8_t *load_encrypted_private_key(const char *pin, const char *private_key_file) {
  FILE *fp = fopen(private_key_file, "rb");
  if (!fp) {
    perror("Failed to open encrypted private key file");
    return NULL;
  }

  uint8_t iv[AES_BLOCK_SIZE];
  if (fread(iv, 1, AES_BLOCK_SIZE, fp) != AES_BLOCK_SIZE) {
    fprintf(stderr, "Failed to read IV\n");
    fclose(fp);
    return NULL;
  }

  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp) - AES_BLOCK_SIZE;
  fseek(fp, AES_BLOCK_SIZE, SEEK_SET);

  uint8_t *ciphertext = calloc(file_size + 1, 1);
  if (!ciphertext) {
    fprintf(stderr, "Memory allocation error\n");
    fclose(fp);
    return NULL;
  }

  if (fread(ciphertext, 1, file_size, fp) != file_size) {
    fprintf(stderr, "Failed to read encrypted private key\n");
    fclose(fp);
    free(ciphertext);
    return NULL;
  }
  fclose(fp);

  uint8_t key[AES_256_KEY_SIZE], iv_null[AES_BLOCK_SIZE];
  derive_key_iv(pin, key, iv_null);

  size_t plaintext_len = RSA_KEY_SIZE * 2 - 1;
  uint8_t *plaintext = calloc(plaintext_len + 1, 1);
  if (!plaintext) {
    fprintf(stderr, "Memory allocation error\n");
    free(ciphertext);
    fclose(fp);
    return NULL;
  }

  int ret = decrypt_private_key(key, iv, ciphertext, file_size, plaintext, &plaintext_len);
  if (ret != 0) {
    printf("Invalid PIN to decrypt private key\n");
    free(ciphertext);
    free(plaintext);
    return NULL;
  }

  mbedtls_pk_context key_ctx;
  mbedtls_pk_init(&key_ctx);

  ret = mbedtls_pk_parse_key(&key_ctx, plaintext, plaintext_len + 1, NULL, 0, NULL, NULL);
  if (ret != 0) {
    printf("Failed to parse private key\n");
    free(ciphertext);
    free(plaintext);
    mbedtls_pk_free(&key_ctx);
    return NULL;
  }

  free(ciphertext);
  mbedtls_pk_free(&key_ctx);
  return plaintext;
}
