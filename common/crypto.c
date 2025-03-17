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

void handleErrors() {
  fprintf(stderr, "An error occurred\n");
  exit(1);
}

/**
 * There are some security concerns because the IV is based on the PIN. Generating IV randomly would fix the issue.
 */
void derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv) {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    handleErrors();
  }

  uint8_t hash[PSA_HASH_MAX_SIZE];
  psa_algorithm_t alg = PSA_ALG_SHA_256;
  psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

  status = psa_hash_setup(&operation, alg);
  if (status != PSA_SUCCESS) {
    handleErrors();
  }

  status = psa_hash_update(&operation, (const uint8_t *)pin, strlen(pin));
  if (status != PSA_SUCCESS) {
    psa_hash_abort(&operation);
    handleErrors();
  }

  size_t hash_length;
  status = psa_hash_finish(&operation, hash, PSA_HASH_MAX_SIZE, &hash_length);
  if (status != PSA_SUCCESS) {
    psa_hash_abort(&operation);
    handleErrors();
  }

  // First 32 bytes for the key
  memcpy(key, hash, AES_256_KEY_SIZE);

  // Last 16 bytes for the IV
  memcpy(iv, hash + AES_256_KEY_SIZE - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

  psa_hash_abort(&operation);
  mbedtls_psa_crypto_free();
}

int encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext) {
  psa_status_t status = psa_crypto_init();

  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

  psa_key_id_t key_id;
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 256);
  status = psa_import_key(&attr, pin, AES_256_KEY_SIZE, &key_id);

  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }
  psa_reset_key_attributes(&attr);

  status = psa_cipher_encrypt_setup(&operation, key_id, alg);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  status = psa_cipher_set_iv(&operation, iv, AES_BLOCK_SIZE);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  size_t key_len = strlen((char *)key);
  size_t len = 0, ciphertext_len = 0;

  while (key_len > 0) {
    size_t chunk_size = key_len > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : key_len;
    status = psa_cipher_update(&operation, key, chunk_size, ciphertext + ciphertext_len, AES_BLOCK_SIZE, &len);
    if (status != PSA_SUCCESS)
      return 0;

    key += chunk_size;
    key_len -= chunk_size;
    ciphertext_len += len;
  }

  status = psa_cipher_finish(&operation, ciphertext + ciphertext_len, AES_BLOCK_SIZE, &len);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }
  ciphertext_len += len;

  psa_cipher_abort(&operation);
  psa_destroy_key(key_id);
  mbedtls_psa_crypto_free();
  return ciphertext_len;
}

int decrypt_private_key(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *pin, const uint8_t *iv,
                        uint8_t *plaintext, size_t *plaintext_len) {
  psa_status_t status = psa_crypto_init();

  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

  psa_key_id_t key_id;
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 256);
  status = psa_import_key(&attr, pin, AES_256_KEY_SIZE, &key_id);

  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }
  psa_reset_key_attributes(&attr);

  status = psa_cipher_decrypt_setup(&operation, key_id, alg);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  status = psa_cipher_set_iv(&operation, iv, AES_BLOCK_SIZE);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }
  size_t len = 0, total_len = 0;

  status = psa_cipher_update(&operation, ciphertext, ciphertext_len, plaintext, *plaintext_len, &len);
  if (status != PSA_SUCCESS) {
    psa_cipher_abort(&operation);
    return 0;
  }
  total_len = len;

  status = psa_cipher_finish(&operation, plaintext + total_len, *plaintext_len - total_len, &len);
  if (status != PSA_SUCCESS) {
    psa_cipher_abort(&operation);
    return 0;
  }
  total_len += len;
  *plaintext_len = total_len;

  psa_cipher_abort(&operation);
  psa_destroy_key(key_id);
  mbedtls_psa_crypto_free();

  return 1;
}

/**
 * This function adds Initialization Vector at the beginning of encrypted private key file, but it isn't neccessary with
 * current implementation of derive_key_iv(). Either it should be removed or derive_key_iv() function should be updated
 * in the future.
 */
void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file) {
  uint8_t key[AES_256_KEY_SIZE], iv[AES_BLOCK_SIZE];
  derive_key_iv(pin, key, iv);

  int ret;
  mbedtls_pk_context key_ctx;
  mbedtls_entropy_context entropy = {0};
  mbedtls_ctr_drbg_context rng_ctx = {0};
  const char *seed = "rsa_gen";

  mbedtls_pk_init(&key_ctx);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng_ctx);

  ret = mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy, (const uint8_t *)seed, strlen(seed));
  if (ret != 0) {
    handleErrors();
  }

  ret = mbedtls_pk_setup(&key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) {
    handleErrors();
  }

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key_ctx), mbedtls_ctr_drbg_random, &rng_ctx, RSA_KEY_SIZE, 65537);
  if (ret != 0) {
    handleErrors();
  }

  uint8_t priv_key[RSA_KEY_SIZE * 2] = {0};
  uint8_t enc_priv_key[RSA_KEY_SIZE * 2] = {0};
  uint8_t pub_key[RSA_KEY_SIZE * 2];
  FILE *private_key_file_fp = fopen(private_key_file, "wb");
  if (private_key_file_fp) {
    mbedtls_pk_write_key_pem(&key_ctx, priv_key, RSA_KEY_SIZE * 2);
    int key_len = encrypt_private_key(priv_key, key, iv, enc_priv_key);
    fwrite(enc_priv_key, 1, key_len, private_key_file_fp);
    fclose(private_key_file_fp);
  }

  FILE *public_key_fp = fopen(public_key_file, "wb");
  if (public_key_fp) {
    mbedtls_pk_write_pubkey_pem(&key_ctx, pub_key, RSA_KEY_SIZE * 2);
    fwrite(pub_key, 1, strlen((char *)pub_key), public_key_fp);
    fclose(public_key_fp);
  }

  mbedtls_pk_free(&key_ctx);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&rng_ctx);
}

void decrypt_and_load_private_key(const char *private_key_file, const char *pin) {
  FILE *fp = fopen(private_key_file, "rb");
  if (!fp) {
    perror("Failed to open encrypted private key file");
    return;
  }

  // Read IV
  // uint8_t iv[AES_BLOCK_SIZE];
  // if (fread(iv, 1, AES_BLOCK_SIZE, fp) != AES_BLOCK_SIZE) {
  //   fprintf(stderr, "Failed to read IV\n");
  //   fclose(fp);
  //   return NULL;
  // }

  // Read encrypted key data
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  uint8_t *ciphertext = calloc(file_size + 1, 1);
  if (!ciphertext) {
    fprintf(stderr, "Memory allocation error\n");
    fclose(fp);
    return;
  }

  if (fread(ciphertext, 1, file_size, fp) != file_size) {
    fprintf(stderr, "Failed to read encrypted private key\n");
    fclose(fp);
    free(ciphertext);
    return;
  }
  fclose(fp);

  uint8_t key[AES_256_KEY_SIZE], iv[AES_BLOCK_SIZE];
  derive_key_iv(pin, key, iv);

  uint8_t plaintext[8192] = {0};
  size_t plaintext_len = 8192;
  decrypt_private_key(ciphertext, file_size, key, iv, plaintext, &plaintext_len);

  mbedtls_pk_context key_ctx;
  int ret = mbedtls_pk_parse_key(&key_ctx, plaintext, plaintext_len + 1, NULL, 0, NULL, NULL);
  if (ret != 0) {
    printf("Failed to load private key\n");
    free(ciphertext);
    mbedtls_pk_free(&key_ctx);
    return;
  }

  free(ciphertext);
  mbedtls_pk_free(&key_ctx);
}
