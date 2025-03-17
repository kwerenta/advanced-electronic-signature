#include "crypto.h"
#include "mbedtls/entropy.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <psa/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void handleErrors() {
  fprintf(stderr, "An error occurred\n");
  exit(1);
}

/**
 * There are some security concerns because the IV is based on the PIN. Generating IV randomly would fix the issue.
 */
void derive_key_iv(const char *pin, uint8_t *key, uint8_t *iv) {
  uint8_t hash[EVP_MAX_MD_SIZE];
  EVP_Digest(pin, strlen(pin), hash, NULL, EVP_sha256(), NULL);

  // First 32 bytes for the key
  memcpy(key, hash, AES_256_KEY_SIZE);

  // Last 16 bytes for the IV
  memcpy(iv, hash + AES_256_KEY_SIZE - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

int mbed_encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext) {
  enum {
    block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
  };

  psa_status_t status = psa_crypto_init();

  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;

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

  size_t len, ciphertext_len;
  status = psa_cipher_update(&operation, key, block_size, ciphertext, block_size, &len);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }
  ciphertext_len = len;

  status = psa_cipher_finish(&operation, ciphertext + ciphertext_len, block_size - ciphertext_len, &len);
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

int encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handleErrors();

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin, iv) != 1)
    handleErrors();

  int len, ciphertext_len;
  if (EVP_EncryptUpdate(ctx, ciphertext, &len, key, RSA_KEY_SIZE) != 1)
    handleErrors();
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int mbed_decrypt_private_key(const uint8_t *key, int key_len, const uint8_t *pin, const uint8_t *iv,
                             uint8_t *plaintext) {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

  psa_key_id_t key_id;
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 256);

  status = psa_import_key(&attr, pin, strlen((char *)pin), &key_id);
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

  size_t len, plaintext_len;

  status = psa_cipher_update(&operation, key, key_len, plaintext, RSA_KEY_SIZE + 64, &len);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  plaintext_len = len;
  status = psa_cipher_finish(&operation, plaintext + len, RSA_KEY_SIZE + 64 - len, &len);
  if (status != PSA_SUCCESS) {
    handleErrors();
    return 0;
  }

  plaintext_len += len;

  psa_cipher_abort(&operation);
  psa_destroy_key(key_id);
  mbedtls_psa_crypto_free();

  return plaintext_len;
}

int decrypt_private_key(const uint8_t *key, int key_len, const uint8_t *pin, const uint8_t *iv, uint8_t *plaintext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handleErrors();

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin, iv) != 1)
    handleErrors();

  int len, plaintext_len;
  if (EVP_DecryptUpdate(ctx, plaintext, &len, key, key_len) != 1)
    handleErrors();
  plaintext_len = len;

  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

/**
 * This function adds Initialization Vector at the beginning of encrypted private key file, but it isn't neccessary with
 * current implementation of derive_key_iv(). Either it should be removed or derive_key_iv() function should be updated
 * in the future.
 */
void generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  FILE *private_key_fp = NULL, *public_key_fp = NULL;

  uint8_t key[AES_256_KEY_SIZE], iv[AES_BLOCK_SIZE];
  derive_key_iv(pin, key, iv);

  // Create a context for key generation
  ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0)
    handleErrors();

  if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    handleErrors();

  // Convert private key to PEM format (plaintext)
  BIO *bio_private = BIO_new(BIO_s_mem());
  if (!bio_private || PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL) <= 0)
    handleErrors();

  uint8_t *plaintext_private_key;
  long plaintext_len = BIO_get_mem_data(bio_private, &plaintext_private_key);

  unsigned char ciphertext[RSA_KEY_SIZE];
  int ciphertext_len = encrypt_private_key(plaintext_private_key, key, iv, ciphertext);
  BIO_free(bio_private);

  private_key_fp = fopen(private_key_file, "wb");
  if (!private_key_fp)
    handleErrors();
  // Store IV at the beginning
  fwrite(iv, 1, AES_BLOCK_SIZE, private_key_fp);
  fwrite(ciphertext, 1, ciphertext_len, private_key_fp);
  fclose(private_key_fp);

  public_key_fp = fopen(public_key_file, "wb");
  if (!public_key_fp || PEM_write_PUBKEY(public_key_fp, pkey) <= 0)
    handleErrors();
  fclose(public_key_fp);

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
}

void mbed_generate_encrypted_RSA_keypair(const char *pin, const char *private_key_file, const char *public_key_file) {
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

  uint8_t priv_key[RSA_KEY_SIZE * 2];
  uint8_t enc_priv_key[RSA_KEY_SIZE * 2];
  uint8_t pub_key[RSA_KEY_SIZE * 2];
  FILE *private_key_file_fp = fopen(private_key_file, "wb");
  if (private_key_file_fp) {
    mbedtls_pk_write_key_pem(&key_ctx, priv_key, RSA_KEY_SIZE * 2);
    int key_len = mbed_encrypt_private_key(priv_key, key, iv, enc_priv_key);
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

EVP_PKEY *decrypt_and_load_private_key(const char *private_key_file, const char *pin) {
  FILE *fp = fopen(private_key_file, "rb");
  if (!fp) {
    perror("Failed to open encrypted private key file");
    return NULL;
  }

  // Read IV
  uint8_t iv[AES_BLOCK_SIZE];
  if (fread(iv, 1, AES_BLOCK_SIZE, fp) != AES_BLOCK_SIZE) {
    fprintf(stderr, "Failed to read IV\n");
    fclose(fp);
    return NULL;
  }

  // Read encrypted key data
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp) - AES_BLOCK_SIZE;
  fseek(fp, AES_BLOCK_SIZE, SEEK_SET);

  uint8_t *ciphertext = malloc(file_size);
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

  uint8_t key[AES_256_KEY_SIZE];
  derive_key_iv(pin, key, iv);

  uint8_t plaintext[8192];
  int plaintext_len = decrypt_private_key(ciphertext, file_size, key, iv, plaintext);
  free(ciphertext);

  if (plaintext_len < 0) {
    fprintf(stderr, "Private key decryption failed\n");
    return NULL;
  }

  // Load decrypted private key
  BIO *bio_private = BIO_new_mem_buf(plaintext, plaintext_len);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_private, NULL, NULL, NULL);
  BIO_free(bio_private);

  if (!pkey) {
    fprintf(stderr, "Failed to parse decrypted private key\n");
    return NULL;
  }

  printf("Decryption successful! Private key loaded.\n");
  return pkey;
}
