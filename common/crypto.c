#include "crypto.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "psa/crypto_sizes.h"
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
 * @brief Internal function that is used for destroying context created in generate_encrypted_RSA_keypair() function
 * @param pk PK context
 * @param entropy Entropy context
 * @param ctr_drbg CTR drbg context
 */
void free_keygen_context(mbedtls_pk_context *pk, mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg) {
  mbedtls_pk_free(pk);
  mbedtls_entropy_free(entropy);
  mbedtls_ctr_drbg_free(ctr_drbg);
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
  const char *custom = "rsa_gen";

  mbedtls_pk_init(&key_ctx);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng_ctx);

  ret = mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy, (const uint8_t *)custom, strlen(custom));
  if (ret != 0) {
    free_keygen_context(&key_ctx, &entropy, &rng_ctx);
    printf("Failed to initialize RNG\n");
    return;
  }

  ret = mbedtls_pk_setup(&key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) {
    free_keygen_context(&key_ctx, &entropy, &rng_ctx);
    printf("Failed to initialize RNG\n");
    return;
  }

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key_ctx), mbedtls_ctr_drbg_random, &rng_ctx, RSA_KEY_SIZE, 65537);
  if (ret != 0) {
    free_keygen_context(&key_ctx, &entropy, &rng_ctx);
    printf("Failed to generate RSA keypair\n");
    return;
  }

  uint8_t enc_priv_key[RSA_KEY_SIZE * 2] = {0}, priv_key[RSA_KEY_SIZE * 2] = {0}, pub_key[RSA_KEY_SIZE * 2] = {0};

  FILE *private_key_file_fp = fopen(private_key_file, "wb");
  if (private_key_file_fp == NULL) {
    free_keygen_context(&key_ctx, &entropy, &rng_ctx);
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
    free_keygen_context(&key_ctx, &entropy, &rng_ctx);
    perror("Failed to open public key file");
    return;
  }

  mbedtls_pk_write_pubkey_pem(&key_ctx, pub_key, RSA_KEY_SIZE * 2);
  fwrite(pub_key, 1, strlen((char *)pub_key), public_key_fp);
  fclose(public_key_fp);

  free_keygen_context(&key_ctx, &entropy, &rng_ctx);
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

  uint8_t key[AES_256_KEY_SIZE], _iv[AES_BLOCK_SIZE];
  derive_key_iv(pin, key, _iv);

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

void compute_pdf_hash(FILE *pdf_file, uint8_t *hash) {
  fseek(pdf_file, 0, SEEK_END);
  size_t pdf_size = ftell(pdf_file);
  rewind(pdf_file);

  uint8_t *pdf_data = malloc(pdf_size);

  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pdf_data, pdf_size, hash);

  free(pdf_data);
}

void sign_hash(const uint8_t *hash, const uint8_t *private_key, uint8_t *sign) {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id;

  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    return;
  }

  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
  psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_bits(&attributes, RSA_KEY_SIZE);

  mbedtls_pk_context key_ctx;
  mbedtls_pk_init(&key_ctx);

  status = mbedtls_pk_parse_key(&key_ctx, private_key, strlen((char *)private_key) + 1, NULL, 0, NULL, NULL);
  if (status != 0) {
    printf("Failed to parse private key\n");
    mbedtls_pk_free(&key_ctx);
    return;
  }

  // Convert PEM private key to DER format
  uint8_t pkey_der[RSA_KEY_SIZE];
  size_t pkey_len = 0;
  status = mbedtls_pk_write_key_der(&key_ctx, pkey_der, sizeof(pkey_der));
  if (status < 0) {
    printf("Failed to convert RSA key to DER");
    return;
  }
  pkey_len = status;

  status = psa_import_key(&attributes, pkey_der + sizeof(pkey_der) - pkey_len, pkey_len, &key_id);
  if (status != PSA_SUCCESS) {

    char err_buf[100];
    mbedtls_strerror(status, err_buf, sizeof(err_buf));
    printf("mbed TLS error: %s\n", err_buf);
    return;
  }

  size_t sign_len = PSA_SIGNATURE_MAX_SIZE;

  status = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW, hash, PSA_HASH_MAX_SIZE, sign, sign_len, &sign_len);
  if (status != PSA_SUCCESS) {
    printf("Failed to sign\n");
    return;
  }

  psa_reset_key_attributes(&attributes);
  psa_destroy_key(key_id);
  mbedtls_psa_crypto_free();
}

uint8_t verify_hash(const uint8_t *hash, const uint8_t *public_key, const uint8_t *signature) {
  // psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  // psa_key_id_t key_id;

  // psa_status_t status = psa_crypto_init();
  // if (status != PSA_SUCCESS) {
  //   return 0;
  // }

  // psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
  // psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
  // psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

  mbedtls_pk_context key_ctx;
  mbedtls_pk_init(&key_ctx);

  int status = mbedtls_pk_parse_public_keyfile(&key_ctx, "public_key.pem");
  if (status != 0) {
    printf("Failed to parse public key\n");
    mbedtls_pk_free(&key_ctx);
    return 0;
  }

  // mbedtls_entropy_context entropy = {0};
  // mbedtls_ctr_drbg_context rng_ctx = {0};

  // const char *custom = "rsa_gen";
  // mbedtls_entropy_init(&entropy);
  // mbedtls_ctr_drbg_init(&rng_ctx);

  // status = mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy, (const uint8_t *)custom, strlen(custom));
  // if (status != 0) {
  //   free_keygen_context(&key_ctx, &entropy, &rng_ctx);
  //   printf("Failed to initialize RNG\n");
  //   return 0;
  // }

  // uint8_t pkey_der[10240] = {0};
  // size_t pkey_len = 0;
  // size_t der_len = mbedtls_pk_write_pubkey_der(&key_ctx, pkey_der, sizeof(pkey_der));
  // if (der_len <= 0) {
  //   printf("Failed to convert RSA key to DER");
  //   return 0;
  // }
  // pkey_len = status;

  // status = psa_import_key(&attributes, pkey_der + sizeof(pkey_der) - der_len, der_len, &key_id);
  // if (status != PSA_SUCCESS) {
  //   char err_buf[100];
  //   mbedtls_strerror(status, err_buf, sizeof(err_buf));
  //   printf("mbed TLS error: %s\n", err_buf);
  //   return 0;
  // }

  // status = psa_verify_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW, hash, PSA_HASH_MAX_SIZE, signature,
  //                          PSA_SIGNATURE_MAX_SIZE);
  status = mbedtls_pk_verify(&key_ctx, MBEDTLS_MD_SHA256, hash, 0, signature, PSA_SIGNATURE_MAX_SIZE);
  if (status != PSA_SUCCESS) {
    printf("Failed to verify\n");
    return 0;
  }

  // psa_reset_key_attributes(&attributes);
  // psa_destroy_key(key_id);
  // mbedtls_psa_crypto_free();
  mbedtls_pk_free(&key_ctx);

  return 1;
}

void sign_pdf_file(const char *pdf_path, const uint8_t *private_key) {
  FILE *pdf_file = fopen(pdf_path, "a+");

  if (pdf_file == NULL) {
    perror("Failed to open PDF file");
    return;
  }

  uint8_t hash[PSA_HASH_MAX_SIZE], sign[PSA_SIGNATURE_MAX_SIZE];

  compute_pdf_hash(pdf_file, hash);
  sign_hash(hash, private_key, sign);

  fseek(pdf_file, 0, SEEK_END);
  long size = ftell(pdf_file);

  fputs("<</Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n", pdf_file);

  fprintf(pdf_file, "/ByteRange [0 %lu %lu 0]\n", size, size);

  char hex[3] = {0}, contents[1025] = {0};
  for (int i = 0; i < PSA_SIGNATURE_MAX_SIZE; i++) {
    snprintf(hex, 3, "%02X", sign[i]);
    strcat(contents, hex);
  }
  fprintf(pdf_file, "/Contents <%s>\n>>\n", contents);

  fclose(pdf_file);
}

void verify_pdf_signature(const char *pdf_path, const uint8_t *public_key) {
  FILE *pdf_file = fopen(pdf_path, "r");

  if (pdf_file == NULL) {
    perror("Failed to open PDF file");
    return;
  }

  uint8_t signature_headers = 0;
  char buffer[10240];

  while (fgets(buffer, sizeof(buffer), pdf_file)) {
    if (strstr(buffer, "<</Type /Sig") != NULL && signature_headers == 0)
      signature_headers++;
    else if (strstr(buffer, "/Filter /Adobe.PPKLite") != NULL && signature_headers == 1)
      signature_headers++;
    else if (strstr(buffer, "/SubFilter /adbe.pkcs7.detached") != NULL && signature_headers == 2)
      signature_headers++;

    if (signature_headers == 3) {
      break;
    }
  }

  if (signature_headers != 3) {
    perror("Failed to find signature in PDF file");
    fclose(pdf_file);
    return;
  }

  uint32_t range[4] = {0};
  fgets(buffer, sizeof(buffer), pdf_file);
  int has_found = sscanf(buffer, "/ByteRange [%d %d %d %d]", &range[0], &range[1], &range[2], &range[3]);
  if (has_found != 4) {
    perror("Failed to load byte range");
    return;
  }

  char signature_hex[1024 + 1] = {0};
  fgets(buffer, sizeof(buffer), pdf_file);
  has_found = sscanf(buffer, "/Contents <%1024s>\n>>\n", signature_hex);
  if (has_found == 0) {
    perror("Failed to load signature content");
    return;
  }

  uint8_t signature[512 + 1] = {0};
  for (size_t i = 0; i < 512; i++) {
    sscanf(signature_hex + (2 * i), "%2hhx", &signature[i]);
  }

  uint8_t hash[PSA_HASH_MAX_SIZE] = {0};
  compute_pdf_hash(pdf_file, hash);
  fclose(pdf_file);

  uint8_t has_verified = verify_hash(hash, public_key, signature);
  if (has_verified == 0)
    printf("Failed to verify signature\n");
  else
    printf("Verified successfully\n");
}
