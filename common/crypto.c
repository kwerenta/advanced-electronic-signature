#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void handle_errors() {
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

int encrypt_private_key(const uint8_t *key, const uint8_t *pin, const uint8_t *iv, uint8_t *ciphertext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handle_errors();

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin, iv) != 1)
    handle_errors();

  int len, ciphertext_len;
  if (EVP_EncryptUpdate(ctx, ciphertext, &len, key, RSA_KEY_SIZE) != 1)
    handle_errors();
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handle_errors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_private_key(const uint8_t *key, int key_len, const uint8_t *pin, const uint8_t *iv, uint8_t *plaintext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handle_errors();

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin, iv) != 1)
    handle_errors();

  int len, plaintext_len;
  if (EVP_DecryptUpdate(ctx, plaintext, &len, key, key_len) != 1)
    handle_errors();
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
    handle_errors();

  if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    handle_errors();

  // Convert private key to PEM format (plaintext)
  BIO *bio_private = BIO_new(BIO_s_mem());
  if (!bio_private || PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL) <= 0)
    handle_errors();

  uint8_t *plaintext_private_key;
  long plaintext_len = BIO_get_mem_data(bio_private, &plaintext_private_key);

  unsigned char ciphertext[RSA_KEY_SIZE];
  int ciphertext_len = encrypt_private_key(plaintext_private_key, key, iv, ciphertext);
  BIO_free(bio_private);

  private_key_fp = fopen(private_key_file, "wb");
  if (!private_key_fp)
    handle_errors();
  // Store IV at the beginning
  fwrite(iv, 1, AES_BLOCK_SIZE, private_key_fp);
  fwrite(ciphertext, 1, ciphertext_len, private_key_fp);
  fclose(private_key_fp);

  public_key_fp = fopen(public_key_file, "wb");
  if (!public_key_fp || PEM_write_PUBKEY(public_key_fp, pkey) <= 0)
    handle_errors();
  fclose(public_key_fp);

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
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

uint8_t compute_pdf_hash(const char *pdf_file, uint8_t *hash, uint32_t *hash_len) {
  FILE *file = fopen(pdf_file, "rb");
  if (!file)
    handle_errors();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    handle_errors();

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    handle_errors();

  uint8_t buffer[RSA_KEY_SIZE];
  size_t bytes_read;
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
    if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1)
      handle_errors();
  }
  fclose(file);

  if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1)
    handle_errors();

  EVP_MD_CTX_free(mdctx);
  return 0;
}

uint8_t sign_hash(const uint8_t *hash, uint32_t hash_len, EVP_PKEY *private_key, uint8_t *sign, size_t *sign_len) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx)
    handle_errors();

  if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) != 1)
    handle_errors();
  if (EVP_DigestSignUpdate(md_ctx, hash, hash_len) != 1)
    handle_errors();
  if (EVP_DigestSignFinal(md_ctx, NULL, sign_len) != 1)
    handle_errors();

  if (EVP_DigestSignFinal(md_ctx, sign, sign_len) != 1)
    handle_errors();

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(private_key);

  return 1;
}
