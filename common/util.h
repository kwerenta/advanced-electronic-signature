#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

/**
 * Extension of private key file
 */
#define PRIVATE_KEY_FILE_EXT ".pem"

/**
 * @brief Searches for a private key file (with PRIVATE_KEY_FILE_EXT extension) in specified directory
 * @param[in] path Path to the directory
 * @param[out] out_file Buffer where the path to the found file will be stored
 * @return Boolean value indicating whether the file was found or not
 */
uint8_t search_for_private_key(const char *path, char *key_file_path);

/**
 * @brief Search for a private key file (with PRIVATE_KEY_FILE_EXT extension) in root directory of all connected
 * removable storage devices
 * @param[out] out_file Buffer where the path to the found file will be stored
 * @return Boolean value indicating whether the file was found or not
 */
uint8_t find_private_key(char *key_file_path);

#endif
