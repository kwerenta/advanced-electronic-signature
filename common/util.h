#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

/**
 * @brief Searches for a key file (.pem) in specified directory
 * @param path Path to the directory
 * @param out_file Buffer where the path to the found file will be stored
 * @return Boolean value indicating whether the file was found or not
 */
uint8_t search_for_key(const char *path, char *out_file);

/**
 * @brief Search for a key file (.pem) in root directory of all connected removable storage devices
 * @param out_file Buffer where the path to the found file will be stored
 * @return Boolean value indicating wheter the file was found or not
 */
uint8_t find_private_key(const char *out_file);

#endif
