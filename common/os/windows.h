#ifndef WINDOWS_H
#define WINDOWS_H

#define KEY_FILE_EXT ".pem"

#include <stdint.h>

/**
 * @brief Searches for a key file (.pem) in specified directory
 * @param path Path to the directory
 * @param out_file Buffer where the path to the found file will be stored
 * @return Boolean value indicating whether the file was found or not
 */
uint8_t windows_search_for_key(const char* path, char* out_file);

#endif