#ifndef WINDOWS_H
#define WINDOWS_H

#define KEY_FILE_EXT ".pem"

#include <stdint.h>

uint8_t windows_search_for_key(const char* path, char* out_file);

#endif