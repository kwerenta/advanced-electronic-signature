#include "util.h"
#include <raylib.h>
#include <string.h>

/**
 * key_file_path buffer size should be 128 bytes
 */
uint8_t search_for_private_key(const char *path, char *key_file_path) {
  FilePathList files = LoadDirectoryFilesEx(path, PRIVATE_KEY_FILE_EXT, 0);

  if (files.count == 0) {
    UnloadDirectoryFiles(files);
    return 0;
  }

  strncpy(key_file_path, files.paths[0], 128);
  UnloadDirectoryFiles(files);
  return 1;
}
