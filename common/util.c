#include "util.h"
#include <raylib.h>
#include <string.h>

/**
 * out_file buffer size should be 128 bytes
 */
uint8_t search_for_key(const char *path, char *out_file) {
  FilePathList files = LoadDirectoryFilesEx(path, KEY_FILE_EXT, 0);

  if (files.count == 0) {
    UnloadDirectoryFiles(files);
    return 0;
  }

  strncpy(out_file, files.paths[0], 128);
  UnloadDirectoryFiles(files);
  return 1;
}
