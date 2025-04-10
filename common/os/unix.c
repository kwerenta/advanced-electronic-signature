#include "../util.h"

#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>

/**
 * @brief Internal version of find_private_key() function that is called with proper paths depending on operating system
 * @param[in] path Path where volumes will be searched
 * @param[out] out_file Buffer where the path to the found file will be stored
 */
uint8_t __find_private_key(const char *path, char *key_file_path) {
  struct dirent *entry;
  struct stat statbuf;

  DIR *dir = opendir(path);
  if (!dir) {
    return 0;
  }

  while ((entry = readdir(dir)) != NULL) {
    // Skip hidden and special directories
    if (entry->d_name[0] == '.')
      continue;

    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", path, entry->d_name);

    // Check if it's a directory (mounted storage)
    if (stat(full_path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
      uint8_t has_found = search_for_key(full_path, key_file_path);

      if (has_found == 1) {
        closedir(dir);
        return 1;
      }
    }
  }

  closedir(dir);
  return 0;
}

/**
 * Technically, UNIX version of this function returns almost all mounted volumes because it is impossible to reliably
 * detect wheter volume is removeable
 */
uint8_t find_private_key(char *out_file) {
#ifdef __APPLE__
  return __find_private_key("/Volumes/", out_file);
#else
  uint8_t has_found = __find_private_key("/media/", out_file);
  if (has_found == 1)
    return 1;

  return __find_private_key("/run/media/", out_file);
#endif
}
