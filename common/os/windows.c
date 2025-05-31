#include "../util.h"

#include <stdio.h>
#include <windows.h>

/**
 * @brief Searches for private key file in removable drives on Windows
 * @param[out] key_file_path Buffer where the path to the found file will be stored
 */
uint8_t find_private_key(char *key_file_path) {
  DWORD drives = GetLogicalDrives();
  if (drives == 0) {
    printf("Failed to get drive list.\n");
    return 0;
  }

  for (char letter = 'A'; letter <= 'Z'; letter++) {
    if (drives & (1 << (letter - 'A'))) {
      char path[3] = {letter, ':', '\0'};
      UINT type = GetDriveTypeA(path);
      if (type == DRIVE_REMOVABLE) {
        if (search_for_private_key(path, key_file_path) == 1)
          return 1;
      }
    }
  }
  return 0;
}
