#include "../util.h"

#include <stdio.h>
#include <windows.h>

uint8_t find_private_key(char *out_file) {
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
        if (search_for_key(path, out_file) == 1)
          return 1;
      }
    }
  }
  return 0;
}
