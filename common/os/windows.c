#include "windows.h"
#include "../util.h"

#include <Windows.h>

#include <stdio.h>
#include <string.h>

/**
 * @brief Checks whether the specified file has a correct extension (.pem by default)
 * @param filename Full name of the file
 * @return Boolean value indicating whether the file contains a key
 */
static uint8_t is_key(char *filename) {
  char *dot = strrchr(filename, '.');

  if (!dot)
    return 0;

  printf("filename: %s\n", filename);

  if (strncmp(dot, KEY_FILE_EXT, 4) == 0)
    return 1;
  else
    return 0;
}

uint8_t windows_search_for_key(const char *path, char *out_file) {
  TCHAR find_path[MAX_PATH];
  WIN32_FIND_DATA find_data;

  strcpy(find_path, path);
  strcat(find_path, "/*");

  HANDLE file_handle = FindFirstFileA(find_path, &find_data);

  if (!file_handle)
    return 0;

  do {
    if (is_key(find_data.cFileName)) {
      strcpy(out_file, path);
      strcat(out_file, "/");
      strcat(out_file, find_data.cFileName);
      FindClose(file_handle);
      return 1;
    }
  } while (FindNextFileA(file_handle, &find_data));

  FindClose(file_handle);

  return 0;
}

uint8_t find_private_key(const char *out_file) {
  DWORD drives = GetLogicalDrives();
  if (drives == 0) {
    printf("Failed to get drive list.\n");
    return;
  }

  for (char letter = 'A'; letter <= 'Z'; letter++) {
    if (drives & (1 << (letter - 'A'))) {
      char path[4] = {letter, ':', '\\', '\0'};
      UINT type = GetDriveTypeA(path);
      if (type == DRIVE_REMOVABLE) {
        if (search_for_key(path, out_file) == 1)
          return 1;
      }
    }
  }
  return 0;
}
