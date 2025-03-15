#include "windows.h"

#include <Windows.h>

#include <string.h>
#include <stdio.h>

/**
 * @brief Checks whether the specified file has a correct extension (.pem by default)
 * @param filename Full name of the file
 * @return Boolean value indicating whether the file contains a key
 */
static uint8_t is_key(char *filename) {
  char* dot = strrchr(filename, '.');

  if (!dot) return 0;

  printf("filename: %s\n", filename);

  if (strncmp(dot, KEY_FILE_EXT, 4) == 0) return 1;
  else return 0;
}

uint8_t windows_search_for_key(const char *path, char *out_file) {
  TCHAR find_path[MAX_PATH];
  WIN32_FIND_DATA find_data;

  strcpy(find_path, path);
  strcat(find_path, "/*");

  HANDLE file_handle = FindFirstFileA(find_path, &find_data);

  if (!file_handle) return 0;

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