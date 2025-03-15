#include "util.h"

#if defined(_WIN32)

#include "os/windows.h"

#endif

uint8_t search_for_key(const char *path, char *out_file) {
#if defined(_WIN32)
  return windows_search_for_key(path, out_file);
#else
  return 0;
#endif
}
