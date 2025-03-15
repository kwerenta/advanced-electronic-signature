#include "util.h"

#if defined(_WIN32)

#include "os/windows.h"

#elif defined(__APPLE__)

#include "os/apple.h"

#elif defined(__linux__)

#include "os/linux.h"

#endif

uint8_t search_for_key(const char* path, char* out_file) {
#if defined(_WIN32)
  return windows_search_for_key(path, out_file);
#elif defined(__APPLE__)
  return apple_search_for_key(path, out_file);
#elif defined(__linux__)
  return linux_search_for_key(path, out_file);
#else
  return 0;
#endif
}