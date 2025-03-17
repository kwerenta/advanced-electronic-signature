if (WIN32)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_win.cpp)
elseif (UNIX and not APPLE)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_gtk.c)
else()
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_cocoa.m)
endif()

add_library(nfd STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_common.c
  ${OS_SOURCE}
)