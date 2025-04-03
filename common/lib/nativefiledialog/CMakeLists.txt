if (WIN32)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_win.cpp)
elseif (UNIX AND NOT APPLE)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_gtk.c)
else()
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_cocoa.m)
endif()

add_library(nfd STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/nfd_common.c
  ${OS_SOURCE}
)

target_include_directories(nfd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/include)

if (UNIX AND NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

    target_include_directories(nfd PUBLIC ${GTK3_INCLUDE_DIRS})
    target_link_directories(nfd PUBLIC ${GTK3_INCLUDE_DIRS})

    add_definitions(${GTK3_CFLAGS_OTHER})

    target_link_libraries(nfd ${GTK3_LIBRARIES})
endif()
