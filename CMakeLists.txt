cmake_minimum_required(VERSION 3.15)
project(advanced-electronic-signature)

include(FetchContent)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)

# Dependencies
set(RAYLIB_VERSION 5.5)
find_package(raylib ${RAYLIB_VERSION} QUIET) 
if (NOT raylib_FOUND)
  FetchContent_Declare(
    raylib
    DOWNLOAD_EXTRACT_TIMESTAMP OFF
    URL https://github.com/raysan5/raylib/archive/refs/tags/${RAYLIB_VERSION}.tar.gz
  )
  FetchContent_GetProperties(raylib)
  if (NOT raylib_POPULATED)
    set(FETCHCONTENT_QUIET NO)
    FetchContent_MakeAvailable(raylib)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  endif()
endif()

FetchContent_Declare(
    tinycthread
    DOWNLOAD_EXTRACT_TIMESTAMP OFF
    URL https://github.com/tinycthread/tinycthread/archive/master.tar.gz
)
FetchContent_MakeAvailable(tinycthread)

add_subdirectory(common)

add_subdirectory(signature-app)
add_subdirectory(pin-app)
