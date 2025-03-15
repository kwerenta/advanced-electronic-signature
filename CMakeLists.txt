cmake_minimum_required(VERSION 3.15)
project(advanced-electronic-signature)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
set(RAYLIB_VERSION 5.5)
find_package(raylib ${RAYLIB_VERSION} QUIET) 
if (NOT raylib_FOUND)
  include(FetchContent)
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

find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)

add_executable(${PROJECT_NAME} main.c crypto.c)

target_link_libraries(${PROJECT_NAME} raylib OpenSSL::Crypto OpenSSL::SSL)

# Checks if not Windows and linnks appropriate libraries
if (NOT WIN32)
  target_link_libraries(${PROJECT_NAME} m)
endif()

# Checks if OSX and links appropriate frameworks (only required on MacOS)
if (APPLE)
  target_link_libraries(${PROJECT_NAME} "-framework IOKit")
  target_link_libraries(${PROJECT_NAME} "-framework Cocoa")
  target_link_libraries(${PROJECT_NAME} "-framework OpenGL")
endif()
