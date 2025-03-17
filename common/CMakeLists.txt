project(common)

include(FetchContent)

set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls_config.h" CACHE STRING "Use custom mbedTLS config")

FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG v3.6.2
)
set(ENABLE_TESTING OFF CACHE BOOL "Disable testing")
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable CLI programs")
set(ENABLE_ZLIB_SUPPORT OFF CACHE BOOL "Disable zlib support")
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "Disable build tests")

FetchContent_MakeAvailable(mbedtls)

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c crypto.c util.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC mbedcrypto raylib)
