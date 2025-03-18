project(common)

include(FetchContent)

set(MBEDTLS_VERSION 3.6.2)
set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls_config.h" CACHE STRING "Use custom mbedTLS config")
FetchContent_Declare(
    mbedtls
    DOWNLOAD_EXTRACT_TIMESTAMP OFF
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2
)

set(ENABLE_TESTING OFF CACHE BOOL "Disable testing")
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable CLI programs")
set(ENABLE_ZLIB_SUPPORT OFF CACHE BOOL "Disable zlib support")
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "Disable build tests")
FetchContent_MakeAvailable(mbedtls)

if (WIN32)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/os/windows.c)
else()
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/os/unix.c)
endif()

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c crypto.c util.c ${OS_SOURCE})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC mbedcrypto raylib)
