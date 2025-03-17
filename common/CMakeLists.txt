project(common)

include(FetchContent)

FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG v3.6.2
)
set(ENABLE_TESTING Off)

FetchContent_MakeAvailable(mbedtls)

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c crypto.c util.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC mbedcrypto raylib)
