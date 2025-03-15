project(common)

find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c crypto.c)

if (WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto raylib)
