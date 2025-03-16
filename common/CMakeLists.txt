project(common)

find_package(OpenSSL REQUIRED)

if (WIN32)
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/os/windows.c)
else()
  set(OS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/os/unix.c)
endif()

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c crypto.c util.c ${OS_SOURCE})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto raylib)
