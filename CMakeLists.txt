cmake_minimum_required(VERSION 3.10.2)

project(app LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}" ${CMAKE_MODULE_PATH})

# OpenSSL
find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(LIB ${LIB} -lssl -lcrypto)

# Add sources
add_executable(${PROJECT_NAME} openssl_encrypt_pbdfk2.cpp)
target_sources(${PROJECT_NAME} PRIVATE ${SRC})
target_include_directories(${PROJECT_NAME} PRIVATE ${INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIB})
