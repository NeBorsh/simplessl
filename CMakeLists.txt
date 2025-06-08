cmake_minimum_required(VERSION 3.10.0)
project(crypt VERSION 0.1.0 LANGUAGES C CXX)

add_executable(crypt 
        src/main.cpp
        
        src/utils/utils.h
        src/utils/utils.cpp
        )

target_include_directories(crypt PRIVATE ${CMAKE_SOURCE_DIR}/includes)
target_link_directories(crypt PRIVATE ${CMAKE_SOURCE_DIR}/libs)

target_link_libraries(crypt PRIVATE libssl.lib libcrypto.lib)