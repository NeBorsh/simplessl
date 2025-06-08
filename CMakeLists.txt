cmake_minimum_required(VERSION 3.10.0)
project(simplessl VERSION 0.1.0 LANGUAGES C CXX)

add_executable(simplessl 
        src/main.cpp
        
        src/utils/utils.h
        src/utils/utils.cpp
        )

target_include_directories(simplessl PRIVATE ${CMAKE_SOURCE_DIR}/includes)
target_link_directories(simplessl PRIVATE ${CMAKE_SOURCE_DIR}/libs)

target_link_libraries(simplessl PRIVATE libssl.lib libsimplesslo.lib)