cmake_minimum_required(VERSION 3.22.1)

project(blackom_native LANGUAGES CXX)

add_library(blackom_native SHARED
        native_bridge.cpp)

target_compile_features(blackom_native PRIVATE cxx_std_17)

find_library(log-lib log)

target_link_libraries(blackom_native
        ${log-lib})
