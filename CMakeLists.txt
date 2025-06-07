cmake_minimum_required(VERSION 3.15)

project(blockchain VERSION 1.0 LANGUAGES CXX DESCRIPTION "Basic blockchain implementation")

set(PROJECT_SOURCE_DIR src/)
set(PROJECT_INCLUDE_DIR include/)

file(GLOB_RECURSE sources ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(blockchain ${sources})
target_include_directories(blockchain PUBLIC ${PROJECT_INCLUDE_DIR})
