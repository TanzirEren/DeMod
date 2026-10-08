cmake_minimum_required(VERSION 3.18.1)
project(demod CXX)
set(CMAKE_CXX_STANDARD 17)
add_library(demod SHARED demod.cpp)
