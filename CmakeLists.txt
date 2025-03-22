cmake_minimum_required(VERSION 3.10)
project(Bionic64)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/include)
file(GLOB SOURCES "src/*.cpp")

add_executable(Bionic64 ${SOURCES})

# Link com Bionic no Android (se necessário)
target_link_libraries(Bionic64 PRIVATE c)
