cmake_minimum_required(VERSION 3.5)
project(Demo)

# Include the directory containing FindCrypto++.cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

# Find the Crypto++ package
find_package(Crypto++ REQUIRED)

# Add your executable and link with Crypto++ library
add_executable(myExecutable main.cpp)
target_include_directories(myExecutable PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(myExecutable ${Crypto++_LIBRARIES})
