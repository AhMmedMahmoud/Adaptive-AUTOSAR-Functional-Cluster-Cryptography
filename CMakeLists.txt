cmake_minimum_required(VERSION 3.5)
project(Demo)

# Include the directory containing FindCrypto++.cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

# Find the Crypto++ package
find_package(Crypto++ REQUIRED)


# Add your executable and link with Crypto++ library
add_executable(aes AES_CBC_128.cpp)
target_include_directories(aes PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(aes ${Crypto++_LIBRARIES})


# Add your executable and link with Crypto++ library
add_executable(sha256 SHA_256.cpp)
target_include_directories(sha256 PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(sha256 ${Crypto++_LIBRARIES})