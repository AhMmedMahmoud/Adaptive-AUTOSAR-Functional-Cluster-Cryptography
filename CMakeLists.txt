cmake_minimum_required(VERSION 3.5)
project(Demo)

# Include the directory containing FindCrypto++.cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

# Find the Crypto++ package
find_package(Crypto++ REQUIRED)


# Add your executable and link with Crypto++ library
add_executable(aes CryptoPP_examples/AES_CBC_128.cpp)
target_include_directories(aes PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(aes ${Crypto++_LIBRARIES})


# Add your executable and link with Crypto++ library
add_executable(sha256 CryptoPP_examples/SHA_256.cpp)
target_include_directories(sha256 PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(sha256 ${Crypto++_LIBRARIES})


# Add your executable and link with Crypto++ library
add_executable(keysGeneration CryptoPP_examples/PUK_PRK_generation.cpp)
target_include_directories(keysGeneration PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(keysGeneration ${Crypto++_LIBRARIES})

# Add your executable and link with Crypto++ library
add_executable(rsa CryptoPP_examples/RAS_2048.cpp)
target_include_directories(rsa PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(rsa ${Crypto++_LIBRARIES})