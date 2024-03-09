cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 20)
project(Demo)

# Include the directory containing FindCrypto++.cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})
# Find the Crypto++ package
find_package(Crypto++ REQUIRED)


add_library(
   Crypto

   ## core ##
   ara/core/error_code.cpp
   ara/core/error_code.h
   ara/core/error_domain.h
   ara/core/instance_id.cpp
   ara/core/instance_id.h
   ara/core/instance_specifier.h
   ara/core/instance_specifier.cpp
   ara/core/optional.h
   ara/core/result.h
   ara/core/SamplePtr.h
   ara/core/Span.h
   ara/core/StringView.h
   ara/core/utility.h
   ara/core/vector.h

   ara/crypto/private/common/base_id_types.h
   ara/crypto/private/common/mem_region.h
   ara/crypto/private/cryp/cryobj/crypto_primitive_id.h
   ara/crypto/private/cryp/crypto_context.h
   ara/crypto/private/cryp/hash_function_ctx.h

   ara/crypto/public/cryp/cryptopp_crypto_context.h
   ara/crypto/public/cryp/cryobj/cryptopp_crypto_primitive_id.h
   ara/crypto/public/cryp/cryptopp_crypto_context.h
   ara/crypto/public/cryp/cryptopp_hash_function_ctx.cpp
)

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


# Add your executable and link with Crypto++ library
add_executable(mmm CryptoPP_examples/SemiAutosar_SHA_256.cpp)
target_include_directories(mmm PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(mmm ${Crypto++_LIBRARIES})


########################################
#         executables on core          #
########################################

add_executable(sss example_span.cpp)

add_executable(rrr example_result.cpp)
target_link_libraries(mmm Crypto)

########################################
#         executables on crypto        #
########################################

add_executable(hhh hashctx.cpp)
target_link_libraries(hhh Crypto)
target_link_libraries(hhh ${Crypto++_LIBRARIES})
