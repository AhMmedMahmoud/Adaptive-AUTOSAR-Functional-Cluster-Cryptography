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
   ara/core/error_code.h
   ara/core/error_domain.h
   ara/core/exception.h
   ara/core/initialization.h
   ara/core/initialization.cpp
   ara/core/instance_id.h
   ara/core/instance_specifier.cpp
   ara/core/instance_specifier.h
   ara/core/optional.h
   ara/core/result.h
   ara/core/Span.h
   #ara/core/string.h
   ara/core/StringView.h
   ara/core/utility.h
   ara/core/vector.h

   ####### helper ######### 
   ara/crypto/helper/state.h
   ara/crypto/helper/print.h
   ara/crypto/helper/print.cpp
   
   ####### manifest #######
   ara/crypto/Manifest/CryptoKeySlotInterface.h
   ara/crypto/Manifest/manifestOperations.h
   ara/crypto/Manifest/manifestOperations.cpp
   ara/crypto/Manifest/sharedSlotsInterface.h
   ara/crypto/Manifest/sharedSlotsInterface.cpp

   ####### private ########
   ## common
   ara/crypto/private/common/base_id_types.h
   ara/crypto/private/common/crypto_error_domain.h
   ara/crypto/private/common/crypto_object_uid.h
   ara/crypto/private/common/uuid.h
   ara/crypto/private/common/entry_point.h
   ara/crypto/private/common/entry_point.cpp
   ara/crypto/private/common/io_interface.h
   ara/crypto/private/common/mem_region.h
   ## key 
   ara/crypto/private/keys/key_slot_content_props.h
   ara/crypto/private/keys/key_slot_prototype_props.h
   ara/crypto/private/keys/key_storage_provider.h
   ara/crypto/private/keys/keyslot.h
   ara/crypto/private/keys/elementary_types.h
   ## cryp/cryobj
   ara/crypto/private/cryp/cryobj/crypto_object.h
   ara/crypto/private/cryp/cryobj/crypto_primitive_id.h
   ara/crypto/private/cryp/cryobj/private_key.h
   ara/crypto/private/cryp/cryobj/public_key.h
   ara/crypto/private/cryp/cryobj/restricted_use_object.h
   ara/crypto/private/cryp/cryobj/signature.h
   ara/crypto/private/cryp/cryobj/symmetric_key.h
   ## cryp
   ara/crypto/private/cryp/crypto_context.h
   ara/crypto/private/cryp/crypto_provider.h
   ara/crypto/private/cryp/decryptor_private_ctx.h
   ara/crypto/private/cryp/encryptor_public_ctx.h
   ara/crypto/private/cryp/hash_function_ctx.h
   ara/crypto/private/cryp/message_authn_code_ctx.h
   ara/crypto/private/cryp/msg_recovery_public_ctx.h
   ara/crypto/private/cryp/sig_encode_private_ctx.h
   ara/crypto/private/cryp/symmetric_block_cipher_ctx.h

   ######### public ##########
   ## common
   ara/crypto/public/common/file_io_interface.h
   ## keys
   ara/crypto/public/keys/cryptopp_key_storage_provider.h
   ara/crypto/public/keys/cryptopp_keyslot.h
   ## cryp/cryobj
   ara/crypto/public/cryp/cryobj/cryptopp_crypto_primitive_id.h
   ara/crypto/public/cryp/cryobj/cryptopp_aes_128_symmetric_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_hmac_sha_256_symmetric_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_rsa_2046_public_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_rsa_2046_private_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_ecdsa_sha_256_public_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_ecdsa_sha_256_private_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_hmac_sha_256_signature.h
   ara/crypto/public/cryp/cryobj/loadKey.h
   ara/crypto/public/cryp/cryobj/saveKey.h

   ## cryp
   ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h
   ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.cpp
   ara/crypto/public/cryp/cryptopp_aes_ecb_128_symmetric_block_cipher_ctx.h
   ara/crypto/public/cryp/cryptopp_aes_ecb_128_symmetric_block_cipher_ctx.cpp
   ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h
   ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.cpp
   ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h
   ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.cpp
   ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.h
   ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.cpp  
   ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_sig_encode_private_ctx.h
   ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_sig_encode_private_ctx.cpp
   ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_msg_recovery_public_ctx.h
   ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_msg_recovery_public_ctx.cpp
   ara/crypto/public/cryp/cryptopp_crypto_provider.h
   ara/crypto/public/cryp/cryptopp_crypto_provider.cpp
)

###################################################
#              executables on CryptoPP            #
###################################################
### aes_cbc example using CryptoPP
#add_executable(aes CryptoPP_examples/AES_CBC_128.cpp)
#target_include_directories(aes PUBLIC ${Crypto++_INCLUDE_DIRS})
#target_link_libraries(aes ${Crypto++_LIBRARIES})

### aes_cbc example using CryptoPP
#add_executable(aes_ecb CryptoPP_examples/AES_ECB_128.cpp)
#target_include_directories(aes_ecb PUBLIC ${Crypto++_INCLUDE_DIRS})
#target_link_libraries(aes_ecb ${Crypto++_LIBRARIES})

### sha256 example using CryptoPP
#add_executable(sha256 CryptoPP_examples/SHA_256.cpp)
#target_include_directories(sha256 PUBLIC ${Crypto++_INCLUDE_DIRS})
#target_link_libraries(sha256 ${Crypto++_LIBRARIES})

### rsa keys generation example using CryptoPP
add_executable(RSA_keysGeneration CryptoPP_examples/RSA_PUK_PRK_generation.cpp)
target_include_directories(RSA_keysGeneration PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(RSA_keysGeneration ${Crypto++_LIBRARIES})

### rsa example using CryptoPP
#add_executable(rsa CryptoPP_examples/RAS_2048.cpp)
#target_include_directories(rsa PUBLIC ${Crypto++_INCLUDE_DIRS})
#target_link_libraries(rsa ${Crypto++_LIBRARIES})

### hmac example using CryptoPP
add_executable(mac CryptoPP_examples/hmac_sha256.cpp)
target_include_directories(mac PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(mac ${Crypto++_LIBRARIES})

### ecdsa example using CryptoPP
add_executable(ecdsa CryptoPP_examples/ESDSA.cpp)
target_include_directories(ecdsa PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(ecdsa ${Crypto++_LIBRARIES})

## ecdsa keys generation example using CryptoPP
add_executable(ECDSA_keysGeneration CryptoPP_examples/ECDSA_PUK_PRK_generation.cpp)
target_include_directories(ECDSA_keysGeneration PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(ECDSA_keysGeneration ${Crypto++_LIBRARIES})


###################################################
#            executables for core                 #
###################################################
#add_executable(ex_span samples/example_span.cpp)

#add_executable(ex_result samples/example_result.cpp)
#target_link_libraries(ex_result Crypto)


###################################################
#          executables on crypto (contexts)       #
###################################################
#add_executable(ex_uuid samples/example_uuid.cpp)
#target_link_libraries(ex_uuid Crypto)

#add_executable(ex_hash contexts_samples/example_hashctx.cpp)
#target_link_libraries(ex_hash ${Crypto++_LIBRARIES})
#target_link_libraries(ex_hash Crypto)

#add_executable(ex_hmac contexts_samples/example_hmac_Ctx.cpp)
#target_link_libraries(ex_hmac ${Crypto++_LIBRARIES})
#target_link_libraries(ex_hmac Crypto)

#add_executable(ex_aes contexts_samples/example_aes.cpp)
#target_link_libraries(ex_aes ${Crypto++_LIBRARIES})
#target_link_libraries(ex_aes Crypto)

#add_executable(ex_rsa contexts_samples/example_rsa_contexts.cpp)
#target_link_libraries(ex_rsa ${Crypto++_LIBRARIES})
#target_link_libraries(ex_rsa Crypto)

#add_executable(ex_ecdsa contexts_samples/example_ecdsa_contexts.cpp)
#target_link_libraries(ex_ecdsa ${Crypto++_LIBRARIES})
#target_link_libraries(ex_ecdsa Crypto)


###################################################
#           executables on crypto (demo)          #
###################################################
add_executable(demo_hash Demos/demo_hash.cpp)
target_link_libraries(demo_hash Crypto)
target_link_libraries(demo_hash ${Crypto++_LIBRARIES})

add_executable(demo_aes Demos/demo_aes.cpp)
target_link_libraries(demo_aes Crypto)
target_link_libraries(demo_aes ${Crypto++_LIBRARIES})

add_executable(demo_rsa Demos/demo_rsa.cpp)
target_link_libraries(demo_rsa Crypto)
target_link_libraries(demo_rsa ${Crypto++_LIBRARIES})

add_executable(demo_ecdsa Demos/demo_ecdsa.cpp)
target_link_libraries(demo_ecdsa Crypto)
target_link_libraries(demo_ecdsa ${Crypto++_LIBRARIES})

add_executable(demo_hmac Demos/demo_hmac.cpp)
target_link_libraries(demo_hmac Crypto)
target_link_libraries(demo_hmac ${Crypto++_LIBRARIES})




add_executable(test samples/test.cpp)

add_executable(test2 samples/test2.cpp)
target_link_libraries(test2 Crypto)
target_link_libraries(test2 ${Crypto++_LIBRARIES})



add_executable(demo_loadingECDSAKeys Demos/demo_loadingECDSAKeys.cpp)
target_link_libraries(demo_loadingECDSAKeys Crypto)
target_link_libraries(demo_loadingECDSAKeys ${Crypto++_LIBRARIES})

add_executable(demo_generatingECDSAKeys Demos/demo_generatingECDSAKeys.cpp)
target_link_libraries(demo_generatingECDSAKeys Crypto)
target_link_libraries(demo_generatingECDSAKeys ${Crypto++_LIBRARIES})