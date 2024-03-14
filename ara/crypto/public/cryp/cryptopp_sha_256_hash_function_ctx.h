#ifndef CRYPTOPP_SHA_256_HASH_FUNCTION_CTX_H
#define CRYPTOPP_SHA_256_HASH_FUNCTION_CTX_H

#include "../../private/cryp/hash_function_ctx.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <iostream>
#include <sstream>
#include <iomanip>


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            enum class calling
            {
                START_IS_NOT_CALLED,
                START_IS_CALLED,
                UPDATE_IS_CALLED,
                FINISH_IS_CALLED
            };

            class CryptoPP_SHA_256_HashFunctionCtx: public HashFunctionCtx 
            {
            private:
                /***************************** attributes *******************/
                CryptoPP::SHA256 hash;
                CryptoPP::SecByteBlock digest;   
                calling seq;


                /*********** not fundemental and overrided functions **************/
                //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept;
                
                // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept;


            public:  
                /********************** constructor **************************/
                CryptoPP_SHA_256_HashFunctionCtx();

                
                /*********** fundemental and overrided functions **************/
                virtual ara::core::Result<void> Start () noexcept override;

                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv) noexcept override;

                ara::core::Result<void> Update (std::uint8_t in) noexcept override;

                ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > Finish() noexcept override;
                
                ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest(std::size_t offset=0) noexcept override;
            
                //virtual DigestService::Uptr GetDigestService () const noexcept;
            };
        }
    }
}

#endif