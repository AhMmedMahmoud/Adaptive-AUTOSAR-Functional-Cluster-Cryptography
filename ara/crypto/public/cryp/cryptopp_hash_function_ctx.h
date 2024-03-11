#ifndef CRYPTOPP_HASH_FUNCTION_CTX_H
#define CRYPTOPP_HASH_FUNCTION_CTX_H

#include "../../private/cryp/hash_function_ctx.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <iostream>
#include <sstream>
//#include <vector>
//#include <span>

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

            class CryptoPP_HashFunctionCtx: public HashFunctionCtx 
            {
            private:
                CryptoPP::SHA256 hash;
                CryptoPP::SecByteBlock digest;
                
                calling seq;

            public:  
                CryptoPP_HashFunctionCtx();

                //virtual DigestService::Uptr GetDigestService () const noexcept;
                
                
                virtual ara::core::Result<void> Start () noexcept override;
                
                
                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv) noexcept override;

                //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept;


                ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept override;

                // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept;

                ara::core::Result<void> Update (std::uint8_t in) noexcept override;
                
                
                ara::core::Result<ara::core::Vector<ara::core::Byte> > Finish() noexcept override;
                
                
                ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest(std::size_t offset=0) noexcept override;
            };
        }
    }
}

#endif