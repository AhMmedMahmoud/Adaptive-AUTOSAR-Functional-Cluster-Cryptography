#ifndef CRYPTOPP_CRYPTO_CONTEXT_H
#define CRYPTOPP_CRYPTO_CONTEXT_H

#include "../../private/cryp/crypto_context.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CryptoContext: public CryptoContext
            {
            public:        
                //virtual CryptoProvider& MyProvider () const noexcept=0;

                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept=0;

                bool IsInitialized () const noexcept=0;

            };
        }
    }
}

#endif