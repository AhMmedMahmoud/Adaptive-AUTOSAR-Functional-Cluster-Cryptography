#ifndef CRYPTOPP_CRYPTO_PRIMITIVE_ID_h
#define CRYPTOPP_CRYPTO_PRIMITIVE_ID_h


#include "../../../private/cryp/cryobj/crypto_primitive_id.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CryptoPrimitiveId : public CryptoPrimitiveId
            {
            public:
                AlgId GetPrimitiveId () const noexcept;
                
                const ara::core::StringView GetPrimitiveName () const noexcept;
            };
        }
    }
}

#endif