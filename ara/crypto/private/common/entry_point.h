#ifndef ENTRY_POINT_H
#define ENTRY_POINT_H

#include <cstdint>
#include "../../../core/result.h"
#include "../../../core/instance_specifier.h"
#include "../../public/cryp/cryptopp_crypto_provider.h"
#include "../../public/keys/cryptopp_key_storage_provider.h"

namespace ara
{
    namespace crypto
    {
        struct SecureCounter 
        {
            std::uint64_t mLSQW;
            std::uint64_t mMSQW;
        };

        
        cryp::CryptoProvider::Uptr LoadCryptoProvider (const ara::core::InstanceSpecifier &iSpecify) noexcept;
           
        keys::KeyStorageProvider::Uptr LoadKeyStorageProvider () noexcept;
      
        //x509::X509Provider::Uptr LoadX509Provider () noexcept;

        //ara::core::Result<ara::core::Vector<ara::core::Byte>> GenerateRandomData (std::uint32_t count) noexcept;

        //ara::core::Result<SecureCounter> GetSecureCounter () noexcept;
    }
}

#endif