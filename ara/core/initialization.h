#ifndef INITIALIZATION_H
#define INITIALIZATION_H

#include "result.h"
#include "../crypto/Manifest/manifestOperations.h"
#include "../crypto/private/common/crypto_error_domain.h"

namespace ara
{
    namespace core
    {
        ara::core::Result<void> Initialize () noexcept
        {
            try
            {
                crypto::manifest::parseManifest();
                return ara::core::Result<void>::FromValue();
            }
            catch(const std::exception& e)
            {
                std::cout << "parsing failed\n";
                return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(ara::crypto::CryptoErrorDomain::Errc::kResourceFault, NoSupplementaryDataForErrorDescription));
            }
        }
    }
}

#endif