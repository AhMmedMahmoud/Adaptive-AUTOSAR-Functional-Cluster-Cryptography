#include "entry_point.h"

namespace ara
{
    namespace crypto
    {
        cryp::CryptoProvider::Uptr LoadCryptoProvider (const ara::core::InstanceSpecifier &iSpecify) noexcept
        {
           if(iSpecify.ToString() == "cryptopp")
           {
                std::cout << iSpecify.ToString() << std::endl;
                
                return std::make_unique<cryp::CryptoPP_CryptoProvider>();
           }
           else
           {
                std::cout << "not provider\n";
                return nullptr;
           }
        }
        
        keys::KeyStorageProvider::Uptr LoadKeyStorageProvider () noexcept
        {
            return std::make_unique<keys::Cryptopp_KeyStorageProvider>();
        }
        

        //x509::X509Provider::Uptr LoadX509Provider () noexcept;

        //ara::core::Result<ara::core::Vector<ara::core::Byte>> GenerateRandomData (std::uint32_t count) noexcept;

        //ara::core::Result<SecureCounter> GetSecureCounter () noexcept;
    }
}

