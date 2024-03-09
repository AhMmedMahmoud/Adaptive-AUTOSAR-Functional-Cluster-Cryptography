#include "cryptopp_hash_function_ctx.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {         
            ara::core::Result<void> CryptoPP_HashFunctionCtx::Start () noexcept
            {
                hash.Restart();
                return ara::core::Result<void>::FromValue();
            }
            
            
            ara::core::Result<void> CryptoPP_HashFunctionCtx::Start (ReadOnlyMemRegion iv) noexcept
            {
                return ara::core::Result<void>::FromValue();
            }


            //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept;


            ara::core::Result<void> CryptoPP_HashFunctionCtx::Update (ReadOnlyMemRegion in) noexcept
            {
                hash.Update(in.data(), in.size());
                return ara::core::Result<void>::FromValue();
            }
            

            // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept;


            ara::core::Result<void> CryptoPP_HashFunctionCtx::Update (std::uint8_t in) noexcept
            {
                return ara::core::Result<void>::FromValue();
            }
            
            
            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_HashFunctionCtx::Finish() noexcept
            {
                digest.resize(hash.DigestSize());
                hash.Final(digest);

                ara::core::Vector<ara::core::Byte> result;
                for (const auto& byte : digest)
                {
                    result.push_back(static_cast<ara::core::Byte>(byte));
                }

                return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
            }


            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_HashFunctionCtx::GetDigest (std::size_t offset) noexcept
            {
                ara::core::Vector<ara::core::Byte> result;
                for (const auto& byte : digest)
                {
                    result.push_back(static_cast<ara::core::Byte>(byte));
                }

                return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
            }
        }
    }
}
