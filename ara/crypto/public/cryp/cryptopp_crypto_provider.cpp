#include "../../private/common/crypto_error_domain.h"
#include "cryptopp_crypto_provider.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            ara::core::Result<HashFunctionCtx::Uptr> CryptoPP_CryptoProvider::CreateHashFunctionCtx(AlgId algId) noexcept
            {                
                if(algId == SHA_256_ALG_ID)
                {
                    /*
                    std::unique_ptr<CryptoPP_SHA_256_HashFunctionCtx> context = std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>();
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::move(context));
                    */
                    
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>());
                }
                else
                {
                    return ara::core::Result<HashFunctionCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }


            ara::core::Result<MessageAuthnCodeCtx::Uptr> CryptoPP_CryptoProvider::CreateMessageAuthCodeCtx (AlgId algId) noexcept
            {
                if(algId == HMAC_SHA_256_ALG_ID)
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>(std::make_unique<CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx>());
                }
                else
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }

 
            ara::core::Result<SymmetricBlockCipherCtx::Uptr> CryptoPP_CryptoProvider::CreateSymmetricBlockCipherCtx (AlgId algId) noexcept 
            {
                if(algId == AES_ECB_128_ALG_ID)
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>(std::make_unique<CryptoPP_AES_SymmetricBlockCipherCtx>());
                }
                else
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }


            ara::core::Result<EncryptorPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateEncryptorPublicCtx (AlgId algId) noexcept
            {
                if(algId == RSA_2048_ALG_ID)
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>(std::make_unique<CryptoPP_RSA_EncryptorPublicCtx>());
                }
                else
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
          
            ara::core::Result<DecryptorPrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateDecryptorPrivateCtx (AlgId algId) noexcept
            {
                if(algId == RSA_2048_ALG_ID)
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>(std::make_unique<CryptoPP_RSA_DecryptorPrivateCtx>());
                }
                else
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
            ara::core::Result<MsgRecoveryPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateMsgRecoveryPublicCtx (AlgId algId) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID)
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_MsgRecoveryPublicCtx>());
                }
                else
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
            ara::core::Result<SigEncodePrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateSigEncodePrivateCtx (AlgId algId) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID)
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_SigEncodePrivateCtx>());
                }
                else
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }

            ara::core::Result<PrivateKey::Uptrc> CryptoPP_CryptoProvider::GeneratePrivateKey ( AlgId algId, 
                                                                          AllowedUsageFlags allowedUsage, 
                                                                          bool isSession, 
                                                                          bool isExportable
																	) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID && allowedUsage == kAllowSignature)
                {
                    // Create an AutoSeededRandomPool object for random number generation
                    CryptoPP::AutoSeededRandomPool prng;   

                    // Generate private key
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey myPrivateKey;
                    myPrivateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());

                    std::unique_ptr<CryptoPP_ECDSA_PrivateKey> ptr = std::make_unique<CryptoPP_ECDSA_PrivateKey>();
                  
                    ptr->setValue(myPrivateKey);

                    return ara::core::Result<PrivateKey::Uptrc>(std::move(ptr));
                }
                else if(algId == RSA_2048_ALG_ID && allowedUsage == kAllowDataEncryption)
                {
                    size_t keyLength = 2048;                     // Specify the key length here

                    CryptoPP::InvertibleRSAFunction parameters;  // Create RSA parameters object
                    CryptoPP::AutoSeededRandomPool prng;   // Create an AutoSeededRandomPool object for random number generation
                    parameters.GenerateRandomWithKeySize(prng, keyLength);  // Generate random RSA parameters with the specified key length

                    CryptoPP::RSA::PrivateKey myPrivateKey(parameters);  // Create RSA private key using the generated parameters

                    
                    std::unique_ptr<CryptoPP_RSA_PrivateKey> ptr = std::make_unique<CryptoPP_RSA_PrivateKey>();
                  
                    ptr->setValue(myPrivateKey);

                    return ara::core::Result<PrivateKey::Uptrc>(std::move(ptr));
                }
                else
                {
                    return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
        }
    }
}
