#include "cryptopp_aes_symmetric_block_cipher_ctx.h"
#include "../../private/common/crypto_error_domain.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            const std::string CryptoPP_AES_SymmetricBlockCipherCtx::mAlgName("aes_ecb");

            CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryptor;
            CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryptor;


            /***************** constructor **********************/
            
            CryptoPP_AES_SymmetricBlockCipherCtx::CryptoPP_AES_SymmetricBlockCipherCtx(): mKey(nullptr),
                                                    mTransform(CryptoTransform::kEncrypt),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(helper::setKeyState::NOT_CALLED)
            {}




            /****** override pure virtual functions related to CryptoContext *****/

            /*
                Return CryptoPrimitivId instance containing instance identification
            */
            CryptoPrimitiveId::Uptr CryptoPP_AES_SymmetricBlockCipherCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
            */
            bool CryptoPP_AES_SymmetricBlockCipherCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }
            


            /***** override pure virtual functions inherited related SymmetricBlockCipherCtx *****/

            /*
                takes key and type of processing we want (type of operation ex:Encryption or decryption)
            */
            ara::core::Result<void> CryptoPP_AES_SymmetricBlockCipherCtx::SetKey( const SymmetricKey &key,
                                                    CryptoTransform transform
                                                    ) noexcept
            {  
                if(transform != CryptoTransform::kEncrypt && 
                    transform != CryptoTransform::kDecrypt) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUsageViolation,5));
                }

                try
                {    
                    const CryptoPP_AES_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_AES_SymmetricKey&>(key);
                    mKey = new CryptoPP_AES_SymmetricKey(aesKey);
                    
                    mTransform = transform;
                    mSetKeyState = helper::setKeyState::CALLED;
                    if(transform == CryptoTransform::kEncrypt)
                        encryptor.SetKey(mKey->getValue(), mKey->getValue().size());
                    else
                        decryptor.SetKey(mKey->getValue(), mKey->getValue().size());

                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject,5));
                }
            }



            /* 
                takes the data that we want to process (preform an operation on it)
                returns CryptoErrorDomain::kUninitializedContext,if SetKey() has not been called yet
            */                
            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_AES_SymmetricBlockCipherCtx::ProcessBlock ( ReadOnlyMemRegion in,
                                                                                        bool suppressPadding
                                                                                        ) const noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,5));
                }
                else if(mTransform == CryptoTransform::kEncrypt)
                {
                    CryptoPP::SecByteBlock ciphertext(mKey->getValue().size());
                    encryptor.ProcessData(ciphertext, in.data(), in.size());
                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : ciphertext)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(result);
                }
                else
                {
                    CryptoPP::SecByteBlock ciphertext(mKey->getValue().size());
                    decryptor.ProcessData(ciphertext, in.data(), in.size());
                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : ciphertext)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(result);
                }                   
            }



            /*
                Get the kind of transformation configured for this context: kEncrypt or kDecrypt
                returns CryptoErrorDomain::kUninitializedContext,if SetKey() has not been called yet
            */
            ara::core::Result<CryptoTransform> CryptoPP_AES_SymmetricBlockCipherCtx::GetTransformation () const noexcept
            {
                if(mSetKeyState == helper::setKeyState::CALLED)
                    return ara::core::Result<CryptoTransform>(mTransform);
                else // return error
                {
                    return ara::core::Result<CryptoTransform>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,5));
                }
            }
            



            // ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

            // CryptoService::Uptr GetCryptoService () const noexcept=0;
                                            
            // ara::core::Result<void> Reset () noexcept=0;
        }
    }
}