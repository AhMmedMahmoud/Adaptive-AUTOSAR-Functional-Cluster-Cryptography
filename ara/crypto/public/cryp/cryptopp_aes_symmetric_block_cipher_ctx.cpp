#include "cryptopp_aes_symmetric_block_cipher_ctx.h"


std::string bytes_to_hex(const uint8_t* data, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            const std::string CryptoPP_AES_SymmetricBlockCipherCtx::mAlgName("aes_ecb");

            /***************** constructor **********************/
            CryptoPP_AES_SymmetricBlockCipherCtx::CryptoPP_AES_SymmetricBlockCipherCtx(): mKey(nullptr),
                                                    mTransform(CryptoTransform::kEncrypt),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(setKeyState::NOT_CALLED)
            {}


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
                return (mSetKeyState == setKeyState::CALLED && mKey != nullptr);
            }
            

            /*
                takes key and type of processing we want (type of operation ex:Encryption or decryption)
            */
            ara::core::Result<void> CryptoPP_AES_SymmetricBlockCipherCtx::SetKey( const SymmetricKey &key,
                                                    CryptoTransform transform
                                                    ) noexcept
            {  
                try
                {
                    const CryptoPP_AES_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_AES_SymmetricKey&>(key);
                    mKey = new CryptoPP_AES_SymmetricKey(aesKey);
                    mSetKeyState = setKeyState::CALLED;
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) {
                    std::cerr << "Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey: " << e.what() << std::endl;
                    //return ara::core::Result<void>::FromError();
                }
            }
            
                            
            /* 
                takes the data that we want to process (preform an operation on it)
            */                
            ara::core::Result<ara::core::Vector<ara::core::Byte> > CryptoPP_AES_SymmetricBlockCipherCtx::ProcessBlock ( ReadOnlyMemRegion in,
                                                                                        bool suppressPadding
                                                                                        ) const noexcept
            {
                try 
                {
                    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryptor;
                    encryptor.SetKey(mKey->getKey(), mKey->getKey().size());
                    //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;
            
                    std::string plain(in.begin(), in.end());
                    std::cout << "Input Data: " << plain << std::endl;

                    std::string cipher;
                    CryptoPP::StringSource(plain, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));
                    //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                    //std::cout << "Cipher Text: " << cipher << std::endl;

                    ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                } 
                catch (const CryptoPP::Exception& e) {
                    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                }
            }

            // ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;
            
            // ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

            // CryptoService::Uptr GetCryptoService () const noexcept=0;
                                            
            // ara::core::Result<void> Reset () noexcept=0;
        }
    }
}