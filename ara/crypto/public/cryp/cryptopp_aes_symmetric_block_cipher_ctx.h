#ifndef CRYPTOPP_AES_SYMMETRIC_BLOCK_CIPHER_CTX_h
#define CRYPTOPP_AES_SYMMETRIC_BLOCK_CIPHER_CTX_h


#include "../../private/cryp/symmetric_block_cipher_ctx.h"
#include "cryobj/cryptopp_aes_symmetric_key.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"

// header files for standard C++ library
#include <iostream>
#include <string>

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
            class CryptoPP_AES_SymmetricBlockCipherCtx : public SymmetricBlockCipherCtx 
            {
            private:
                /*****************  attributes **********************/
                CryptoPP_AES_SymmetricKey *mKey;
                CryptoTransform  mTransform;

            public:
                /***************** constructor **********************/
                CryptoPP_AES_SymmetricBlockCipherCtx(): mKey(nullptr),
                                                        mTransform(CryptoTransform::kEncrypt)
                {

                }

                using Uptr = std::unique_ptr<CryptoPP_AES_SymmetricBlockCipherCtx>;
                
                
                /*
                    takes key and type of processing we want (type of operation ex:Encryption or decryption)
                */
                virtual ara::core::Result<void> SetKey( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                      ) noexcept override
                {  
                    /*
                    std::cout << "kkkkkkk\n";
                    mKey = new CryptoPP_AES_SymmetricKey(key);
                    std::cout << "aaaaaaaaaa\n";
                    mTransform = transform;

                    return ara::core::Result<void>::FromValue();
                    */
                    try {
                        const CryptoPP_AES_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_AES_SymmetricKey&>(key);
                        mKey = new CryptoPP_AES_SymmetricKey(aesKey);
                        return ara::core::Result<void>::FromValue();
                    } catch (const std::bad_cast& e) {
                        std::cerr << "Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey: " << e.what() << std::endl;
                        //return ara::core::Result<void>::FromError();
                    }
                }
                
                
                //virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;
                
                
                /* 
                    takes the data that we want to process (preform an operation on it)
                */
                
                
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlock ( ReadOnlyMemRegion in,
                                                                                            bool suppressPadding=false
                                                                                            ) const noexcept
                {
                    try 
                    {
                        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryptor;
                        encryptor.SetKey(mKey->getKey(), mKey->getKey().size());
                        std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;
              

                        std::string plain(in.begin(), in.end());
                        std::cout << "Input Data: " << plain << std::endl;

                        std::string cipher;
                        CryptoPP::StringSource(plain, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));
                        std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                    } 
                    catch (const CryptoPP::Exception& e) {
                        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                    }
                }

                
                
                //virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

                //virtual CryptoService::Uptr GetCryptoService () const noexcept=0;
                                                
                //virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}

#endif