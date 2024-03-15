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
#include <iostream>
#include <string>
#include "cryobj/cryptopp_crypto_primitive_id.h"


std::string bytes_to_hex(const uint8_t* data, size_t size);

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            /*
                this helper class doesnot mention in autosar 
            */
            enum class setKeyState
            {
                CALLED,
                NOT_CALLED
            };

            class CryptoPP_AES_SymmetricBlockCipherCtx : public SymmetricBlockCipherCtx 
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 1;


            private:
                /*****************  attributes **********************/
                CryptoPP_AES_SymmetricKey *mKey;
                CryptoTransform  mTransform;
                CryptoPP_CryptoPrimitiveId mPId;
                setKeyState mSetKeyState;

            public:
                using Uptr = std::unique_ptr<CryptoPP_AES_SymmetricBlockCipherCtx>;

                /***************** constructor **********************/
                CryptoPP_AES_SymmetricBlockCipherCtx();

                
                /******************* override virtual functions of parent ***********/
                /*
                    Return CryptoPrimitivId instance containing instance identification
                */
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;


                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                virtual bool IsInitialized () const noexcept override;
      

                /*
                    takes key and type of processing we want (type of operation ex:Encryption or decryption)
                */
                virtual ara::core::Result<void> SetKey( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                      ) noexcept override;
                
                                
                /* 
                    takes the data that we want to process (preform an operation on it)
                */                
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlock ( ReadOnlyMemRegion in,
                                                                                            bool suppressPadding=false
                                                                                            ) const noexcept;



                //virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;
                
                //virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

                //virtual CryptoService::Uptr GetCryptoService () const noexcept=0;
                                                
                //virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}

#endif