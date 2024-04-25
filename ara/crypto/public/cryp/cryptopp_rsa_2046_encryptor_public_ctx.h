#ifndef CRYPTOPP_RSA_2046_ENCRYPTOR_PUBLIC_CTX_H
#define CRYPTOPP_RSA_2046_ENCRYPTOR_PUBLIC_CTX_H

#include "../../private/cryp/encryptor_public_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_rsa_2046_public_key.h"
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_RSA_EncryptorPublicCtx : public EncryptorPublicCtx 
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 4;


            private:
                /*****************  attributes **********************/
                CryptoPP_RSA_2046_PublicKey *mKey;
                CryptoPP_CryptoPrimitiveId mPId;
                helper::setKeyState mSetKeyState;

            public:
                /***************** constructor **********************/   
                CryptoPP_RSA_EncryptorPublicCtx();


                /****** override pure virtual functions related to CryptoContext *****/
                //  Return CryptoPrimitivId instance containing instance identification
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related EncryptorPublicCtx *****/
                ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlock ( ReadOnlyMemRegion in,
                                                                                            bool suppressPadding=false
                                                                                            ) const noexcept override;

                ara::core::Result<void> SetKey (const PublicKey &key) noexcept override;
                
                // ara::core::Result<void> Reset () noexcept override;
            };
        }
    }
}

#endif