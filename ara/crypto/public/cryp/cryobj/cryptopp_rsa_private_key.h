#ifndef CRYPTOPP_RSA_PRIVATE_KEY_H
#define CRYPTOPP_RSA_PRIVATE_KEY_H

#include "../../../private/cryp/cryobj/private_key.h"
#include "cryptopp_rsa_public_key.h"

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include "cryptopp/hex.h"
#include <iostream>
#include <string>
#include "loadKey.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_RSA_PrivateKey : public PrivateKey
            {
            private:
                /************ attributes ***************/
                CryptoPP::RSA::PrivateKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_RSA_PrivateKey() {}

                /************ Copy constructor *********/
                CryptoPP_RSA_PrivateKey(const CryptoPP_RSA_PrivateKey& other) {
                    mValue = other.mValue;
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PrivateKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_RSA_PrivateKey> ptr = std::make_unique<CryptoPP_RSA_PrivateKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::RSA::PrivateKey>("rsa_private.key");
                    
                    return std::move(ptr);  
                }

                /************ getter and setter ***********/
                CryptoPP::RSA::PrivateKey getValue()
                {
                    return mValue;
                }

                void setValue(CryptoPP::RSA::PrivateKey mValue)
                {
                    this->mValue = mValue;
                }
   
                /************* override parent functions ************/
                virtual ara::core::Result<PublicKey::Uptrc> GetPublicKey () const noexcept override
                {
                    CryptoPP::RSA::PublicKey publicKey(mValue);

                    std::unique_ptr<CryptoPP_RSA_PublicKey> ptr = std::make_unique<CryptoPP_RSA_PublicKey>();
                  
                    ptr->setValue(publicKey);

                    return ara::core::Result<PublicKey::Uptrc>(std::move(ptr));
                }

                virtual Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowDataDecryption;
                }



                /*
                virtual COIdentifier GetObjectId () const noexcept override

                virtual COIdentifier HasDependence () const noexcept override

                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override

                virtual std::size_t GetPayloadSize () const noexcept override

                virtual bool IsExportable () const noexcept override

                virtual bool IsSession () const noexcept override
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept override
                
                */
            };
        }
    }
}





#endif