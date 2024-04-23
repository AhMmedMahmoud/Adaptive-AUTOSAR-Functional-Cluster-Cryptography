#ifndef CRYPTOPP_RSA_PUBLIC_KEY_H
#define CRYPTOPP_RSA_PUBLIC_KEY_H

#include "../../../private/cryp/cryobj/public_key.h"
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
            class CryptoPP_RSA_PublicKey : public PublicKey
            {
            private:
                /************ attributes ***************/
                CryptoPP::RSA::PublicKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_RSA_PublicKey() {}

                /************ Copy constructor *********/
                CryptoPP_RSA_PublicKey(const CryptoPP_RSA_PublicKey& other) {
                    mValue = other.mValue;
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PublicKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_RSA_PublicKey> ptr = std::make_unique<CryptoPP_RSA_PublicKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::RSA::PublicKey>("rsa_public.key");
                    
                    return std::move(ptr);  
                }

                /************ getter and setter ***********/
                CryptoPP::RSA::PublicKey getValue()
                {
                    return mValue;
                }

                void setValue(CryptoPP::RSA::PublicKey mValue)
                {
                    this->mValue = mValue;
                }
   
                /************* override parent functions ************/
                Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowDataEncryption;
                }

                /*            
                bool CheckKey(bool strongCheck=true) const noexcept override

                ara::core::Result<ara::core::Vector<ara::core::Byte> > HashPublicKey (HashFunctionCtx &hashFunc) const noexcept override

                COIdentifier GetObjectId () const noexcept override

                COIdentifier HasDependence () const noexcept override

                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override

                std::size_t GetPayloadSize () const noexcept override

                bool IsExportable () const noexcept override
      
                bool IsSession () const noexcept override
                
                ara::core::Result<void> Save (IOInterface &container) const noexcept override
                */
            };
        }
    }
}





#endif