#ifndef CRYPTOPP_AES_SUMMETRIC_KEY_H
#define CRYPTOPP_AES_SUMMETRIC_KEY_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "../../../private/cryp/cryobj/symmetric_key.h"

#define default_key_length_in_Byte  16 
#define min_key_length_in_Byte  16 
#define max_key_length_in_Byte  32 

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_AES_SymmetricKey : public SymmetricKey
            {
            private:
                /*************** attributes *************/
                CryptoPP::SecByteBlock mValue;

            public:
                /************ constructor **************/
                CryptoPP_AES_SymmetricKey() : mValue(default_key_length_in_Byte)
                {}

                /************ Copy constructor *********/
                CryptoPP_AES_SymmetricKey(const CryptoPP_AES_SymmetricKey& other) : mValue(other.mValue.size()) {
                    mValue.Assign(other.mValue, other.mValue.size());
                }

                CryptoPP_AES_SymmetricKey(const SymmetricKey& obj)
                { 
                   mValue = ((CryptoPP_AES_SymmetricKey)obj).mValue;
                }
                
                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<SymmetricKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_AES_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_SymmetricKey>();
                    
                    std::string key = "0123456789abcdef";
                    ptr->mValue.Assign((const CryptoPP::byte*)key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
                         
                    return std::move(ptr);                    
                }

                /************ getter and setter ***********/
                CryptoPP::SecByteBlock getValue()
                {
                    return mValue;
                }

                /************* override parent functions ************/
                virtual Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowKdfMaterialAnyUsage;
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