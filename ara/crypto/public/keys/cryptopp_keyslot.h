#ifndef CRYPTOPP_KEY_SLOT_H
#define CRYPTOPP_KEY_SLOT_H

#include "../../private/keys/keyslot.h"
#include "../../private/common/crypto_error_domain.h"
#include "../common/file_io_interface.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class Cryptopp_KeySlot : public KeySlot
            {
                /*
                "InstanceSpecifier"  : "rsa_2046_public_key_1",
                "CryptoProvider"     : "CryptoppCryptoProvider",
                "KeyMaterialPath"    : "rsa_2046_public_key_1.key",
                
                --> "ALgId"              : 5,
                --> "AllowUsageFlags"    : 4,
                --> "CryptoObjectType"   : "kPublicKey",
                --> "Exportable"         : true,
                --> "SlotType"           : "kApplication",
                --> "slotCapacity"       : 10000,
                --> "AllocateShadowCopy" : false,
                --> "MaxUpdateAllowed"   : -1
                */
            private:
                std::string mPath;

                KeySlotContentProps mKeySlotContentProps;
                /*
                    struct KeySlotContentProps
                    {
                        CryptoAlgId mAlgId; 
                        AllowedUsageFlags mContentAllowedUsage;
                        CryptoObjectType mObjectType;

                        std::size_t mObjectSize;
                        CryptoObjectUid mObjectUid;
                    };
                */

                KeySlotPrototypeProps mKeySlotPrototypeProps;
                /*
                    struct KeySlotPrototypeProps
                    {
                        using Uptr = std::unique_ptr<KeySlotPrototypeProps>;
                        
                        CryptoAlgId mAlgId;
                        AllowedUsageFlags mContentAllowedUsage;
                        CryptoObjectType mObjectType;
                        bool mExportAllowed;
                        KeySlotType mSlotType;
                        std::size_t mSlotCapacity;
                        bool mAllocateSpareSlot;
                        bool mAllowContentTypeChange;
                        std::int32_t mMaxUpdateAllowed;

                        KeySlotPrototypeProps ()=default;
                    };
                */
            public:
                /*********** constructor **********/
                Cryptopp_KeySlot( manifest::CryptoKeySlotInterface mCryptoKeySlotInterface) : KeySlot()
                {
                    mPath = mCryptoKeySlotInterface.CryptoObjectPath;
                    mKeySlotPrototypeProps = mCryptoKeySlotInterface.pro;
                }


                ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates=false, bool writeable=false) const noexcept
                {     
                    std::unique_ptr<IOInterface> ptr = std::make_unique<File_IOInterface>(mPath,mKeySlotPrototypeProps);
                    
                    return ara::core::Result<IOInterface::Uptr>(std::move(ptr));
                    
                    //return ara::core::Result<File_IOInterface::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }

                virtual ara::core::Result<KeySlotContentProps> GetContentProps () const noexcept override
                {
                    return ara::core::Result<KeySlotContentProps>(mKeySlotContentProps);
                }

                virtual ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept override
                {
                    return ara::core::Result<KeySlotPrototypeProps>(mKeySlotPrototypeProps);
                }

                /*
                virtual ara::core::Result<cryp::CryptoProvider::Uptr> MyProvider () const noexcept=0;

                virtual ara::core::Result<void> Clear () noexcept=0;

                virtual bool IsEmpty () const noexcept=0;

                virtual ara::core::Result<void> SaveCopy (const IOInterface &container) noexcept=0;
                */
            };
        }   
    }   
}

#endif