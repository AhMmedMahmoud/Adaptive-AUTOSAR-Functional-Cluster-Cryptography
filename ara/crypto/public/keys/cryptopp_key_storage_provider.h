#ifndef CRYPTOPP_KEY_STORAGE_PROVIDER_H
#define CRYPTOPP_KEY_STORAGE_PROVIDER_H

#include "../../private/keys/key_storage_provider.h"
#include "cryptopp_keyslot.h"
#include "../../Manifest/CryptoKeySlotInterface.h"
#include "../../Manifest/sharedSlotsInterface.h"


namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class Cryptopp_KeyStorageProvider : public KeyStorageProvider
            {
            private:
                /*********** attributes ************/
                //std::vector<std::unique_ptr<IOInterface>> target;
                //TransactionId serialNumber;

            public:
                /*********** constructor ***********/
                Cryptopp_KeyStorageProvider() : KeyStorageProvider()
                {
                    /*
                    for (const manifest::CryptoKeySlotInterface& Interface : manifest::KeySlotsMetaData) 
                    {
                        std::cout << "InstanceSpecifier: " << Interface.specifier << std::endl;
                        std::cout << "CryptoProvider: " << Interface.CryptoProviderName << std::endl;        
                        std::cout << "AlgId: " << Interface.pro.mAlgId << std::endl;
                        std::cout << "AllowedUsage: " << Interface.pro.mContentAllowedUsage << std::endl;
                        
                        if(Interface.pro.mObjectType == CryptoObjectType::kPrivateKey)
                            std::cout << "Object Type: " << "kPrivateKey" << std::endl;
                        else if(Interface.pro.mObjectType == CryptoObjectType::kPublicKey)
                            std::cout << "Object Type: " << "kPublicKey" << std::endl;
                        
                        if(Interface.pro.mExportAllowed)
                            std::cout << "Exportable: true" << std::endl;
                        else
                            std::cout << "Exportable: false" << std::endl;
                        
                        if(Interface.pro.mSlotType == KeySlotType::kApplication)
                            std::cout << "Slot Type: " << "kApplication" << std::endl;
                        else if(Interface.pro.mSlotType == KeySlotType::kMachine)
                            std::cout << "Slot Type: " << "kMachine" << std::endl;

                        std::cout << "--------------------------\n";
                    }
                    */

                   //serialNumber = 0;
                }

                ara::core::Result<KeySlot::Uptr> LoadKeySlot (ara::core::InstanceSpecifier &iSpecify) noexcept override
                {
                    for(int i = 0; i < manifest::KeySlotsMetaData.size(); i++)
                    {
                        if(manifest::KeySlotsMetaData[i].specifier == iSpecify.ToString())
                        {
                            std::unique_ptr<KeySlot> ptr = std::make_unique<Cryptopp_KeySlot>(manifest::KeySlotsMetaData[i]);

                            return ara::core::Result<KeySlot::Uptr>(std::move(ptr));
                        }
                    }
                    return ara::core::Result<KeySlot::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnreservedResource, NoSupplementaryDataForErrorDescription));
                }

                /*
                ara::core::Result<TransactionId> BeginTransaction (const TransactionScope &targetSlots) noexcept override
                {
                    std::cout << "begin function\n";
                    for (const auto& slot : targetSlots) 
                    {                     
                        target.push_back(std::move(slot->Open().Value()));
                        std::cout << "loop in begin\n";                 
                    }
                    serialNumber++;
                    return ara::core::Result<TransactionId>::FromValue(serialNumber);       
                }

                ara::core::Result<void> CommitTransaction (TransactionId id) noexcept override
                {
                    std::cout << "commit function\n";
                    for(auto& interface : target)
                    {
                        // Release ownership of the Base pointer
                        IOInterface* rawPtr = interface.release();

                        // Reassign the raw pointer to a new unique_ptr of the Derived class
                        std::unique_ptr<File_IOInterface> derivedPtr(static_cast<File_IOInterface*>(rawPtr));
                        
                        // declares an object of ByteQueue (a queue of bytes used to store binary data)
                        CryptoPP::ByteQueue queue = derivedPtr->getQueue();

                        CryptoPP::FileSink file(derivedPtr->getPath().c_str());
  
                        // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                        // effectively writing the key data to the file.
                        queue.CopyTo(file);

                        // signals the end of the message to the FileSink
                        file.MessageEnd();     
                        std::cout << "loop in commit\n";                 
                    }
                    return ara::core::Result<void>::FromValue();
                }
                */


                //virtual UpdatesObserver::Uptr GetRegisteredObserver () const noexcept=0;

                //virtual UpdatesObserver::Uptr RegisterObserver (UpdatesObserver::Uptr observer=nullptr) noexcept=0;

                //virtual ara::core::Result<void> RollbackTransaction (TransactionId id) noexcept=0;

                //virtual ara::core::Result<void> UnsubscribeObserver (KeySlot &slot) noexcept=0;
            };
        }
    }
}


#endif