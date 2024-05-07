#ifndef KEY_STORAGE_PROVIDER_h
#define KEY_STORAGE_PROVIDER_h

#include "../../../core/instance_specifier.h"
#include "elementary_types.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class KeyStorageProvider
            {
            public:
                using Uptr = std::unique_ptr<KeyStorageProvider>;

                virtual ara::core::Result<KeySlot::Uptr> LoadKeySlot (ara::core::InstanceSpecifier &iSpecify) noexcept=0;


                //virtual ara::core::Result<TransactionId> BeginTransaction (const TransactionScope &targetSlots) noexcept=0;

                //virtual ara::core::Result<void> CommitTransaction (TransactionId id) noexcept=0;
            
                //virtual UpdatesObserver::Uptr GetRegisteredObserver () const noexcept=0;

                //virtual UpdatesObserver::Uptr RegisterObserver (UpdatesObserver::Uptr observer=nullptr) noexcept=0;

                //virtual ara::core::Result<void> RollbackTransaction (TransactionId id) noexcept=0;

                //virtual ara::core::Result<void> UnsubscribeObserver (KeySlot &slot) noexcept=0;


                KeyStorageProvider& operator= (const KeyStorageProvider &other)=default;

                KeyStorageProvider& operator= (KeyStorageProvider &&other)=default;	
                
                virtual ~KeyStorageProvider () noexcept=default;
            };
        }
    }
}


#endif