#ifndef KEY_SLOT_H
#define KEY_SLOT_H

#include "../../../core/result.h"
#include "../common/io_interface.h"
#include "key_slot_content_props.h"
#include "key_slot_prototype_props.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class KeySlot
            {
            public:
                using Uptr = std::unique_ptr<KeySlot>;

                virtual ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates=false, bool writeable=false) const noexcept=0;

                virtual ara::core::Result<KeySlotContentProps> GetContentProps () const noexcept=0;

                virtual ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept=0;

                /*
                virtual ara::core::Result<cryp::CryptoProvider::Uptr> MyProvider () const noexcept=0;
        
                virtual ara::core::Result<void> Clear () noexcept=0;

                virtual bool IsEmpty () const noexcept=0;

                virtual ara::core::Result<void> SaveCopy (const IOInterface &container) noexcept=0;
                */

                
                KeySlot& operator= (const KeySlot &other)=default;
                
                KeySlot& operator= (KeySlot &&other)=default;
                
                virtual ~KeySlot () noexcept=default;
            };
        }   
    }   
}

#endif