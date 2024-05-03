#ifndef IO_INTERFACE_H
#define IO_INTERFACE_H


#include <memory>
#include "crypto_object_uid.h"
#include "base_id_types.h"

namespace ara
{
    namespace crypto
    {
        class IOInterface
        {
        public:
            using Uptr = std::unique_ptr<IOInterface>;
            using Uptrc = std::unique_ptr<const IOInterface>;
            
                        
            virtual bool IsValid () const noexcept=0;
            
            virtual bool IsWritable () const noexcept=0;
            
            /*
            virtual CryptoObjectUid GetObjectId () const noexcept=0;
            
            virtual std::size_t GetCapacity () const noexcept=0;
            
            virtual std::size_t GetPayloadSize () const noexcept=0;
            
            virtual CryptoAlgId GetPrimitiveId () const noexcept=0;
            
            virtual AllowedUsageFlags GetAllowedUsage () const noexcept=0;

            virtual CryptoObjectType GetCryptoObjectType () const noexcept=0;
       
            virtual bool IsObjectExportable () const noexcept=0;
            
            virtual CryptoObjectType GetTypeRestriction () const noexcept=0;
            
            virtual bool IsObjectSession () const noexcept=0;
            
            virtual bool IsVolatile () const noexcept=0;
            */
            

            /*********** copy assignment operators *******/
            IOInterface& operator= (const IOInterface &other)=default;
            
            /*********** move assignment operators *******/
            IOInterface& operator= (IOInterface &&other)=default;
            
            /*********** default deconstructor ************/
            virtual ~IOInterface () noexcept=default;
        };
    }
}

#endif