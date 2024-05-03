#ifndef FILE_IO_INTERFACE_H
#define FILE_IO_INTERFACE_H

#include <filesystem>
#include <cryptopp/files.h>
#include "../../private/common/io_interface.h"
#include "../../private/keys/key_slot_prototype_props.h"

namespace ara
{
    namespace crypto
    {
        class File_IOInterface : public IOInterface
        {
        private:
            std::string mPath;
            keys::KeySlotPrototypeProps mKeySlotPrototypeProps;
            CryptoPP::ByteQueue queue;         

        public:
            File_IOInterface( std::string path,
                              keys::KeySlotPrototypeProps k
                            ) : IOInterface()
            {
                mPath = path;
                mKeySlotPrototypeProps = k;
            }
            
            bool IsValid () const noexcept override
            {
                std::string invalidChars = "\\/:*?\"<>|";
    
                // Check for invalid characters and spaces
                for (char c : mPath) {
                    if (invalidChars.find(c) != std::string::npos || c == ' ') {
                        return false;
                    }
                }
                
                // Check for file extension ".key"
                if (mPath.length() < 4 || mPath.substr(mPath.length() - 4) != ".key") {
                    return false;
                }
                
                return true;
            }

            bool IsWritable () const noexcept override
            {
                if(!IsValid())
                    return false;

                std::filesystem::file_status status = std::filesystem::status(mPath);
                std::filesystem::perms permissions = status.permissions();

                return (permissions & std::filesystem::perms::owner_write) != std::filesystem::perms::none;
            }

            std::string getPath()
            {
                return mPath;
            }

            void setQueue(CryptoPP::ByteQueue queue)
            {
                this->queue = queue;
            }

            CryptoPP::ByteQueue getQueue()
            {
                return queue;
            }

            /*
            virtual CryptoObjectUid GetObjectId () const noexcept=0;
            
            virtual std::size_t GetCapacity () const noexcept=0;
            
            virtual std::size_t GetPayloadSize () const noexcept=0;
            
            virtual CryptoAlgId GetPrimitiveId () const noexcept=0;
            
            virtual AllowedUsageFlags GetAllowedUsage () const noexcept=0;

            virtual CryptoObjectType GetCryptoObjectType () const noexcept=0;
       
            virtual CryptoObjectType GetTypeRestriction () const noexcept=0;

            virtual bool IsObjectExportable () const noexcept=0;
            
            virtual bool IsObjectSession () const noexcept=0;
            
            virtual bool IsVolatile () const noexcept=0;           
            */
        };
    }
}

#endif