#include <iostream>
#include "../ara/core/initialization.h"
#include "../ara/crypto/public/keys/cryptopp_key_storage_provider.h"
#include "../ara/crypto/public/common/file_io_interface.h"

using namespace ara::core;
using namespace ara::crypto;

int main()
{
    /*********************************
    *       call Initialize          *
    *********************************/ 
    auto res_Initialize = ara::core::Initialize();
    if(!res_Initialize.HasValue())
    {
        std::cout << "--- error1 ---\n";
        ara::core::ErrorCode error = res_Initialize.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    ara::crypto::keys::Cryptopp_KeyStorageProvider myKeyStorageProvider;

    InstanceSpecifier specifier("ecdsa_sha_256_public_key_1");
    auto res_loadKeySlot = myKeyStorageProvider.LoadKeySlot(specifier);
    if(res_loadKeySlot.HasValue())
    {
        auto mySlot = std::move(res_loadKeySlot).Value();
        auto res_open = mySlot->Open();
        if(res_open.HasValue())
        {
            auto myIoInterface = std::move(res_open).Value();
            std::cout << myIoInterface->IsValid() << std::endl;

            auto myFileIoInterface = std::unique_ptr<File_IOInterface>(static_cast<File_IOInterface*>(myIoInterface.release()));
            if(myFileIoInterface)
            {
                std::cout << myFileIoInterface->getPath() << std::endl;
                
            }
            else
            {
                std::cout << "null\n";
            }
        }
        else
        {
            std::cout << "--- error3 ---\n";
            ara::core::ErrorCode error = res_open.Error();
            std::cout << error.Message() << std::endl;
            return 0;
        }
    }
    else
    {
        std::cout << "--- error2 ---\n";
        ara::core::ErrorCode error = res_loadKeySlot.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    return 0;
}