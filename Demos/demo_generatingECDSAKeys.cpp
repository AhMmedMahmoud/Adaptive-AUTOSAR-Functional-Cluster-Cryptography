#include "../ara/core/initialization.h"
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
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

    /****************************************
    *       load a key storage provider     *
    ****************************************/
    auto myKeyStorageProvider = LoadKeyStorageProvider();
    if(myKeyStorageProvider == nullptr)
    {
        std::cout << "failed to load crypto provider\n";
        return 0;
    }

    /**************************************************************
    *    using loaded key storage provider to acess private key   *
    **************************************************************/
    InstanceSpecifier privateKeySpecifier("ecdsa_sha_256_private_key_1");
    auto res_loadKeySlot = myKeyStorageProvider->LoadKeySlot(privateKeySpecifier);
    if(!res_loadKeySlot.HasValue())
    {
        std::cout << "--- error2 ---\n";
        ara::core::ErrorCode error = res_loadKeySlot.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto mySlot = std::move(res_loadKeySlot).Value();
    auto res_open = mySlot->Open();
    if(!res_open.HasValue())
    {
        std::cout << "--- error3 ---\n";
        ara::core::ErrorCode error = res_open.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto privateKeyIoInterface = std::move(res_open).Value();

    /**************************************************************
    *    using loaded key storage provider to acess public key    *
    **************************************************************/
    InstanceSpecifier publicKeySpecifier("ecdsa_sha_256_public_key_1");
    auto res_loadKeySlot2 = myKeyStorageProvider->LoadKeySlot(publicKeySpecifier);
    if(!res_loadKeySlot2.HasValue())
    {
        std::cout << "--- error4 ---\n";
        ara::core::ErrorCode error = res_loadKeySlot2.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto mySlot2 = std::move(res_loadKeySlot2).Value();
    auto res_open2 = mySlot2->Open();
    if(!res_open2.HasValue())
    {
        std::cout << "--- error5 ---\n";
        ara::core::ErrorCode error = res_open2.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto publicKeyIoInterface = std::move(res_open2).Value();
  
    /****************************************
    *          load a crypto provider       *
    ****************************************/
    InstanceSpecifier crypoProviderSpecifier("cryptopp");
    auto myCryptoProvider = LoadCryptoProvider(crypoProviderSpecifier);
    if(myCryptoProvider == nullptr)
    {
        std::cout << "failed to load crypto provider\n";
        return 0;
    }
    
    /**************************************************************
    *    using loaded crypto provider to generate private key     *
    **************************************************************/
    auto res_genPrKey = myCryptoProvider->GeneratePrivateKey(ECDSA_SHA_256_ALG_ID,kAllowSignature);
    if(!res_genPrKey.HasValue())
    {
        std::cout << "failed to generate private key\n";
        return 0;
    }
    auto myPrivateKey = std::move(res_genPrKey).Value();


    /**************************************************************
    *    getting public key from private key object               *
    **************************************************************/
    auto res_getPkKey = myPrivateKey->GetPublicKey();
    if(!res_getPkKey.HasValue())
    {
        std::cout << "failed to get public key\n";
        return 0;
    }
    auto myPublicKey = std::move(res_getPkKey).Value();


    /**************************************
    *          save private key 
    **************************************/ 
    auto res_save_private = myPrivateKey->Save(*privateKeyIoInterface);
    if(!res_save_private.HasValue())
    {
        std::cout << "failed to save private key\n";
        return 0;
    }
    
    /**************************************
    *          save public key 
    **************************************/ 
    auto res_save_public = myPublicKey->Save(*publicKeyIoInterface);
    if(!res_save_public.HasValue())
    {
        std::cout << "failed to save public key\n";
    }

    std::cout << "ECDSA Keys are generated succuessfully\n";
    return 0;
}
