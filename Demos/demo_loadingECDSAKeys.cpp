#include "../ara/core/initialization.h"
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;

#define example_string 1
#define example_vector 2
#define example example_vector

int main()
{
    /*********************************
    *       call Initialize          *
    *********************************/ 
    auto res_Initialize = ara::core::Initialize();
    if(!res_Initialize.HasValue())
    {
        std::cout << "--- error ---\n";
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
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_loadKeySlot.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto mySlot = std::move(res_loadKeySlot).Value();
    auto res_open = mySlot->Open();
    if(!res_open.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_open.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto myIoInterface = std::move(res_open).Value();

    /**************************************************************
    *    using loaded key storage provider to acess public key    *
    **************************************************************/
    InstanceSpecifier publicKeySpecifier("ecdsa_sha_256_public_key_1");
    auto res_loadKeySlot2 = myKeyStorageProvider->LoadKeySlot(publicKeySpecifier);
    if(!res_loadKeySlot2.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_loadKeySlot2.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    auto mySlot2 = std::move(res_loadKeySlot2).Value();
    auto res_open2 = mySlot2->Open();
    if(!res_open2.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_open2.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto myIoInterface2 = std::move(res_open2).Value();

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
    *    using loaded crypto provider to load private key         *
    **************************************************************/
    auto res_loadPrKey = myCryptoProvider->LoadPrivateKey(*myIoInterface);
    if(!res_loadPrKey.HasValue())
    {
        std::cout << "--- error in loading private key ---\n";
        ara::core::ErrorCode error = res_loadPrKey.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto myPrivateKey = std::move(res_loadPrKey).Value();

    /**************************************************************
    *    using loaded crypto provider to load public key         *
    **************************************************************/
   auto res_loadPUKey = myCryptoProvider->LoadPublicKey(*myIoInterface2);
    if(!res_loadPUKey.HasValue())
    {
        std::cout << "--- error in loading public key---\n";
        ara::core::ErrorCode error = res_loadPUKey.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    auto myPublicKey = std::move(res_loadPUKey).Value();


    /****************************************
    *          create ecdsa contexts        *
    ****************************************/
    auto res_createSigEncodePrivateCtx = myCryptoProvider->CreateSigEncodePrivateCtx(ECDSA_SHA_256_ALG_ID);
    auto res_createMsgRecoveryPublicCtx = myCryptoProvider->CreateMsgRecoveryPublicCtx(ECDSA_SHA_256_ALG_ID);

    if(!res_createSigEncodePrivateCtx.HasValue() && !res_createMsgRecoveryPublicCtx.HasValue())
    {
        std::cout << "failed to create ecdsa contexts\n";
        return 0;
    }
    
    auto mySigEncodePrivateCtx = std::move(res_createSigEncodePrivateCtx).Value();
    auto myMsgRecoveryPublicCtx = std::move(res_createMsgRecoveryPublicCtx).Value();


    /****************************************
    *        using SigEncodePrivateCtx      *
    ****************************************/
    mySigEncodePrivateCtx->SetKey(*myPrivateKey);

#if(example == example_string)
    std::string str = "ahmed mahmoud";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
#elif(example == example_vector)
    std::vector<uint8_t> instr = {1,2,3,4,5,6,7,8};
#endif

    auto _result = mySigEncodePrivateCtx->SignAndEncode(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get messagePlusSignature
        auto messagePlusSignature = _result.Value();
        
        printHex(instr, "Message: ");                 
        printHex(messagePlusSignature, "SignedMessage: ");  
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    std::cout << "------------------------------\n";



    /****************************************
    *       using  MsgRecoveryPublicCtx     *
    ****************************************/  
    myMsgRecoveryPublicCtx->SetKey(*myPublicKey);
    
    // get messagePlusSignature
    auto messagePlusSignature = _result.Value();

    //messagePlusSignature[0] = '0';

    auto _result2 = myMsgRecoveryPublicCtx->DecodeAndVerify(messagePlusSignature);   
    if(_result2.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get recoveryMessage
        auto recoveryMessage = _result2.Value();

#if(example == example_string)       
        printVector(recoveryMessage, "Verified Message: ");
#endif
        printHex(recoveryMessage, "Verified Message: ");  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result2.Error();
        std::cout << error.Message() << std::endl;
    }

    return 0;
}
