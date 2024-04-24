#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;

int main()
{
    /****************************************
    *          load a crypto provider       *
    ****************************************/
    InstanceSpecifier specifier("cryptopp");
    auto myProvider = LoadCryptoProvider(specifier);
    if(myProvider == nullptr)
    {
        std::cout << "failed to load crypto provider\n";
        return 0;
    }
    
    /**************************************************************
    *    using loaded crypto provider to generate symmetric key   *
    **************************************************************/
    auto res_genSymtKey = myProvider->GenerateSymmetricKey(HMAC_SHA_256_ALG_ID, kAllowSignature);
    if(!res_genSymtKey.HasValue())
    {
        std::cout << "failed to generate symmetric key\n";

        
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_genSymtKey.Error();
        std::cout << error.Message() << std::endl;

        return 0;
    }
    auto mySymmetricKey = std::move(res_genSymtKey).Value();

    /****************************************
    *       create MessageAuthnCodeCtx      *
    ****************************************/
    auto res_createMessageAuthnCodeCtx = myProvider->CreateMessageAuthCodeCtx(HMAC_SHA_256_ALG_ID);

    if(!res_createMessageAuthnCodeCtx.HasValue())
    {
        std::cout << "failed to create MessageAuthnCodeCtx \n";
        return 0;
    }
    
    auto myMessageAuthnCodeCtx = std::move(res_createMessageAuthnCodeCtx).Value();

    /****************************************
    *         using MessageAuthnCodeCtx     *
    ****************************************/ 
    myMessageAuthnCodeCtx->SetKey(*mySymmetricKey);

    auto res_start = myMessageAuthnCodeCtx->Start();
    if(res_start.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_start.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    //std::uint8_t instr = 'w';
    
    auto res_update =  myMessageAuthnCodeCtx->Update(instr);
    if(res_update.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_update.Error();
        std::cout << error.Message() << std::endl;
        //return 0;
    }

    auto res_finish = myMessageAuthnCodeCtx->Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
      
        auto res_getDigest = myMessageAuthnCodeCtx->GetDigest();
        if(res_getDigest.HasValue())
        {
            std::cout << "--- sucess ---\n";
            
            // get digest value
            auto digestValue = res_getDigest.Value();
            
            printHex(digestValue);
        }
        else
        {
            std::cout << "--- error ---\n";
            ara::core::ErrorCode error = res_getDigest.Error();
            std::cout << error.Message() << std::endl;
        }
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
    } 
    return 0;
}