#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_public_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h"
#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_private_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h"
#include "../ara/crypto/helper/print.h"
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/core/instance_specifier.h"

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
    *    using loaded crypto provider to generate private key     *
    **************************************************************/
    auto res_genPrKey = myProvider->GeneratePrivateKey(RSA_2048_ALG_ID,kAllowDataEncryption);
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


    /****************************************
    *          load keys (not autosar)      *
    ****************************************/
    //PublicKey::Uptrc myPublicKey = CryptoPP_RSA_PublicKey::createInstance();
    //PrivateKey::Uptrc myPrivateKey = CryptoPP_RSA_PrivateKey::createInstance();


    /****************************************
    *          create rsa contexts          *
    ****************************************/
    auto res_reateEncryptorPublicCtx = myProvider->CreateEncryptorPublicCtx(RSA_2048_ALG_ID);
    auto res_reateDecryptorPrivateCtx = myProvider->CreateDecryptorPrivateCtx(RSA_2048_ALG_ID);

    if(!res_reateEncryptorPublicCtx.HasValue() && !res_reateDecryptorPrivateCtx.HasValue())
    {
        std::cout << "failed two create rsa contexts\n";
        return 0;
    }
    
    auto myEncryptorPublicCtx = std::move(res_reateEncryptorPublicCtx).Value();
    auto myDecryptorPrivateCtx = std::move(res_reateDecryptorPrivateCtx).Value();


    /**************************************
    *        using EncryptorPublicCtx     *  
    ***************************************/    
    myEncryptorPublicCtx->SetKey(*myPublicKey);
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    auto _result = myEncryptorPublicCtx->ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get encrypted data
        auto encryptedDataVector = _result.Value();
        
        printHex(encryptedDataVector);  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    /**************************************
    *       using DecryptorPrivateCtx     *
    **************************************/  
    myDecryptorPrivateCtx->SetKey(*myPrivateKey);
    
    // get encrypted data
    auto encryptedDataVector = _result.Value();

    auto _result_decryptorPrivateCtx = myDecryptorPrivateCtx->ProcessBlock(encryptedDataVector);
    if(_result_decryptorPrivateCtx.HasValue())
    {
        std::cout << "--- sucess ---\n";

        // get decrypted data
        auto decryptedDataVector = _result_decryptorPrivateCtx.Value();

        printVector("recovered text: ", decryptedDataVector);
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result_decryptorPrivateCtx.Error();
        std::cout << error.Message() << std::endl;
    }
        
    return 0;
}