#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;

#define example_string 1
#define example_vector 2
#define example example_string

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
    auto res_genPrKey = myProvider->GenerateSymmetricKey(AES_ECB_128_ALG_ID,kAllowKdfMaterialAnyUsage);
    if(!res_genPrKey.HasValue())
    {
        std::cout << "failed to generate symmetric key\n";
        return 0;
    }
    auto mySymmetricKey = std::move(res_genPrKey).Value();


    /****************************************
    *     create SymmetricBlockCipherCtx    *
    ****************************************/
    auto res_createSymmetricBlockCipherCtx = myProvider->CreateSymmetricBlockCipherCtx(AES_ECB_128_ALG_ID);

    if(!res_createSymmetricBlockCipherCtx.HasValue())
    {
        std::cout << "failed two create ecdsa contexts\n";
        return 0;
    }
    
    auto mySymmetricBlockCipherCtx = std::move(res_createSymmetricBlockCipherCtx).Value();


    /****************************************
    *      using SymmetricBlockCipherCtx    *
    ****************************************/  
    mySymmetricBlockCipherCtx->SetKey(*mySymmetricKey);

/*    
    std::string str = "mr ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
*/

#if(example == example_string)
    std::string str = "mr ahmed mahmoud";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
#elif(example == example_vector)
    std::vector<uint8_t> instr = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
#endif

    auto _result = mySymmetricBlockCipherCtx->ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get encrypted data
        auto encryptedDataVector = _result.Value();

        printHex(instr, "Message: ");
        printHex(encryptedDataVector, "Encrypted Message: "); 
        
        mySymmetricBlockCipherCtx->SetKey(*mySymmetricKey,ara::crypto::CryptoTransform::kDecrypt);
        
        auto _result2 = mySymmetricBlockCipherCtx->ProcessBlock(encryptedDataVector);
        if(_result2.HasValue())
        {
            std::cout << "--- sucess ---\n";
            
            // get decrypted data
            auto decryptedDataVector = _result2.Value();

#if(example == example_string)       
            printVector(decryptedDataVector, "Decrypted Message: ");
#endif
            printHex(decryptedDataVector, "Decrypted Message: "); 

        }
        else
        {
            std::cout << "--- error ---\n";
            ara::core::ErrorCode error = _result.Error();
            std::cout << error.Message() << std::endl;
        }
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
    }
    
    return 0;
}