#include <iostream>
#include <iomanip> // Include the header file for setfill
#include <sstream>
#include <string>

#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_public_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h"

#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_private_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h"


using namespace ara::crypto::cryp;
int main()
{
    /************************************************************
    *                   EncryptorPublicCtx                      *
    ************************************************************/

    PublicKey::Uptrc myPublicKey = CryptoPP_RSA_PublicKey::createInstance();

    CryptoPP_RSA_EncryptorPublicCtx myEncryptorPublicCtx;
    
    myEncryptorPublicCtx.SetKey(*myPublicKey);
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    auto _result = myEncryptorPublicCtx.ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get encrypted data
        auto encryptedDataVector = _result.Value();
        
        // Convert digest to hexadecimal string
        std::stringstream ss;
        std::cout << "encryted text: ";
        for (const auto& byte : encryptedDataVector) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        // Print the hexadecimal digest
        std::cout << ss.str() << std::endl;
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    /************************************************************
    *                   DecryptorPrivateCtx                     *
    ************************************************************/
   
    PrivateKey::Uptrc myPrivateKey = CryptoPP_RSA_PrivateKey::createInstance();
        
    CryptoPP_RSA_DecryptorPrivateCtx myDecryptorPrivateCtx;
    
    myDecryptorPrivateCtx.SetKey(*myPrivateKey);
    
    // get encrypted data
    auto encryptedDataVector = _result.Value();

    auto _result_decryptorPrivateCtx = myDecryptorPrivateCtx.ProcessBlock(encryptedDataVector);
    if(_result_decryptorPrivateCtx.HasValue())
    {
        std::cout << "--- sucess ---\n";

        // get decrypted data
        auto decryptedDataVector = _result_decryptorPrivateCtx.Value();

        std::string decryptedDataString(decryptedDataVector.begin(), decryptedDataVector.end());
        std::cout << "recovered text: " << decryptedDataString << std::endl;
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result_decryptorPrivateCtx.Error();
        std::cout << error.Message() << std::endl;
    }
        

    return 0;
}