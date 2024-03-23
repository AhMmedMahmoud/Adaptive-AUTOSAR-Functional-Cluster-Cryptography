#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "../ara/crypto/public/cryp/cryobj/cryptopp_hmac_sha_256_signature.h"
#include "../ara/crypto/private/common/mem_region.h"

using namespace ara::crypto::cryp;

int main()
{
    CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx myContext;

    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();

    myContext.SetKey(*myKey);

    auto res_start = myContext.Start();
    if(res_start.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_start.Error();
        std::cout << error.Message() << std::endl;
        //return 0;
    }
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    //std::uint8_t instr = 'w';
    

    auto res_update =  myContext.Update(instr);
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


    auto res_finish = myContext.Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
        // Convert digest to hexadecimal string
      
        auto res_getDigest = myContext.GetDigest();
        if(res_getDigest.HasValue())
        {
            std::cout << "--- sucess ---\n";
              std::stringstream ss;
            for (const auto& byte : res_getDigest.Value()) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            // Print the hexadecimal digest
            std::cout << ss.str() << std::endl;
        }
        else
        {
            std::cout << "--- error ---\n";
            ara::core::ErrorCode error = res_getDigest.Error();
            std::cout << error.Message() << std::endl;
            //return 0;
        }
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
        //return 0;
    }
    
    return 0;
}