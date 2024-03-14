#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.h"

using namespace ara::crypto::cryp;
int main()
{
    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();
    


    CryptoPP_AES_SymmetricBlockCipherCtx myContext;
    
    std::cout << "hhhhhhhhhh\n";
    myContext.SetKey(*myKey);
    std::cout << "ssssssssss\n";
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    
    ara::core::Result<ara::core::Vector<ara::core::Byte>> res_finish = myContext.ProcessBlock(instr);
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
        // Convert digest to hexadecimal string
        std::stringstream ss;
        for (const auto& byte : res_finish.Value()) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        // Print the hexadecimal digest
        std::cout << ss.str() << std::endl;
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
        error.Message();
    }
    
}