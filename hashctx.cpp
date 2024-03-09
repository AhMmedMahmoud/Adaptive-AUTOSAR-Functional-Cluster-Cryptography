#include<iostream>
#include "ara/crypto/public/cryp/cryptopp_hash_function_ctx.h"
#include "ara/crypto/private/common/mem_region.h"

using namespace ara::crypto::cryp;

int main()
{
    CryptoPP_HashFunctionCtx h;
    
    h.Start();

    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    h.Update(instr);
    
    ara::core::Result<ara::core::Vector<ara::core::Byte>> res = h.Finish();
    if(res.HasValue())
    {
        // Convert digest to hexadecimal string
        std::stringstream ss;
        for (const auto& byte : res.Value()) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        // Print the hexadecimal digest
        std::cout << ss.str() << std::endl;
    }
    

    return 0;
}