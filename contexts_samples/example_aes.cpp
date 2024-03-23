#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.h"

using namespace ara::crypto::cryp;


int main()
{
    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();
    
    CryptoPP_AES_SymmetricBlockCipherCtx myContext;
    
    myContext.SetKey(*myKey);
    
    std::string str = "mr ahmed mahmoud";
    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    
/*
    std::string plaintext = "ahmed mahmoud";    
    // Padding the plaintext to be a multiple of the block size
    size_t blockSize = CryptoPP::AES::BLOCKSIZE;
    size_t paddedSize = (plaintext.size() / blockSize + 1) * blockSize;
    std::string paddedPlaintext = plaintext;
    paddedPlaintext.resize(paddedSize, ' ');
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(paddedPlaintext.data()), paddedPlaintext.size());
*/

    auto _result = myContext.ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get encrypted data
        auto encryptedDataVector = _result.Value();

        // Convert digest to hexadecimal string
        std::stringstream ss;
        for (const auto& byte : encryptedDataVector) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }

        // Print the hexadecimal
        std::cout << "output: ";
        std::cout << ss.str() << std::endl;

        myContext.SetKey(*myKey,ara::crypto::CryptoTransform::kDecrypt);
        auto _result2 = myContext.ProcessBlock(encryptedDataVector);
        if(_result2.HasValue())
        {
            std::cout << "--- sucess ---\n";
            
            // get decrypted data
            auto decryptedDataVector = _result2.Value();

            // Convert digest to hexadecimal string
            std::stringstream sss;
            std::cout << "output: ";
            for (const auto& byte : decryptedDataVector) {
                sss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            // Print the hexadecimal digest
            std::cout << sss.str() << std::endl;
            
            std::string decryptedDataString(decryptedDataVector.begin(), decryptedDataVector.end());
            std::cout << decryptedDataString << std::endl;
        }
        else
        {
            std::cout << "--- error ---\n";
            ara::core::ErrorCode error = _result.Error();
            std::cout << error.Message() << std::endl;
            return 0;
        }
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    
}