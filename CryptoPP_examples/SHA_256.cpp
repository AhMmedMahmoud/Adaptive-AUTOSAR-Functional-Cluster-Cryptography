#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <span>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>


using ReadOnlyMemRegion = std::span<const std::uint8_t>;


int main() 
{
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock digest;

    hash.Restart();

    std::string str = "ahmed mahmoud";

    CryptoPP::SecByteBlock instr1(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    hash.Update(instr1.data(), instr1.size());

/*
    ReadOnlyMemRegion instr2(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    hash.Update(instr2.data(), instr2.size());
*/
    
    digest.resize(hash.DigestSize());
    hash.Final(digest);


    /***************************************************
    *                  print digest                    *
    ***************************************************/ 
    // Convert digest to hexadecimal string
    std::stringstream ss;
    for (const auto& byte : digest) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    // Print the hexadecimal digest
    std::cout << "Output: ";
    std::cout << ss.str() << std::endl;

    return 0;
}