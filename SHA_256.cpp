// header files for cryptopp library
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"

// header files for standard C++ library
#include <iostream>

// namespaces
using namespace CryptoPP;

/*
In Sha256
    hash value is called digest
    digest size = 32 byte
*/

int main() 
{
    
    /**************************************************
    *                     plaintext                   *
    **************************************************/
    std::string message = "Hello, World!";
    

    /**************************************************
    *                     hashing                     *
    **************************************************/
    SecByteBlock digest(SHA256::DIGESTSIZE);
    SHA256 hash;
    hash.CalculateDigest(digest, (byte*)message.c_str(), message.length());


    /***************************************************
    *                  print digest                    *
    ***************************************************/
    // Create a HexEncoder object to output to console
    HexEncoder encoder(new FileSink(std::cout)); 
    
    // Print the digest in hexadecimal format
    std::cout << "digest: ";
    encoder.Put(digest, digest.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    return 0;
}