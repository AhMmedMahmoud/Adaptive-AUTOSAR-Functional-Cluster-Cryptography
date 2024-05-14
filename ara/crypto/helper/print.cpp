#include "print.h"

namespace ara
{
    namespace crypto
    {
        namespace helper
        {
            void printHex(const std::string& data, std::string description) 
            {
                std::cout << description;
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << ss.str() << std::endl;
            }

            void printHex(const std::vector<unsigned char>& data, std::string description)
            {
                std::cout << description;
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << ss.str() << std::endl;
            }

            void printHex(const ara::core::Span<const std::uint8_t>& data, std::string description) 
            {
                std::cout << description;
                for (const auto& byte : data) {
                    printf("%02x", byte);
                }
                std::cout << std::endl;
            }

            void printVector(const std::vector<unsigned char>& vec, std::string description) 
            {
                std::cout << description;
                for (const auto& elem : vec) {
                    std::cout << elem; // Print the character
                }
                std::cout << "\n";
            }       
       }
    }
}