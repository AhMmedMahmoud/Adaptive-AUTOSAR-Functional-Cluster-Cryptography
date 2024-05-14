#ifndef PRINT_H
#define PRINT_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include "../../core/Span.h"

namespace ara
{
    namespace crypto
    {
        namespace helper
        {
            void printHex(const std::string& data, std::string description = "");

            void printHex(const std::vector<unsigned char>& data, std::string description = "");

            void printHex(const ara::core::Span<const std::uint8_t>& data, std::string description = "");

            void printVector(const std::vector<unsigned char>& vec, std::string description = "");       
       }
    }
}

#endif