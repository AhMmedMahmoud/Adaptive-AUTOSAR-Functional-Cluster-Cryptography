#ifndef CRYPTO_KEY_SLOT_INTERFACE_H
#define CRYPTO_KEY_SLOT_INTERFACE_H

#include <string>
#include "../private/keys/key_slot_prototype_props.h"

namespace ara
{
    namespace crypto
    {
        namespace manifest
        {
            struct CryptoKeySlotInterface
            {
                std::string specifier;
                std::string CryptoProviderName;
                std::string CryptoObjectPath;
                keys::KeySlotPrototypeProps pro;
            };
        }
    }
}

#endif