#ifndef SHARED_SLOTS_INTEFACES_H
#define SHARED_SLOTS_INTEFACES_H

#include "CryptoKeySlotInterface.h"

namespace ara
{
    namespace crypto
    {
        namespace manifest
        {
            extern std::vector<CryptoKeySlotInterface> KeySlotsMetaData;
        }
    }
}

#endif
