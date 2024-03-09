#ifndef MEM_REGION_H
#define MEM_REGION_H

#include <cstdint>
#include "../../../core/Span.h"

namespace ara
{
    namespace crypto
    {
        using ReadOnlyMemRegion = ara::core::Span<const std::uint8_t>;
        using ReadWriteMemRegion = ara::core::Span<std::uint8_t>;
    }
}


#endif