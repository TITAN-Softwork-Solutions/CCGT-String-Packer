#pragma once
#include <cstdint>
#include <cstddef>

namespace ccgt::crypto {

void derive_nonce96(uint8_t nonce12[12], uint64_t seed, uint32_t rva);

} // namespace ccgt::crypto