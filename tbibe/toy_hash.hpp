#pragma once

#include "config.hpp"
#include "keccak.hpp"
#include "thesis_sampler.hpp"

namespace tbibe {

class ToyHash {
public:
    static std::uint64_t u64(const std::string& input, std::uint64_t seed = 0);
    static Vector batchTarget(const std::vector<std::string>& identities);
    static Matrix trapdoorPublicC(ThesisSampler& sampler);
    static Matrix identityMatrixF(const std::string& identity);

private:
    static std::uint64_t mix(std::uint64_t x);
};

} // namespace tbibe
