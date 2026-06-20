#pragma once

#include "config.hpp"

#include <random>

namespace tbibe {

class ThesisSampler {
public:
    explicit ThesisSampler(std::uint64_t seed);

    Scalar uniformZq();
    Vector uniformVectorZq(int size);
    Matrix uniformMatrixZq(int rows, int cols);

    Scalar errorChi();
    Scalar errorChiPrime();
    Vector errorVectorChi(int size);
    Vector errorVectorChiPrime(int size);
    Matrix trapdoorGaussianMatrix(int rows, int cols);

    std::mt19937_64& engine() { return rng_; }

private:
    std::mt19937_64 rng_;

    Scalar centeredDiscreteGaussian(double sigma, int bound);
};

} // namespace tbibe
