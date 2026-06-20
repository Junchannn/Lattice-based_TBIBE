#include "thesis_sampler.hpp"

#include "mod_arith.hpp"

#include <cmath>

namespace tbibe {

ThesisSampler::ThesisSampler(std::uint64_t seed) : rng_(seed) {}

Scalar ThesisSampler::uniformZq() {
    std::uniform_int_distribution<Scalar> dist(0, Q - 1);
    return dist(rng_);
}

Vector ThesisSampler::uniformVectorZq(int size) {
    Vector out(size);
    for (auto& x : out) x = uniformZq();
    return out;
}

Matrix ThesisSampler::uniformMatrixZq(int rows, int cols) {
    Matrix out(rows, Vector(cols));
    for (auto& row : out) {
        for (auto& x : row) x = uniformZq();
    }
    return out;
}

Scalar ThesisSampler::centeredDiscreteGaussian(double sigma, int bound) {
    if (bound == 0 || sigma == 0.0) return 0;
    std::normal_distribution<double> dist(0.0, sigma);
    Scalar x = static_cast<Scalar>(std::llround(dist(rng_)));
    if (x > bound) x = bound;
    if (x < -bound) x = -bound;
    return ModArith::normalize(x);
}

Scalar ThesisSampler::errorChi() {
    return centeredDiscreteGaussian(CiphertextChiSigma, CiphertextChiBound);
}

Scalar ThesisSampler::errorChiPrime() {
    return centeredDiscreteGaussian(CiphertextChiPrimeSigma, CiphertextChiPrimeBound);
}

Vector ThesisSampler::errorVectorChi(int size) {
    Vector out(size);
    for (auto& x : out) x = errorChi();
    return out;
}

Vector ThesisSampler::errorVectorChiPrime(int size) {
    Vector out(size);
    for (auto& x : out) x = errorChiPrime();
    return out;
}

Matrix ThesisSampler::trapdoorGaussianMatrix(int rows, int cols) {
    Matrix out(rows, Vector(cols));
    for (auto& row : out) {
        for (auto& x : row) x = centeredDiscreteGaussian(TrapdoorGaussianSigma, TrapdoorGaussianBound);
    }
    return out;
}

} // namespace tbibe
