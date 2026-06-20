#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tbibe {

using Scalar = long long;
using Vector = std::vector<Scalar>;
using Matrix = std::vector<Vector>;

constexpr Scalar Q = 12289;
constexpr Scalar HalfQ = Q / 2;
constexpr int Parties = 5;
constexpr int Threshold = 3;
constexpr int Dim = 128;
constexpr int KeyCols = 256;
constexpr int GadgetWidth = 14;
constexpr int IdentityCols = Dim * GadgetWidth;
constexpr double TrapdoorGaussianSigma = 0.0;
constexpr int TrapdoorGaussianBound = 0;
constexpr double CiphertextChiSigma = 0.45;
constexpr int CiphertextChiBound = 1;
constexpr double CiphertextChiPrimeSigma = 0.45;
constexpr int CiphertextChiPrimeBound = 1;

struct PublicKey {
    Matrix Atilde;
    Matrix Btilde;
    Matrix C;
    Vector u;
};

struct Ciphertext {
    std::string identity;
    Scalar c1;
    Vector c2;
    Vector c3;
    Scalar e1;
    Vector e2;
    Vector e3;
};

struct PredecryptionShare {
    int party;
    std::vector<int> thresholdSet;
    std::vector<std::string> batchIdentities;
    Vector value;
};

struct BatchDecryptionKey {
    std::vector<int> thresholdSet;
    std::vector<std::string> batchIdentities;
    Vector value;
};

} // namespace tbibe
