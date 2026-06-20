#include "mod_arith.hpp"

#include <stdexcept>

namespace tbibe {

Scalar ModArith::normalize(Scalar x) {
    x %= Q;
    return x < 0 ? x + Q : x;
}

Scalar ModArith::add(Scalar a, Scalar b) { return normalize(a + b); }
Scalar ModArith::sub(Scalar a, Scalar b) { return normalize(a - b); }
Scalar ModArith::mul(Scalar a, Scalar b) { return normalize(a) * normalize(b) % Q; }

Scalar ModArith::power(Scalar a, Scalar e) {
    Scalar r = 1;
    for (; e; e >>= 1, a = mul(a, a)) {
        if (e & 1) r = mul(r, a);
    }
    return r;
}

Scalar ModArith::inverse(Scalar a) {
    a = normalize(a);
    if (!a) throw std::runtime_error("zero inverse");
    return power(a, Q - 2);
}

Scalar ModArith::dot(const Vector& a, const Vector& b) {
    Scalar r = 0;
    for (std::size_t i = 0; i < a.size(); ++i) r = add(r, mul(a[i], b[i]));
    return r;
}

Vector ModArith::scale(Scalar a, const Vector& x) {
    Vector r(x.size());
    for (std::size_t i = 0; i < x.size(); ++i) r[i] = mul(a, x[i]);
    return r;
}

Vector ModArith::addVectors(Vector a, const Vector& b) {
    for (std::size_t i = 0; i < a.size(); ++i) a[i] = add(a[i], b[i]);
    return a;
}

Vector ModArith::matVec(const Matrix& A, const Vector& x) {
    Vector r(A.size());
    for (std::size_t i = 0; i < A.size(); ++i) r[i] = dot(A[i], x);
    return r;
}

Matrix ModArith::matMul(const Matrix& A, const Matrix& B) {
    Matrix out(A.size(), Vector(B[0].size()));
    for (std::size_t i = 0; i < A.size(); ++i) {
        for (std::size_t k = 0; k < B.size(); ++k) {
            for (std::size_t j = 0; j < B[k].size(); ++j) {
                out[i][j] = add(out[i][j], mul(A[i][k], B[k][j]));
            }
        }
    }
    return out;
}

Vector ModArith::transposeMatVec(const Matrix& A, const Vector& x) {
    Vector r(A[0].size());
    for (std::size_t i = 0; i < A.size(); ++i) {
        for (std::size_t j = 0; j < A[i].size(); ++j) {
            r[j] = add(r[j], mul(A[i][j], x[i]));
        }
    }
    return r;
}

} // namespace tbibe
