#pragma once

#include "config.hpp"

namespace tbibe {

class ModArith {
public:
    static Scalar normalize(Scalar x);
    static Scalar add(Scalar a, Scalar b);
    static Scalar sub(Scalar a, Scalar b);
    static Scalar mul(Scalar a, Scalar b);
    static Scalar inverse(Scalar a);

    static Scalar dot(const Vector& a, const Vector& b);
    static Vector scale(Scalar a, const Vector& x);
    static Vector addVectors(Vector a, const Vector& b);
    static Vector matVec(const Matrix& A, const Vector& x);
    static Matrix matMul(const Matrix& A, const Matrix& B);
    static Vector transposeMatVec(const Matrix& A, const Vector& x);

private:
    static Scalar power(Scalar a, Scalar e);
};

} // namespace tbibe
