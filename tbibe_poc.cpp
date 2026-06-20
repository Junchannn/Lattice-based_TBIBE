#include "tbibe/bench.hpp"
#include "tbibe/tests.hpp"

#include <cstring>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc > 1 && std::strcmp(argv[1], "bench") == 0) {
        tbibe::runBenchmarks();
    } else {
        tbibe::runRandomizedTests();
    }
    return 0;
}
