CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic
SRC = btibe_poc.cpp btibe/keccak.cpp btibe/mod_arith.cpp btibe/thesis_sampler.cpp btibe/toy_hash.cpp btibe/threshold_batch_ibe.cpp btibe/tests.cpp btibe/bench.cpp

.PHONY: all test asan clean

all: btibe_poc

btibe_poc: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@

test: btibe_poc
	./btibe_poc

bench: btibe_poc
	./btibe_poc bench

asan:
	$(CXX) -std=c++17 -O1 -g -fsanitize=address,undefined -Wall -Wextra -pedantic $(SRC) -o btibe_poc_asan
	ASAN_OPTIONS=detect_leaks=0 ./btibe_poc_asan

clean:
	rm -f btibe_poc btibe_poc_asan
