CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic
SRC = tbibe_poc.cpp tbibe/keccak.cpp tbibe/mod_arith.cpp tbibe/thesis_sampler.cpp tbibe/toy_hash.cpp tbibe/threshold_batch_ibe.cpp tbibe/tests.cpp tbibe/bench.cpp

.PHONY: all test asan clean

all: tbibe_poc

tbibe_poc: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@

test: tbibe_poc
	./tbibe_poc

bench: tbibe_poc
	./tbibe_poc bench

asan:
	$(CXX) -std=c++17 -O1 -g -fsanitize=address,undefined -Wall -Wextra -pedantic $(SRC) -o tbibe_poc_asan
	ASAN_OPTIONS=detect_leaks=0 ./tbibe_poc_asan

clean:
	rm -f tbibe_poc tbibe_poc_asan
