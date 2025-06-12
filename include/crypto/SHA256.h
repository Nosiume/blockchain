#pragma once

#include <gmpxx.h>
#include <stdint.h>
#include <vector>
#include <iostream>

extern uint32_t round_keys[64];
extern uint32_t input_vector[8];

class SHA256 {

private:
    uint32_t hash[8];

public:
    SHA256();
    ~SHA256();

    void append(const std::string& message);

    // Util
    std::string pad(const std::string& message) const;
    std::vector<std::string> get_blocks(const std::string& padded) const;
    std::array<uint32_t, 16> divide_block(const std::string& block) const;
    std::array<uint32_t, 64> expand_block(const std::array<uint32_t, 16>& words) const;

    inline uint32_t rotr(uint32_t x, size_t n) const;

    void reset();
    std::string hex_digest() const;
    mpz_class as_bigint() const;

};
