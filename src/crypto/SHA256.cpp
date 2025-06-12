#include "crypto/SHA256.h"
#include <sstream>
#include <iomanip>
#include <array>

uint32_t round_keys[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t input_vector[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

SHA256::SHA256() {
    reset();
}

SHA256::~SHA256() {}

void SHA256::append(const std::string& message) {
    std::string padded = pad(message); 
    std::vector<std::string> blocks = get_blocks(padded);
    
    for(const std::string& block : blocks) {
        std::array<uint32_t, 16> block_words = divide_block(block);
        std::array<uint32_t, 64> words = expand_block(block_words);

        uint32_t a = hash[0];
        uint32_t b = hash[1];
        uint32_t c = hash[2];
        uint32_t d = hash[3];
        uint32_t e = hash[4];
        uint32_t f = hash[5];
        uint32_t g = hash[6];
        uint32_t h = hash[7];

        for(int i = 0 ; i < 64 ; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + round_keys[i] + words[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
}

std::string SHA256::pad(const std::string& message) const {
    std::string padded = message;
    uint64_t len_bits = static_cast<uint64_t>(message.length()) * 8;

    padded += static_cast<char>(0x80);
    size_t pad_len = (56 - (padded.size() % 64)) % 64;
    padded.append(pad_len, '\0');

    for (int i = 7; i >= 0; --i)
        padded += static_cast<char>((len_bits >> (i * 8)) & 0xFF);

    return padded;
}

std::array<uint32_t, 16> SHA256::divide_block(const std::string& block) const {
    std::array<uint32_t, 16> res;
	const uint8_t* ptr = reinterpret_cast<const uint8_t*>(block.c_str());

	for (int i = 0; i < 16; i++) {
		res[i] = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
		ptr += 4;
	}
	return res; 
}

std::vector<std::string> SHA256::get_blocks(const std::string& padded) const {
    if(padded.length() % 64 != 0)
		throw std::runtime_error("trying to get blocks from non 512 bits multiple");

	std::vector<std::string> blocks;
	for(int i = 0 ; i < padded.length(); i+= 64) {
		blocks.push_back(padded.substr(i, 64));
	}
	return blocks;	
}

std::array<uint32_t, 64> SHA256::expand_block(const std::array<uint32_t, 16>& words) const {
    std::array<uint32_t, 64> res;
    std::copy(words.begin(), words.end(), res.begin());
    for(size_t i = 16 ; i < 64 ; i++) {
        uint32_t s0 = rotr(res[i-15], 7) ^ rotr(res[i-15], 18) ^ res[i-15] >> 3;
        uint32_t s1 = rotr(res[i-2], 17) ^ rotr(res[i-2], 19) ^ res[i-2] >> 10;
        res[i] = res[i-16] + s0 + res[i-7] + s1;
    }
    return res;
}

inline uint32_t SHA256::rotr(uint32_t x, size_t n) const {
    return (x >> n) | (x << (32 - n));
}

void SHA256::reset() {
    for(int i = 0 ; i < 8 ; i++) 
        hash[i] = input_vector[i];
}

std::string SHA256::hex_digest() const {
    std::stringstream ss;
    ss << std::hex; 
    for (int i = 0 ; i < 8 ; i++)
        ss << std::setw(8) << std::setfill('0') << hash[i];
    return ss.str();
}

mpz_class SHA256::as_bigint() const {
    mpz_class res = hash[0];
    for(int i = 1 ; i < 8 ; i++) {
        res <<= 32;
        res += hash[i];
    }
    return res;
}
