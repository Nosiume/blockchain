#pragma once

#include <gmpxx.h>

int legendre_symbol(const mpz_class& x, const mpz_class& modulus);
bool mpz_sqrtm(mpz_class& res, const mpz_class& x, const mpz_class& modulus);
