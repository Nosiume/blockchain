#include "crypto/utils.h"

int legendre_symbol(const mpz_class &x, const mpz_class &modulus) {
	mpz_class res;
	mpz_class power = ((modulus - 1) / 2);
	mpz_powm(res.get_mpz_t(), x.get_mpz_t(), power.get_mpz_t(), modulus.get_mpz_t());
	if(res == modulus - 1)
		return -1;
	return res.get_si();
}

// This is just a tonelli-shanks algorith pretty much
bool mpz_sqrtm(mpz_class &res, const mpz_class &x, const mpz_class &modulus) {
	if(legendre_symbol(x, modulus) != 1)
		return false; // No solutions, so we cancel

	mpz_class q = modulus - 1;
	mpz_class s = 0;

	while ( q % 2 == 0 ) {
		q /= 2;
		s++;
	}

	if( s == 1 ) {
		mpz_powm(res.get_mpz_t(), x.get_mpz_t(),
				((mpz_class) ((modulus+1)/4)).get_mpz_t(), modulus.get_mpz_t());
		return true;
	}

	mpz_class z = 2;
	while (legendre_symbol(z, modulus) != -1)
		z++;

	mpz_class c;
	mpz_powm(c.get_mpz_t(), z.get_mpz_t(), q.get_mpz_t(), modulus.get_mpz_t());

	mpz_class t;
	mpz_powm(t.get_mpz_t(), x.get_mpz_t(), q.get_mpz_t(), modulus.get_mpz_t());

	mpz_class r_temp;
	mpz_powm(r_temp.get_mpz_t(), x.get_mpz_t(), 
			((mpz_class) ((q + 1) / 2)).get_mpz_t(), modulus.get_mpz_t());

	mpz_class m = s;
	while (t != 1) {
		mpz_class i = 1;
		mpz_class temp = ( t * t ) % modulus;
		while(temp != 1) {
			temp = (temp * temp) % modulus;
			i++;
			if (i == m) return false;
		}

		mpz_class b;
		mpz_powm(b.get_mpz_t(), c.get_mpz_t(), 
				mpz_class(1 << (m.get_ui() - i.get_ui() - 1)).get_mpz_t(), modulus.get_mpz_t());

		r_temp = (r_temp * b) % modulus;
		c = (b * b) % modulus;
		t = (t * c) % modulus;
		m = i;
	}
	
	res = r_temp;
	return true;
}
