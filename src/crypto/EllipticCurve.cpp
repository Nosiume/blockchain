#include "crypto/EllipticCurve.h"
#include "crypto/utils.h"
#include "crypto/SHA256.h"

#include <cassert>
#include <ctime>
#include <gmp.h>

//Sets all members
EllipticCurve::EllipticCurve(uint32_t a, uint32_t b, const Point& p, const mpz_class& modulus)
{
	m_a = a;
	m_b = b;
	m_modulus = modulus;
	//m_order = 9735; // Hardcoded calculation using sage for now
    m_order = mpz_class("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

	assert(contains(p) && "Generator point has to be on the elliptic curve");
    assert(ec_scalar_mul(p, m_order).is_infinity && "n*G with n being the order of the EC has to be equal to O");
	m_gen = p;
}

// Nothing to do for now
EllipticCurve::~EllipticCurve() {}

// ECDSA

Signature EllipticCurve::generate_signature(const std::string& message, const mpz_class& private_key) const {
    gmp_randclass rr(gmp_randinit_default);
    rr.seed(time(0));
   
    mpz_class k = 0;
    mpz_class r = 0;
    while(r == 0) {
        k = rr.get_z_range(m_order - 2) + 1;
        Point Q = ec_scalar_mul(m_gen, k);
        r = Q.x % m_order;
    }

    SHA256 hash;
    hash.append(message);
    mpz_class m = hash.as_bigint();
    mpz_class k_inverse;
    mpz_invert(k_inverse.get_mpz_t(), k.get_mpz_t(), m_order.get_mpz_t());

    mpz_class s = (k_inverse * (m + private_key*r)) % m_order;
    if(s == 0) return generate_signature(message, private_key); // We start again from the beginning if y = 0

    return {r, s};
}

bool EllipticCurve::verify_signature(const std::string& message, const Signature& signature, const Point& public_key) const {
    if(!contains(public_key)) return false;
    if(!ec_scalar_mul(public_key, m_order).is_infinity) return false;

    // Now we check if the signature is in the order of the EC
    if(0 >= signature.r || signature.r >= m_order) return false;
    if(0 >= signature.s || signature.s >= m_order) return false;
   
    SHA256 hash;
    hash.append(message);
    mpz_class e = hash.as_bigint();

    mpz_class s_inverse;
    mpz_invert(s_inverse.get_mpz_t(), signature.s.get_mpz_t(), m_order.get_mpz_t());

    mpz_class u1 = (e * s_inverse) % m_order;
    mpz_class u2 = (signature.r * s_inverse) % m_order;
    
    Point P = ec_add(ec_scalar_mul(m_gen, u1), ec_scalar_mul(public_key, u2));
    if(P.is_infinity) return false;

    return (P.x % m_order) == signature.r;
}

// Implementation of EC operations
bool EllipticCurve::contains(const Point& p) const {
    if(p.is_infinity) return true;

	mpz_class res;
	mpz_pow_ui(res.get_mpz_t(), p.x.get_mpz_t(), 3);
	res += m_a*p.x + m_b;
	res %= m_modulus;

	mpz_class y_squared;
	mpz_powm_ui(y_squared.get_mpz_t(), p.y.get_mpz_t(), 2, m_modulus.get_mpz_t());
	return res == y_squared;
}

bool EllipticCurve::generate_point_from_x(Point& point, const mpz_class& x) const {
	mpz_class res;
	mpz_pow_ui(res.get_mpz_t(), x.get_mpz_t(), 3);
	res += m_a*x + m_b;
	res %= m_modulus;

	// Now we need to find the square root mod m_modulus of res
	// Check crypto/utils.h for root algorithm
	mpz_class y;
	if(!mpz_sqrtm(y, res, m_modulus))
		return false;
	
	point = {x, y};
	return true;
}

Point EllipticCurve::ec_add(const Point& p, const Point& q) const {
	assert((contains(p))  && "p is not on the elliptic curve, addition is undefined");
	assert((contains(q)) && "q is not on the elliptic curve, addition is undefined");

	if (p.is_infinity) return q;  // P = O
	if (q.is_infinity) return p;  // Q = O
    if (p.x == q.x && (p.y + q.y) % m_modulus == 0) return {0, 0, true}; // vertical line

	mpz_class lambda;
	if ( p.x != q.x || p.y != q.y ) {
		// If p and q are different points
		mpz_class tmp;
		mpz_invert(tmp.get_mpz_t(), 
				((mpz_class) (q.x - p.x)).get_mpz_t(), m_modulus.get_mpz_t());
		lambda = ((q.y - p.y) * tmp) % m_modulus;	
	} else {
		// If p and q are the same point then we use the slope
		mpz_class tmp;
		mpz_invert(tmp.get_mpz_t(), 
				((mpz_class) (2*p.y)).get_mpz_t(), m_modulus.get_mpz_t());
		lambda = ((3 * p.x * p.x + m_a) * tmp) % m_modulus;
	}

	mpz_class x = (lambda * lambda - p.x - q.x) % m_modulus;
	mpz_class y = (lambda * (p.x - x) - p.y) % m_modulus;
	return {(x < 0 ? x + m_modulus : x), (y < 0 ? y + m_modulus : y)};
}

Point EllipticCurve::ec_scalar_mul(const Point& p, const mpz_class& n) const {
	Point q = p;
	Point r = {0, 0, true}; // r = O
	mpz_class i = n;

	while (i > 0) {
		if (i % 2 == 1) {
			r = ec_add(r, q);
		}
		q = ec_add(q, q);
		i /= 2;
	}
	return r;
}

KeyPair EllipticCurve::generate_key_pair() const {
    gmp_randclass rr(gmp_randinit_default); // Be aware that this could be unsafe
    rr.seed(time(0));
    mpz_class s = rr.get_z_range(m_order - 2) + 1; // s in the range of 1 to n - 1 with n being the modulus of the EC
    Point Q = ec_scalar_mul(m_gen, s);
    return {.private_key=s, .public_key=Q};
}

void EllipticCurve::calculate_order() {
	//TODO: Implement Schoof's algorithm to calculate order from
	//Generator point on the elliptic curve (that shit hard af)
}

mpz_class EllipticCurve::order() {
	if (m_order == 0) calculate_order();
	return m_order;
}
