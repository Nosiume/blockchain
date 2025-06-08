#include "crypto/EllipticCurve.h"
#include "crypto/utils.h"
#include <cassert>

//Sets all members
EllipticCurve::EllipticCurve(uint32_t a, uint32_t b, const Point& p, const mpz_class& modulus)
{
	m_a = a;
	m_b = b;
	m_modulus = modulus;
	m_order = 0;

	assert(contains(p) && "Generator point has to be on the elliptic curve");
	m_gen = p;
}

// Nothing to do for now
EllipticCurve::~EllipticCurve() {}

// Implementation of EC operations
bool EllipticCurve::contains(const Point& p) const {
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
	assert((contains(p) || (p.x == -1 && p.y == -1))  && "p is not on the elliptic curve, addition is undefined");
	assert((contains(q) || (q.x == -1 && q.y == -1)) && "q is not on the elliptic curve, addition is undefined");

	if (p.x == -1 && p.y == -1) return q;  // P = O
	if (q.x == -1 && q.y == -1) return p;  // Q = O
	if (p.x == q.x && p.y == -q.y) return {-1, -1}; // we return O when vertical slope

	mpz_class lambda;
	if ( p.x != q.x || p.y != q.y ) {
		// If p and q are different points
		mpz_class tmp;
		mpz_invert(tmp.get_mpz_t(), 
				((mpz_class) (q.x - p.x)).get_mpz_t(), m_modulus.get_mpz_t());
		lambda = (q.y - p.y) * tmp;	
	} else {
		// If p and q are the same point then we use the slope
		mpz_class tmp;
		mpz_invert(tmp.get_mpz_t(), 
				((mpz_class) (2*p.y)).get_mpz_t(), m_modulus.get_mpz_t());
		lambda = (3 * p.x * p.x + m_a) * tmp;
	}

	mpz_class x = (lambda * lambda - p.x - q.x) % m_modulus;
	mpz_class y = (lambda * (p.x - x) - p.y) % m_modulus;
	return {(x < 0 ? x + m_modulus : x), (y < 0 ? y + m_modulus : y)};
}

Point EllipticCurve::ec_scalar_mul(const Point& p, const mpz_class& n) const {
	Point q = p;
	Point r = {-1, -1}; // r = O
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

void EllipticCurve::calculate_order() {
	//TODO: Implement Schoof's algorithm to calculate order from
	//Generator point on the elliptic curve
}

mpz_class EllipticCurve::order() {
	if (m_order == 0) calculate_order();
	return m_order;
}
