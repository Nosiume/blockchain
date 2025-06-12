#pragma once

#include <gmpxx.h>
#include <stdint.h>
#include <random>

// This is a basic struct for a point with arbitrary int precision
struct Point {
	mpz_class x;
	mpz_class y;
    bool is_infinity;
};

struct Signature {
    mpz_class r;
    mpz_class s;
};


// This is a basic KeyPair struct representing the public and private key pair on a given Elliptic Curve
struct KeyPair {
    mpz_class private_key;
    Point public_key;
};

/**
 * This class represents an elliptic curve of the form y^2 = x^3 + ax + b [p]
 * It uses a generator point given in the constructor to generate private/public key pairs
 * and verify or generate signatures for a given message.
 *
 * /!\ Note that this is a class made as a learning project and has a lot of unsafe features,
 * for example the fact that multiplication can be analyzed through side channel analysis and beaten
 * pretty easily. Please use a regulated standardized implementation and not mine :)
 */
class EllipticCurve {

private:
	uint32_t m_a, m_b;
	mpz_class m_modulus;
	mpz_class m_order;
	Point m_gen;

public:
	
	// Just sets the values for this elliptic curve, not much of interest here
	EllipticCurve(uint32_t a, uint32_t b, const Point& m_gen, const mpz_class& modulus);
	~EllipticCurve();

    /**
     * Generate a signature from the SHA256 hash of message using the private_key given in parameter
     * We can then use the verify function to verify the signature over the elliptic curve
     */
    Signature generate_signature(const std::string& message, const mpz_class& private_key) const;

    /**
     * Verifies if the given signature has been signed by the private key paired with the given public key
     */
    bool verify_signature(const std::string& message, const Signature& signature, const Point& public_key) const;

	/**
	 * Finds a value of y given the x value of the point we wish to generate
	 * returns true if there is a root and the generation was successful, false otherwise
	 *
	 * We'll relay this function to using tonelli-shanks algorithm in order to find a root
	 * of the elliptic curve's formula and obtain the y value (if there is a root)
	 */
	bool generate_point_from_x(Point& res, const mpz_class& x) const ;

	/**
	 * Adds two points on the elliptic curve by projecting a line through both points and intersecting
	 * the main curve and performing a symmetry with the x-axis.
	 */
	Point ec_add(const Point& p, const Point& q) const;

	/**
	 * Scalar multiplication of a point on the elliptic curve, key operation for any use in ECC
	 */
	Point ec_scalar_mul(const Point& p, const mpz_class& n) const;

	/**
	 * Verifies if a point is on the elliptic curve
	 */
	bool contains(const Point& p) const;

    /**
     * Generates a public and private key pair randomly from the current elliptic curve
     */
    KeyPair generate_key_pair() const;

    //TODO:
	void calculate_order();

	mpz_class order();

};
