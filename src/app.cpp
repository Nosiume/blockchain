#include <iostream>

#include "crypto/EllipticCurve.h"
#include "crypto/SHA256.h"

int main() {
    EllipticCurve ec(
        0, 7,
        {mpz_class("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
         mpz_class("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
         false},
        mpz_class("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16));

    KeyPair pair = ec.generate_key_pair();
    std::cout << "Private Key : 0x" << std::hex << pair.private_key << std::endl;
    std::cout << "Public Key : 0x" << std::hex << pair.public_key << std::endl;

    Point q = ec.generate_signature("hello, world!", pair.private_key);
    std::cout << "Signature : (" << q.x << ", " << q.y << ")" << std::endl;
    std::cout << "Is signature valid : " << ( ec.verify_signature("hello, world!", q, pair.public_key) ? "yes" : "no") << std::endl; 
	return 0;
}
