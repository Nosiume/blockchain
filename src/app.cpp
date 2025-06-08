#include <iostream>
#include "crypto/EllipticCurve.h"

int main() {
	EllipticCurve ec(497, 1768, {0, 0}, 9739);
	
	Point p = {5323, 5438};
	Point q = ec.ec_scalar_mul(p, 1337);
	std::cout << "q = [7863]p = (" << q.x << ", " << q.y << ")" << std::endl;
	return 0;
}
