"""
Your goal this week is to write a program to compute discrete log modulo a prime p. Let g be some element in Zp* and
suppose you are given h in Zp* such that h = gx where 1 <= x <= 2^40. Your goal is to find x. More precisely, the input
to your program is p, g, h and the output is x.

The trivial algorithm for this problem is to try all 2^40 possible values of x until the correct one is found, that is
until we find an x satisfying h = g^x in Zp. This requires 2^40 multiplications. In this project you will implement an
algorithm that runs in time roughly sqrt(2^40) = 2^20 using a meet in the middle attack.

Let B = 2^20. Since x is less than B^2, we can write the unknown x base B as x = x0 * B + x1, where x0, x1 are in the
range [0, B-1]. Then: h = g^x = g^(x0 * B + x1) = (g^B)^x0 * (g^x1) in Zp.

By moving the term g^x1 to the other side we obtain: h / g^x1 = (g^B)^x0 in Zp.

The variables in this equation are x0, x1 and everything else is known: you are given g, h and B = 2^20. Since the
variables x0 and x1 are now on different sides of the equation we can find a solution using meet in the middle:

1. First build a hash table of all possible values of the left hand side h / g^x1 for x1 = 0, 1, ..., 2^20.
2. Then for each value x0 = 0, 1, 2, ..., 2^20 check if the right hand side (g^B)^x0 is in this hash table. If so, then
   you have found a solution (x0, x1) from which you can compute the required x as x = x0 * B + x1.

The overall work is about 2^20 multiplications to build the table and another 2^20 lookups in this table.

Now that we have an algorithm, here is the problem to solve (see crypto-5.json). Each of these three numbers is about
153 digits. Find x such that h = g^x in Zp.

To solve this assignment it is best to use an environment that supports multi-precision and modular arithmetic. In
Python you could use the gmpy2 or numbthy modules. Both can be used for modular inversion and exponentiation. In C you
can use GMP. In Java use a BigInteger class which can perform mod, modPow and modInverse operations.
"""

import json
import gmpy2
from gmpy2 import mpz


# noinspection PyArgumentList
def main():
    with open('crypto-5.json', 'r') as fp:
        inputs = json.loads(fp.read())

    p = mpz(inputs['p'])
    g = mpz(inputs['g'])
    h = mpz(inputs['h'])
    b = 2 ** 20

    print
    print 'p = %d' % p
    print 'g = %d' % g
    print 'h = %d\n' % h

    table = {}
    x0 = None
    x1 = None

    print 'Building hash table...'
    g_inverse = gmpy2.invert(g, p)
    for i in xrange(1, b - 1):
        table[gmpy2.f_mod(h * gmpy2.powmod(g_inverse, i, p), p)] = i
    print 'Build complete.\n'

    print 'Searching hash table...'
    g_raised = gmpy2.powmod(g, b, p)
    for j in xrange(1, b - 1):
        x1 = table.get(gmpy2.powmod(g_raised, j, p))
        if x1 is not None:
            x0 = j
            break
    print 'Search complete.\n'

    print 'x0 =', x0
    print 'x1 =', x1, '\n'

    print 'x =', gmpy2.f_mod((x0 * b) + x1, p)

if __name__ == "__main__":
    main()
