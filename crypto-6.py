"""
Your goal in this project is to break RSA when the public modulus N is generated incorrectly. This should serve as yet
another reminder not to implement crypto primitives yourself.

Normally, the primes that comprise an RSA modulus are generated independently of one another. But suppose a developer
decides to generate the first prime p by choosing a random number R and scanning for a prime close by. The second prime
q is generated by scanning for some other random prime also close to R.

We show that the resulting RSA modulus N = p * q can be easily factored.

Suppose you are given a composite N and are told that N is a product of two relatively close primes p and q, namely p
and q satisfy: |p - q| < 2 * N^(1/4) (*).

Your goal is to factor N.

Let A be the arithmetic average of the two primes, that is A = (p + q) / 2. Since p and q are odd, we know that p + q
is even and therefore A is an integer.

To factor N, you first observe that under condition (*) the quantity sqrt(N) is very close to A. In particular, we show
that A - sqrt(N) < 1.

But since A is an integer, rounding sqrt(N) up to the closest integer reveals the value of A. In code,  = ceil(sqrt(N))
where "ceil" is the ceiling function.

Since A is the exact mid-point between p and q there is an integer x such that p = A - x and q = A + x.

But then N = p * q = (A - x)(A + x) = A^2 - x^2 and therefore x = sqrt(A^2 - N)

Now, given x and A you can find the factors p and q of N since p = A - x and q = A + x. You have now factored N!

Further reading: the method described above is a greatly simplified version of a much more general result on factoring
when the high order bits of the prime factor are known (https://dl.acm.org/citation.cfm?id=1754517).

In the following challenges, you will factor the given moduli using the method outlined above. To solve this assignment
it is best to use an environment that supports multi-precision arithmetic and square roots. In Python you could use the
gmpy2 module. In C you can use GMP.

-------------------- Challenge #1 --------------------

The following modulus N is a products of two primes p and q where |p - q| < 2 * N^(1/4) (see crypto-6.json).

For completeness, let us see why A - sqrt(N) < 1. This follows from the following simple calculation.

First observe that A^2 - N = ((p + q) / 2)^2 - N = ((p^2 + 2N + q^4) / 4) - N = (p^2 - 2N + q^2) / 4 = ((p - q)^2) / 4.

Now, since for all x, y:  (x - y)(x + y) = x^2 - y^2 we obtain A - sqrt(N) = (A - sqrt(N))(A + sqrt(N))(A + sqrt(N)) =
(A^2 - N)/(A + sqrt(N)) = (((p - q)^2) / 4) / (A + sqrt(N))

Since sqrt(N) <= A it follows that A - sqrt(N) <= (((p - q)^2) / 4) / (2 * sqrt(N)) = ((p - q)^2) / (8 * sqrt(N)).

By assumption (*) we know that (p - q)^2 < 4 * sqrt(N) and therefore A - sqrt(N) <= (4 * sqrt(N)) / (8 * sqrt(N)) = 1/2
as required.

-------------------- Challenge #2 --------------------

The following modulus N (see crypto-6.json) is a products of two primes p and q where |p - q| < 2^11 * N^(1/4). Find the
smaller of the two factors and enter it as a decimal integer.

Hint: in this case A - sqrt(N) < 2^20 so try scanning for A from sqrt(N) upwards, until you succeed in factoring N.

-------------------- Challenge #3 --------------------

The following modulus N (see crypto-6.json) is a product of two primes p and q where |3p - 2q| < N1 / 4. Find the
smaller of the two factors and enter it as a decimal integer.

Hint: first show that sqrt(6N) is close to (3p + 2q) / 2 and then adapt the method in challenge #1 to factor N.

-------------------- Challenge #4 --------------------

The challenge ciphertext provided (see crypto-6.json) is the result of encrypting a short secret ASCII plaintext using
the RSA modulus given in the first factorization challenge.

The encryption exponent used is e = 65537. The ASCII plaintext was encoded using PKCS v1.5 before the RSA function was
applied, as described in PKCS.

Use the factorization you obtained for this RSA modulus to decrypt this challenge ciphertext. Recall that the
factorization of N enables you to compute phi(N) from which you can obtain the RSA decryption exponent.

After you use the decryption exponent to decrypt the challenge ciphertext you will obtain a PKCS1 encoded plaintext. To
undo the encoding it is best to write the decrypted value in hex. You will observe that the number starts with a '0x02'
followed by many random non-zero digits. Look for the '0x00' separator and the digits following this separator are the
ASCII letters of the plaintext.

(note: the separator used here is '0x00'.)
"""

import json
import gmpy2
from gmpy2 import mpz


def challenge_1(n):
    print '\n-------------Challenge 1-------------\n'
    print 'N =', n
    print

    a = gmpy2.isqrt(n) + 1
    print 'A =', a

    x = gmpy2.isqrt((a ** 2) - n)
    print 'x =', x

    p1 = a - x
    p2 = a + x
    print 'p1 =', p1
    print 'p2 =', p2

    return p1, p2


def challenge_2(n):
    print '\n-------------Challenge 2-------------\n'
    print 'N =', n
    print

    a = gmpy2.isqrt(n) + 1
    print 'A =', a

    while not gmpy2.is_square((a ** 2) - n):
        a += 1

    x = gmpy2.isqrt((a ** 2) - n)
    print 'x =', x

    p1 = a - x
    p2 = a + x
    print 'p1 =', p1
    print 'p2 =', p2


def challenge_3(n):
    print '\n-------------Challenge 3-------------\n'
    print 'N =', n
    print

    a = gmpy2.isqrt(24 * n) + 1
    print 'A =', a

    x = gmpy2.isqrt((a ** 2) - (24 * n))
    print 'x =', x

    p1 = (a - x) / 6
    p2 = (a + x) / 4
    print 'p1 =', p1
    print 'p2 =', p2


def challenge_4(n, p1, p2, e, ciphertext):
    print '\n-------------Challenge 4-------------\n'
    phi = (p1 - 1) * (p2 - 1)
    print 'phi =', phi

    d = gmpy2.invert(e, phi)
    print 'd =', d

    plaintext = (hex(gmpy2.powmod(ciphertext, d, n)).split('00')[1]).decode('hex')
    print 'plaintext =', plaintext


# noinspection PyArgumentList
def main():
    with open('crypto-6.json', 'r') as fp:
        inputs = json.loads(fp.read())

    n1 = mpz(inputs['N1'])
    n2 = mpz(inputs['N2'])
    n3 = mpz(inputs['N3'])
    ciphertext = mpz(inputs['ciphertext'])

    p1, p2 = challenge_1(n1)
    challenge_2(n2)
    challenge_3(n3)
    challenge_4(n1, p1, p2, 65537, ciphertext)


if __name__ == "__main__":
    main()