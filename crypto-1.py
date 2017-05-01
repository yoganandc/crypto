"""
Let us see what goes wrong when a stream cipher key is used more than once. Below are eleven hex-encoded ciphertexts
that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key. Your
goal is to decrypt the last ciphertext, and submit the secret message within it as solution.

Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].
"""

import os
import json
import itertools

PLAIN_TEXTS = "attack at dawn", "attack at dusk"

CIPHER_TEXTS = []
permutations = []

TARGET = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e" \
         "77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"


def most_likely_space(i):
    max_probability = 0
    index = None

    for j in range(0, len(CIPHER_TEXTS)):
        start = (len(CIPHER_TEXTS) - 1) * j
        count = 0.0

        for k in range(0, len(CIPHER_TEXTS) - 1):
            if len(permutations[start + k]) > i and permutations[start + k][i].isalpha():
                count += 1.0

        probability = count / (len(CIPHER_TEXTS) - 2)

        if probability > max_probability:
            max_probability = probability
            index = j

    return index


def str_ascii(string):
    result = ""
    for idx in range(0, len(string), 2):
        val = chr(int(string[idx] + string[idx + 1], 16))
        result += val if val.isalpha() else '#'
    return result


def str_xor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def random(size=16):
    return os.urandom(size)


def encrypt(key, msg):
    c = str_xor(key, msg)
    return c


def main():
    key = random(1024)
    examples = [encrypt(key, msg).encode('hex') for msg in PLAIN_TEXTS]
    print "-------------EXAMPLES-------------"
    for x, y in zip(PLAIN_TEXTS, examples):
        print "PLAIN: %s, CIPHER: %s" % (x, y)
    print

    global CIPHER_TEXTS
    with open("crypto-1.json", "r") as fp:
        CIPHER_TEXTS = json.loads(fp.read())
    CIPHER_TEXTS = [x.decode('hex') for x in CIPHER_TEXTS]

    print "-------------CIPHERTEXTS-------------"
    for idx, val in enumerate(CIPHER_TEXTS):
        print "%02d: %s" % (idx + 1, val.encode('hex'))
    print

    print "-------------XOR-ING-------------"
    for idx, val in zip(itertools.permutations(range(0, len(CIPHER_TEXTS)), 2),
                        itertools.permutations(CIPHER_TEXTS, 2)):
        val_str = str_ascii(str_xor(val[0], val[1]).encode('hex'))
        permutations.append(val_str)
        print "(%d, %d) || %s" % (idx[0], idx[1], val_str)

    longest_length = 0
    for val in permutations:
        if len(val) > longest_length:
            longest_length = len(val)

    indices = []
    for i in range(0, longest_length):
        indices.append(most_likely_space(i))

    key = ""
    for idx, val in enumerate(indices):
        if val is None:
            key += '\0'
        else:
            key += chr(ord(CIPHER_TEXTS[val][idx]) ^ 0x20)

    print
    print "-------------TARGET MESSAGE DECODED-------------"
    print str_xor(key, TARGET.decode('hex'))

    print
    print "-------------CIPHERTEXTS DECODED-------------"
    for x in CIPHER_TEXTS:
        print str_xor(key, x)

if __name__ == "__main__":
    main()
