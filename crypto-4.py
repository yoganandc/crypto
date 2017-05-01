"""
In this project you will experiment with a padding oracle attack against a toy web site hosted at
crypto-class.appspot.com . Padding oracle vulnerabilities affect a wide variety of products, including secure tokens .

This project will show how they can be exploited. We discussed CBC padding oracle attacks in week 3 (segment number 5),
but if you want to read more about them, please see Vaudenay's paper:
(https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf).

Now to business. Suppose an attacker wishes to steal secret information from our target web site
crypto-class.appspot.com . The attacker suspects that the web site embeds encrypted customer data in URL parameters
such as this:

http://crypto-class.appspot.com/po?er
  =f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb5
  15dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4

That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice.
The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded
AES CBC encryption with a random IV of some secret data about Alice's session.

After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. In
particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden
request). When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not
found).

Armed with this information your goal is to decrypt the ciphertext listed above. To do so you can send arbitrary HTTP
requests to the web site of the form:

http://crypto-class.appspot.com/po?er="your ciphertext here"

and observe the resulting error code. The padding oracle will let you decrypt the given ciphertext one byte at a time.
To decrypt a single byte you will need to send up to 256 HTTP requests to the site. Keep in mind that the first
ciphertext block is the random IV. The decrypted message is ASCII encoded.

This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC
as in EAX or GCM, or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it
treats MAC errors.
"""

import urllib2
import sys

BLOCK_SIZE = 16
TARGET = 'http://crypto-class.appspot.com/po?er='
TARGET_CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0' \
                    'bdf302936266926ff37dbf7035d5eeb4'.decode('hex')


def query(blocks):
    blocks = ["".join(block) for block in blocks]
    q = "".join([block.encode('hex') for block in blocks])

    target = TARGET + urllib2.quote(q)  # Create query URL
    req = urllib2.Request(target)  # Send HTTP request to server
    try:
        f = urllib2.urlopen(req)  # Wait for response
    except urllib2.HTTPError as e:
        if e.code == 404:
            return True  # good padding
        return False  # bad padding


def decrypt_block(blocks, index, decrypted_pad=None):
    # save bytes decrypted so far in this array
    if decrypted_pad is not None:
        decrypted_bytes = [decrypted_pad] * decrypted_pad
    else:
        decrypted_bytes = []

    # we need to modify the block at index - 1
    block = blocks[index - 1]

    for pad in range(decrypted_pad + 1 if decrypted_pad is not None else 1, BLOCK_SIZE + 1):
        # save block bytes before modifying
        temp_outer = block[BLOCK_SIZE - (pad - 1):]

        # compute previous block values for already guessed bytes
        for i in range(1, pad):
            block[-i] = chr(ord(block[-i]) ^ decrypted_bytes[i - 1] ^ pad)

        decrypted_byte = None

        # first guess in range A-Za-z
        for guess in range(ord('A'), ord('Z') + 1) + range(ord('a'), ord('z') + 1):
            sys.stdout.write('.')
            sys.stdout.flush()

            # save previous block byte before modifying
            temp = block[-pad]
            block[-pad] = chr(ord(block[-pad]) ^ guess ^ pad)

            if query(blocks[index - 1:index + 1]):
                decrypted_byte = guess

                # revert change made
                block[-pad] = temp
                break

            # revert change made
            block[-pad] = temp

        # Make guesses for remaining chars if not in range A-Za-z
        if decrypted_byte is None:
            for guess in range(0, ord('A')) + range(ord('Z') + 1, ord('a')) + range(ord('z') + 1, 0x100):
                sys.stdout.write('.')
                sys.stdout.flush()

                # save previous block byte before modifying
                temp = block[-pad]
                block[-pad] = chr(ord(block[-pad]) ^ guess ^ pad)

                if query(blocks[index - 1:index + 1]):
                    decrypted_byte = guess

                    # revert change made
                    block[-pad] = temp
                    break

                # revert change made
                block[-pad] = temp

        assert decrypted_byte is not None
        decrypted_bytes.append(decrypted_byte)

        # revert changes made
        block[BLOCK_SIZE - (pad - 1):] = temp_outer
        sys.stdout.write(chr(decrypted_byte) + '\n')
        sys.stdout.flush()

    decrypted_bytes = [chr(x) for x in decrypted_bytes]
    decrypted_bytes.reverse()
    return "".join(decrypted_bytes)


def decrypt_pad(blocks):
    block = blocks[-2]
    pad = None

    # server will return 404 if guess is 0x01
    # because xor will have no effect.
    # Therefore, start from 2.
    for guess in range(2, 0x10):
        temp = block[-1]
        block[-1] = chr(ord(block[-1]) ^ guess ^ 0x01)

        if query(blocks[-2:]):
            pad = guess
            block[-1] = temp
            break

        block[-1] = temp

    return pad if pad is not None else 1


def main():
    # Block-ify ciphertext
    blocks = [list(TARGET_CIPHERTEXT[i:i+16]) for i in range(0, len(TARGET_CIPHERTEXT), 16)]

    print "\n-------------CIPHERTEXT BLOCKS-------------"
    print ["".join(block).encode('hex') for block in blocks]

    print "\n-------------DECRYPTING-------------"
    m0 = decrypt_block(blocks, 1)
    m1 = decrypt_block(blocks, 2)
    pad = decrypt_pad(blocks)
    m2 = decrypt_block(blocks, 3, pad)

    print "\n-------------DECRYPTED MESSAGE-------------"
    print "m0 is: " + m0
    print "m1 is: " + m1
    print "m2 is: " + m2[:-pad]


if __name__ == "__main__":
    main()
