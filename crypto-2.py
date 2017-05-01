"""
In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES
in counter mode (CTR). In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed in the lecture (14:04). While we ask that you implement
both encryption and decryption, we will only test the decryption function. In the following questions you are given an
AES key and a ciphertext (both are hex encoded ) and your goal is to recover the plaintext.

For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any
other. While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC
and CTR modes yourself.
"""

import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def load_cipher_texts():
    with open('crypto-2.json', 'r') as fp:
        crypto_json = json.loads(fp.read())

    cipher_texts = []
    for el in crypto_json:
        key = el['key'].decode('hex')
        msg = el['cipher_text']
        iv = msg[:32].decode('hex')
        cipher_text = msg[32:].decode('hex')

        cipher_texts.append((key, iv, cipher_text))

    return cipher_texts


def print_cipher_texts(cipher_texts):
    for index, el in enumerate(cipher_texts):
        print "%d: key: %s, iv: %s, cipher_text: %s" \
              % (index, el[0].encode('hex'), el[1].encode('hex'), el[2].encode('hex'))


def blockify(msg):
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]

    last_block = blocks.pop()
    length = len(last_block)

    if length == 16:
        blocks.append(last_block)
        blocks.append('\x0f' * 16)
    else:
        byte_val = 16 - length
        last_block += (chr(byte_val) * byte_val)
        blocks.append(last_block)

    return blocks


def aes_cbc_encrypt_helper(key, iv, block):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_input = "".join([chr(ord(x) ^ ord(y)) for x, y in zip(iv, block)])
    return cipher.encrypt(cipher_input)


def aes_cbc_encrypt(key, msg):
    output_blocks = []
    iv = get_random_bytes(16)
    blocks = blockify(msg)

    output_blocks.append(aes_cbc_encrypt_helper(key, iv, blocks.pop(0)))

    for block in blocks:
        output_blocks.append(aes_cbc_encrypt_helper(key, output_blocks[-1], block))

    return iv, "".join(output_blocks)


def aes_cbc_decrypt_helper(key, iv, block):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_output = cipher.decrypt(block)
    return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(iv, cipher_output)])


def aes_cbc_decrypt(key, iv, msg):
    output_blocks = []
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]

    output_blocks.append(aes_cbc_decrypt_helper(key, iv, blocks[0]))

    for idx, block in enumerate(blocks[1:]):
        output_blocks.append(aes_cbc_decrypt_helper(key, blocks[idx], block))

    ret = "".join(output_blocks)
    return ret[:(-1 * int(ret[-1].encode('hex'), 16))]


def aes_ctr_encrypt(key, msg):
    output_blocks = []
    nonce = int((get_random_bytes(8) + ('\x00' * 8)).encode('hex'), 16)
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    cipher = AES.new(key, AES.MODE_ECB)

    for ctr, block in enumerate(blocks):
        iv = format(nonce + ctr, 'x').decode('hex')
        cipher_output = cipher.encrypt(iv)
        output_blocks.append("".join([chr(ord(x) ^ ord(y)) for x, y in zip(block, cipher_output)]))

    return format(nonce, 'x').decode('hex'), "".join(output_blocks)


def aes_ctr_decrypt(key, nonce, msg):
    output_blocks = []
    nonce = int(nonce.encode('hex'), 16)
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    cipher = AES.new(key, AES.MODE_ECB)

    for ctr, block in enumerate(blocks):
        iv = format(nonce + ctr, 'x').decode('hex')
        cipher_output = cipher.encrypt(iv)
        output_blocks.append("".join([chr(ord(x) ^ ord(y)) for x, y in zip(block, cipher_output)]))

    return "".join(output_blocks)


def main():
    print "\n-------------TEST SECRET KEY AND MESSAGE-------------"
    key = b"Sixteen byte key"
    print "Key is: %-16s (%s)" % (key, key.encode('hex'))
    msg = b"Attack at dawn"
    print "Msg is: %-16s (%s)" % (msg, msg.encode('hex'))

    print "\n-------------TESTING AES CBC ENCRYPTION AND DECRYPTION-------------"
    cbc_iv, cbc_cipher = aes_cbc_encrypt(key, msg)
    print "IV: %s, MSG: %s" % (cbc_iv.encode('hex'), cbc_cipher.encode('hex'))
    cbc_msg = aes_cbc_decrypt(key, cbc_iv, cbc_cipher)
    print "Decoded Message: %s" % cbc_msg

    print "\n-------------TESTING AES CTR ENCRYPTION AND DECRYPTION-------------"
    ctr_nonce, ctr_cipher = aes_ctr_encrypt(key, msg)
    print "IV: %s, MSG: %s" % (ctr_nonce.encode('hex'), ctr_cipher.encode('hex'))
    ctr_msg = aes_ctr_decrypt(key, ctr_nonce, ctr_cipher)
    print "Decoded Message: %s" % ctr_msg

    print "\n-------------PROVIDED INPUTS-------------"
    cipher_texts = load_cipher_texts()
    print_cipher_texts(cipher_texts)

    print "\n-------------DECRYPTING PROVIDED INPUTS-------------"

    # Ciphertexts 1 & 2 are encrypted in CBC Mode
    for idx, val in enumerate(cipher_texts[0:2]):
        cbc_msg = aes_cbc_decrypt(val[0], val[1], val[2])
        print "%d: %s" % (idx, cbc_msg)

    # Ciphertexts 3 & 4 are encrypted in CBC Mode
    for idx, val in enumerate(cipher_texts[2:]):
        ctr_msg = aes_ctr_decrypt(val[0], val[1], val[2])
        print "%d: %s" % (idx + 2, ctr_msg)

if __name__ == "__main__":
    main()
