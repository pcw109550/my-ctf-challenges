#!/usr/bin/env python3
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import GCD, getPrime

from flag import flag

SIZE = 1024
key = RSA.generate(SIZE, e=getPrime(SIZE // 12))
n, e, p, q = key.n, key.e, key.p, key.q
dp, dq = pow(e, -1, p - 1), pow(e, -1, q - 1)
cipher = PKCS1_OAEP.new(key)
assert GCD(2 * e, (e * dp - 1) // (p - 1)) == 1

print(n)
print(e)
print(dp % (1 << 200))
print(dq % (1 << 200))
print(cipher.encrypt(flag).hex())
