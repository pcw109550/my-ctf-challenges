#!/usr/bin/env python3.6
from secrets import randbelow
from operator import mul, xor
from functools import reduce
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long as b2l

N = 32
RING = (1 << 64) - 1
HINT = 100
HIDDEN = 32


class Random:

    def __init__(self, ring, n):
        self.ring = ring
        self.n = n
        self.c = [randbelow(ring) for _ in range(n)]
        self.s = [randbelow(ring) for _ in range(n)]

    def f(self):
        return sum(map(mul, self.c, self.s)) % self.ring

    def update(self):
        self.s = self.s[1:] + [self.f()]
        return self.s[-1]


if __name__ == '__main__':
    r = Random(RING, N)
    print(r.c)

    [r.update() for _ in range(N ** 2)]

    hints = [r.update() >> HIDDEN for _ in range(HINT)]
    print(hints)

    [r.update() for _ in range(N ** 2)]

    size = RING.bit_length() // 4
    flag = pad(open('flag.txt', 'rb').read(), size)

    key = reduce(xor, r.s + r.c) ** 2
    key = key.to_bytes(size, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(flag).hex()

    print(enc_flag)