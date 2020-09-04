#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long as b2l
from itertools import cycle
from random import randint


class reveal:
    def __init__(self, info, bitlen):
        self.coeff = cycle(info)
        self.prime = getPrime(bitlen)
        self.bitlen = bitlen
        self.seed = randint(1, self.prime)
        print("[*] Revealing...")
        print(self.prime, self.seed)
        print([chunk.bit_length() for chunk in info])

    def __iter__(self):
        return self

    def __next__(self):
        temp = next(self.coeff) * self.seed % self.prime
        self.seed = self.seed ** 2 % self.prime
        return Chall.munch(temp, self.bitlen * 9 // 10, self.bitlen)


class Chall:
    def __init__(self, size, n, cutoff):
        self.key = RSA.generate(size)
        self.cutoff = cutoff
        self.p, self.nchunks = self.key.p, 2 * n + 1
        self.info = []
        print(self.key.n)

    def munchprime(self):
        bitlen = self.p.bit_length()
        for i in range(0, bitlen, 2 * bitlen // self.nchunks):
            bite = self.munch(self.p, i, 2 * bitlen // self.nchunks - 35)
            self.info.append(bite)

    def expose(self):
        leak = reveal(self.info, self.p.bit_length())
        print("[*] Leaking...")
        for i in range(self.cutoff):
            print(next(leak))

    def getflag(self):
        flag = b2l(open("flag.txt", "rb").read())
        c = pow(flag, self.key.e, self.key.n)
        return c

    @staticmethod
    def munch(target, start, length):
        return (target >> start) & ((1 << length) - 1)


if __name__ == "__main__":
    chall = Chall(1024, 3, 200)
    print("[*] Here is your challenge:")
    print(chall.getflag())
    chall.munchprime()
    chall.expose()
