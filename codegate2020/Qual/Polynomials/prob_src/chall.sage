#!/usr/bin/env sage
from sage.misc.banner import version_dict
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from os import urandom

assert version_dict()["major"] >= 9


class Chall:
    def __init__(self, N, p, q):
        self.N, self.p, self.q = N, p, q
        self.R = PolynomialRing(Integers(q), "x")
        self.x = self.R.gen()
        self.S = self.R.quotient(self.x ^ N - 1, "x")
        self.h, self.f = None, None

    def random(self):
        return self.S([randint(-1, 1) for _ in range(self.N)])

    def keygen(self):
        while True:
            self.F = self.random()
            self.f = self.p * self.F + 1
            try:
                self.z = self.f ^ -1
            except:
                continue
            break
        while True:
            self.g = self.random()
            try:
                self.g ^ -1
            except:
                continue
            break
        self.h = self.p * self.z * self.g

    def getPublicKey(self):
        return list(self.h)

    def getPrivateKey(self):
        return list(self.f)

    def encrypt(self, m):
        m_encoded = self.encode(b2l(m))
        e = self.random() * self.h + self.S(m_encoded)
        return list(e)

    def decrypt(self, e, privkey):
        e, privkey = self.S(e), self.S(privkey)
        temp = map(Integer, list(privkey * e))
        temp = [t - self.q if t > self.q // 2 else t for t in temp]
        temp = [t % self.p for t in temp]
        pt_encoded = [t - self.p if t > self.p // 2 else t for t in temp]
        pt = l2b(self.decode(pt_encoded))
        return pt

    def encode(self, value):
        assert 0 <= value < 3 ^ self.N
        out = []
        for _ in range(self.N):
            out.append(value % 3 - 1)
            value -= value % 3
            value /= 3
        return out

    def decode(self, value):
        out = sum([(value[i] + 1) * 3 ^ i for i in range(len(value))])
        return out

    def count(self, row):
        p = sum([e == 1 for e in row])
        n = sum([e == self.q - 1 for e in row])
        return p, len(row) - p - n, n


def wrapper(N, p, q, pt):
    chall = Chall(N, p, q)
    chall.keygen()
    print(chall.getPublicKey())
    print(chall.encrypt(pt))
    print(chall.count(list((chall.F))))

if __name__ == "__main__":
    key = urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = pad(open("flag.txt", "rb").read(), 16)
    enc_flag = b2l(cipher.encrypt(flag))
    print(enc_flag)

    key1, key2 = key[:8], key[8:]

    wrapper(55, 3, 4027, key1)
    wrapper(60, 3, 1499, key2)
