#!/usr/bin/env sage
from secret import P1, Q1, a, b
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

P0 = P1 & ord('?')
Q0 = Q1 & ord('?')
assert is_prime(P0) and is_prime(P1)
assert is_prime(Q0) and is_prime(Q1)


class Chall:

    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.E  = EllipticCurve(Zmod(self.n), [a, b])
        self.E1 = EllipticCurve(Zmod(p), [a, b])

        # Not Implemented, but you get the point :D
        self.G = E.random_point()
        self.d = randint(1, 1 << 128) & (p >> 1)
        self.Q = self.d * self.G

    def expose(self):
        print(self.n)
        print(self.E1.order())
        print(self.G.xy())
        print(self.Q.xy())

    def getkey(self):
        return self.d


if __name__ == '__main__':
    s = Chall(P0, Q0)
    s.expose()
    sd = s.getkey()

    l = Chall(P1, Q1)
    l.expose()
    ld = l.getkey()

    size = 16
    flag = pad(open('flag.txt', 'rb').read(), size)

    key = int(sd + ld)
    key = key.to_bytes(size, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(flag).hex()

    print(enc_flag)