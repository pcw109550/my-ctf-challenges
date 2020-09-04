#!/usr/bin/env sage
from secret import P1, Q1, a, b
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

DEBUG = False

P0 = P1 & ord('?')
Q0 = Q1 & ord('?')
assert is_prime(P0) and is_prime(P1)
assert is_prime(Q0) and is_prime(Q1)


def printd(data):
    if DEBUG:
        print(data)


def random_point(E, p, q, n):
    while True:
        try:
            x = randint(1, n - 1)
            # E.lift_x() does not work since n is composite
            yy = x ** 3 + a * x + b
            # Rabin cryptosystem
            mp = Integer(mod(yy, p).sqrt(extend=False))
            mq = Integer(mod(yy, q).sqrt(extend=False))
            break
        except:
            continue
    _, u, v = xgcd(p, q)
    r = (u * p * mq + v * q * mp) % n
    s = (u * p * mq - v * q * mp) % n
    y_cand = [r, n - r, s, n - s]

    for y in y_cand:
        assert E.is_on_curve(x, y)

    y = choice(y_cand)
    return E(x, y)


class Chall:

    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.E  = EllipticCurve(Zmod(self.n), [a, b])
        self.E1 = EllipticCurve(Zmod(p), [a, b])
        if DEBUG:
            print(self.E)
            print(self.E1)

        while True:
            try:
                # Not working, but you get the point :D
                # self.G = E.random_point()
                self.G = random_point(self.E, p, q, self.n)
                self.d = randint(1, 1 << 128) & (p >> 1)
                self.Q = self.d * self.G
                break
            except:
                continue

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
    printd(sd)

    l = Chall(P1, Q1)
    l.expose()
    ld = l.getkey()
    printd(ld)

    size = 16
    flag = pad(open('flag.txt', 'rb').read(), size)
    printd(flag.decode())

    key = int(sd + ld)
    key = key.to_bytes(size, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(flag).hex()

    print(enc_flag)