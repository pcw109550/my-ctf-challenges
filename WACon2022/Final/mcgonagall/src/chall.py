import signal
from hashlib import sha256
from random import choice, randint
from secrets import randbits, token_bytes
from string import ascii_uppercase, digits

from ecdsa import SECP256k1, SigningKey

from flag import flag


def PoW():
    s = "".join(choice(ascii_uppercase + digits) for _ in range(16))
    print(s)
    answer = input()
    hash = sha256((s + answer).encode()).hexdigest()
    assert hash[:6] == "000000"


def main():
    trials = 30
    correct = 0
    for _ in range(trials):
        sk = SigningKey.generate(curve=SECP256k1)
        pk = sk.privkey.secret_multiplier
        print(sk.get_verifying_key().pubkey.point.x())
        print(sk.get_verifying_key().pubkey.point.y())

        info = 0
        for _ in range(256):
            msg = token_bytes(32)
            klen = randint(250, 256)
            sig = sk.sign(msg, k=randbits(klen))
            info += 256 - klen
            print(msg.hex(), sig.hex(), klen)

        assert info >= pk.bit_length()

        pk_ = int(input())
        if pk_ == pk:
            correct += 1

    assert correct / trials >= 0.7
    print(flag)


if __name__ == "__main__":
    [signal.alarm(1200), PoW(), main()]
