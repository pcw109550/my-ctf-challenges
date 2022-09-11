#!/usr/local/bin/sage
import os
import time
from hashlib import sha1, sha256

from Crypto.Util.number import long_to_bytes as l2b
from tqdm import tqdm

os.environ["PWNLIB_NOTERM"] = "1"
from pwn import *
from sage.all import *

# context.log_level = "DEBUG"
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
b = 0x0000000000000000000000000000000000000000000000000000000000000007
a = 0x0000000000000000000000000000000000000000000000000000000000000000
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
l = 256
Z = Zmod(n)


conn = remote("127.0.0.1", 13337)

# PoW
s = conn.recvline().rstrip().decode()
assert len(s) == 16
for i in tqdm(range(1 << 26)):
    t = str(i)
    hash = sha256((s + t).encode()).hexdigest()
    if hash[:6] == "000000":
        conn.sendline(t.encode())
        break


trial = 30
success = 0
for t in range(trial):
    Px = int(conn.readline(keepends=False))
    Py = int(conn.readline(keepends=False))

    rs = [None for _ in range(l)]
    ss = [None for _ in range(l)]
    hs = [None for _ in range(l)]
    cs = [None for _ in range(l)]
    pubkey = E(Px, Py)
    for i in range(l):
        row = conn.readline(keepends=False).split()
        r, s = int(row[1][:64], 16), int(row[1][64:], 16)
        h = int.from_bytes(sha1(l2b(int(row[0], 16))).digest(), byteorder="big")
        klen = int(row[2])
        rs[i] = r
        ss[i] = s
        hs[i] = h
        cs[i] = klen

    print([(cs.count(kk), kk) for kk in range(248, 257)])
    print(float(sum(cs) / l))

    cs, rs, ss, hs = zip(*sorted(zip(cs, rs, ss, hs)))

    ts = [None for _ in range(l)]
    us = [None for _ in range(l)]
    ls = [None for _ in range(l)]

    for i in range(l):
        sinv = int(1 / Z(ss[i]))
        ts[i] = sinv * rs[i]
        us[i] = (-sinv) * hs[i]
        ls[i] = 256 + 1 - cs[i]

    B = Matrix(ZZ, l + 2, l + 2)

    for i in range(l):
        li = ls[i] + 1
        B[i, i] = (2 ^ li) * n
        B[l, i] = (2 ^ li) * ts[i]
        B[l + 1, i] = (2 ^ li) * us[i]
    B[l, l] = 1
    B[l + 1, l + 1] = n

    beta = 15
    pk = 0

    st = time.time()
    print(f"BKZ with beta = {beta}")
    B = B.BKZ(block_size=beta)
    for row in B:
        guess = row[-2] % n
        d1, d2 = guess, n - guess
        if pubkey == d1 * G:
            pk = d1
            break
        if pubkey == d2 * G:
            pk = d2
            break
    print("Duration", time.time() - st)
    print("pk: ", pk)
    if pk != 0:
        success += 1
    print(f"# Success: {success} / {t + 1}")
    conn.sendline(str(pk).encode())

# flag
print(conn.recvline())
