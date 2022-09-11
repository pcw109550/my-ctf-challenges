#!/usr/bin/env sage
from sage.all import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

m_1 = 7  # Parameter for 1st Lattice
m_2 = 15 - 1  # Parameter for 2nd Lattice
t_2 = 7  # Parameter for 2nd Lattice

# n is the size of primes, alpha is the size of e. dSize is bit size of dp & dq. Number of unknown bits of dp & dq is Unknown_MSB.
n = 512
dSize = 512
alpha = 85
Unknown_MSB = 512 - 200

# TWO_POWER is the left shift of 2. This value corresponds  to the knowledge of LSBs
TWO_POWER = 2 ^ (dSize - Unknown_MSB)


with open("../public/output") as f:
    data = f.read().strip().split()
    [N, e, LSB_dp, LSB_dq, ciphertext] = [
        int(data[0]),
        int(data[1]),
        int(data[2]),
        int(data[3]),
        int(data[4], 16),
    ]


def solve(N, e, LSB_dp, LSB_dq):
    A = -e ^ 2 * LSB_dp * LSB_dq + e * LSB_dp + e * LSB_dq - 1

    B = gcd(N - 1, e * TWO_POWER)

    C = (N - 1) / B
    C = ZZ(C)

    C_IN = C.inverse_mod(e * TWO_POWER)

    C_IN = ZZ(C_IN)
    R.<x, y> = QQ[]


    f = (
        B * x * y - C_IN * (e * LSB_dq - 1) * x - C_IN * (e * LSB_dp - 1) * y + A * C_IN
    )  # (k,l) is a root of f modulo e*TWO_POWER


    # X and Y are upper bounds of  k and l respectively
    X = 2 ^ alpha
    Y = 2 ^ alpha


    """
    We store shift polynomials in set G and all monomials of shift polynomials in MON
    """
    G = []
    MON = []
    for a in range(m_1 + 1):
        for b in range(m_1 + 1):
            MON.append(x ^ a * y ^ b)
            if a >= b:
                g = x ^ (a - b) * f ^ b * (e * TWO_POWER) ^ (m_1 - b)
            else:
                g = y ^ (b - a) * f ^ a * (e * TWO_POWER) ^ (m_1 - a)

            g = g(x * X, y * Y)
            G.append(g)

    """
    Form a matrix B_LSB. Entries of B_LSB are coming from the coefficient 
    vector from  shift polynomials
    """

    B_LSB = zero_matrix(ZZ, (m_1 + 1) ^ 2)
    print("1st lattice dimension", (m_1 + 1) ^ 2)
    for j in range(len(G)):
        for i in range(len(MON)):
            cij = (G[j]).coefficient(MON[i])
            cij = cij(0, 0)
            B_LSB[j, i] = cij


    from time import process_time

    TIME_Start = process_time()
    # Apply LLL algorithm over the matrix B_LSB
    B_LSB = B_LSB.LLL()
    TIME_Stop = process_time()
    print("1st LLL time", TIME_Stop - TIME_Start)

    """
    After reduction, now we are reconstructing the 
    polynomials from the matrix and these polynomials have common root (k,l) over integer. 
    These polynomials correspond to shorter vectors in the lattice. We store these polynomials in a set POLY
    """
    POLY = []
    MAGIC1 = 1
    for j in range((m_1 + 1) ^ 2 - MAGIC1):
        f = 0
        for i in range((m_1 + 1) ^ 2):
            cij = B_LSB[j, i]
            cij = cij / MON[i](X, Y)
            cj = ZZ(cij)
            f = f + cj * MON[i]
        POLY.append(f)
        print(j, (m_1 + 1) ^ 2)
        #if f(k, l) == 0:
        #    POLY.append(f)
        #else:
        #    break
    set_verbose(-1)

    """
    We compute  Grobner basis over prime field Z instead of over integers for efficiency. Since k, l are less
    than e, we take Z as the next prime of e
    We consider the polynomials of POLY as modular polynomials over GF(Z). Then 
    try to find the root using Groebner basis.
    """
    Z = next_prime(e)
    MOD = PolynomialRing(GF(Z), 2, "X")
    POLY_NEW = []
    for i in range(len(POLY)):
        POLY_NEW.append(MOD(POLY[i]))


    I = (POLY_NEW) * MOD
    tt = cputime()
    B = I.groebner_basis()
    print(B)

    print("Estimated k & l: ", Z - B[0](0, 0), Z - B[1](0, 0))
    k, l = Integer(Z - B[0](0, 0)), Integer(Z - B[1](0, 0))
    #print("k = ", k)
    #print("l = ", l)
    #assert k == Z - B[0](0, 0) and l == Z - B[1](0, 0)

    """
    From here 2nd step starts. After 1st step we know k. Now we try to find unknown 
    MSBs of dp
    """
    R.<x> = QQ[]


    f = e * (TWO_POWER * x + LSB_dp) - 1 + k

    IN_k = (e * TWO_POWER).inverse_mod(k * N)

    f = x + IN_k * (e * LSB_dp - 1 + k)  # Make f monic by inverting the coefficient of x
    X = 2 ^ Unknown_MSB


    # Generate shift polynomials and store these polynomials in F. Store monomials of shift polynomials in S
    F = []
    S = []
    for i in range(m_2 + 1):
        h = f ^ i * k ^ (m_2 - i) * N ^ (max(0, t_2 - i))
        F.append(h)
        S.append(x ^ i)


    """
    Form a matrix MAT. Entries of MAT are coming from the coefficient 
    vector from shift polynomials which are stored in F
    """

    print("2nd lattice dimension", len(F))


    MAT = Matrix(ZZ, len(F))

    for i in range(len(F)):
        f = F[i]
        f = f(x * X)

        coeffs = f.coefficients(sparse=False)
        for j in range(len(coeffs), len(F)):
            coeffs.append(0)
        coeffs = vector(coeffs)
        MAT[i] = coeffs


    from time import process_time

    TIME_Start = process_time()
    tt = cputime()
    MAT = MAT.LLL()
    TIME_Stop = process_time()
    print("2nd LLL time", TIME_Stop - TIME_Start)

    # After reduction identify polynomials which have root MSB_dp over integer and store them in a set A.

    A = []
    MAGIC2 = 1
    for j in range(len(F) - MAGIC2):
        f = 0
        for i in range(len(S)):
            cij = MAT[j, i]
            cij = cij / S[i](X)
            cj = ZZ(cij)
            f = f + cj * S[i]
        A.append(f)
        print(j, len(F))

    # Find the root MSB_dp using Groebner basis techenique over integer

    I = ideal(A)
    tt = cputime()
    B = I.groebner_basis()

    MSB_dp = -B[0](0)

    dp = Integer((MSB_dp << 200) + LSB_dp)

    p = (e * dp - 1) // k + 1
    assert N % p == 0

    q = N // p
    d = pow(e, -1, (p - 1) * (q - 1))
    u = pow(p, -1, q)
    key = RSA.construct((int(N), int(e), int(d), int(p), int(q), int(u)))
    cipher = PKCS1_OAEP.new(key)

    ct = long_to_bytes(ciphertext)
    pt = cipher.decrypt(ct)

    return pt


print(solve(N, e, LSB_dp, LSB_dq))
