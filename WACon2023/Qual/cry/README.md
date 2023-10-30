# Cry

## Description

😭

## Author's Intention

Multiprime RSA, $N = p q r$, $q = (p ^ 2 + 1) / 2$. If we have polynomial relations between RSA primes, based on the relation info, we may factor $N$ by selecting a specific algebraic structure(polynomials / elliptic curves, etc). Apply the operation of the element on the structure and check its structure breaks down(inverse does not exist, etc.). Related with [Lenstra elliptic-curve factorization](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization), [Pollard's $p-1$](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm) or [Williams' $p+1$](https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm) factorization algorithm. This attack can be viewed as a generalization of these attacks.

## Flag

```
WACON2023{75e7511bccf428abfb98da2226b5712ce709a9fc9b92ad1b0a3ccb5f2b1cd772}
```

## Challenge setup

Deploy [dist](dist) directory as tarball. Offline challenge.

## Solution

### Solution 1: Elliptic Curves

Idea extended from [ImaginaryCTF 2023 - Sus](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sus).

1. Create random elliptic curve with extension $F_{p^2}$ having order $p^2 + 1$
2. ECM to factor $n$
- Sample Random Point $G$ over $E_{n^2}$
- Evaluate $Q = n G = p (p ^ 2 + 1) r G = p r (p ^ 2 + 1) G$
- Hope $Q$ is reduced to 0 modulo a prime factor of $p^2 + 1$ of $n$.
- If it is, $Q = (Q_{x}: Q_{y}: Q_{z})$, $p | \gcd(||Q_{z}||, n)$
- Field structure breaks down; addition and multiplication not well defined, when $\gcd(||Q_{z}||, n) \neq 0$
- Inverse cannot exist while addition or multiplication.

Due to ring isomorphism,
$ord(E_{n^2}) = ord(E_{p^2}) \times ord(E_{q^2}) \times ord(E_{r^2}) =  (p^2 + 1)\times ord(E_{q^2}) \times ord(E_{r^2})$. So when $G$ is in $ord(E_{p^2})$, $nG$ is the point of infinity $O$.

Implementation: [exploit/solve.sage](exploit/solve.sage).

### Solution 2: Implement The Paper

Implement [Factoring with Cyclotomic Polynomials](https://www.ams.org/journals/mcom/1989-52-185/S0025-5718-1989-0947467-1/S0025-5718-1989-0947467-1.pdf).

### Solution 3: Polynomials

Use degree 4 polynomial of order $p^4 - 1$ where first and third coefficient is zero.

## External Writeups

- https://soon.haari.me/2023-wacon-quals/
    - Used degree 4 Polynomial of order $p^4 - 1$

## Stats

- General Division: 2 solves
- Global Division: 3 solves
