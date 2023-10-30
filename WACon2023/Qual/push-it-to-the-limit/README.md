# Push It To The Limit

## Description

[https://www.youtube.com/watch?v=Olgn9sXNdl0](https://www.youtube.com/watch?v=Olgn9sXNdl0)

## Author's Intention

Textbook RSA, $n = 1024$ bits $N$. The challenge exactly exposes half of the MSBs of $p$. According to theorem #10 of [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf),

> Theorem 10 (Coppersmith) Let $N = pq$ be an $n$-bit RSA modulus. Then, given the $n / 4$ least significant bits of $p$ or the $n / 4$ most significant bits of $p$, one can efficiently factor $N$.

What happens if we know less or equal to $n / 4$ consecutive bits? If we apply the theorem with some bruteforcing(hybrid attack), factoring is still feasible. Most CTF challenges give slightly more information than $n / 4$. Even given exactly half the bits of prime, it is still feasible when combined with bruteforcing. Lattice size - Brute force size tradeoff!

Faster lattice reduction algorithm == less bruteforce space. Luckily, we love this state-of-the-art lattice reduction algorithm: [flatter](https://github.com/keeganryan/flatter)! Applying a hybrid attack with flatter will give you a flag with less than 10 minutes on your laptop.

## Flag

```
WACON2023{flatter=>https://eprint.iacr.org/2023/237.pdf}
```

## Challenge setup

Deploy [dist](dist) directory as tarball. Offline Challenge.

## Solution

### Solution 1: Using [Flatter](https://github.com/keeganryan/flatter)

For exposing 512 bits of p, [paper](https://rtca2023.github.io/pages_Lyon/DocM3/Ryan.pdf) says
> Our results: 18 core-hours

We can speed up this, by running coppersmith with 506 bits, and 6 bits to be bruteforced. 
In my machine, It takes about 2 minutes per iteration. Overall expected time: $2 * 2 ^ 6 = 128$ minutes.

The script [exploit/factor.sage](exploit/factor.sage) is modified from [flatter](https://github.com/keeganryan/flatter), using the info that p's last bit is always 1. Also, 6 LSBs are assumed to be known. While performing actual attack, this must be bruteforced.

If we use less bits than 6 bits to bruteforce, the time will be more than doubled. Therefore bruteforcing 6 bits is optimal.

```sh
time ./factor.sage --step-1 | ./flatter | ./factor.sage --step-2
```

### Solution 2: Using sagemath's `small_roots()`

We may also use sagemath's default `small_roots()` implementation based on above bruteforce approach. Mind that bruteforce space will be much larger but still feasible to solve during ctf time.

## External Writeups

- https://connor-mccartney.github.io/cryptography/small-roots/push-it-to-the-limit-WACON-2023-prequal
- https://soon.haari.me/2023-wacon-quals/

## Stats

- General Division: 2 solves
- Global Division: 11 solves
