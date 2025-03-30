## Author

Park Changwan(pcw109550|diff)

## Problem Setup

`./prob/for_user/` for user
At `./prob/for_organizer`, run `docker compose up -d` for deployment

## Notes about remote exploit

Server code is heavy. Connection timeout: 900s, and PoW also added: `python3 pow.py ask 7777`.

Confirmed that the container only uses single core. Expect four active connections, or we need to scale out/up when needed. Tested with three parallel connections. Targeted the server machine: `m5.xlarge` and server side computation takes about 6 minutes.

## Description

`Can you tune into the hidden frequency of the supersingular sea? Serverside timeout: 900s`

## Writeup

**chall.sage**

```py
import itertools
import sys

p = 73743043621499797449074820543863456997944695372324032511999999999999999999999

x = var("x")
Fp2 = GF(p**2, name="z2", modulus=x**2 + 1)
z2 = Fp2.gen()
Fp4 = Fp2.extension(2, name="z4")
z4 = Fp4.gen()

E0 = EllipticCurve(Fp4, [1, 0])
E0.set_order((p**2 - 1) ** 2, num_checks=0)
E0_j_invariant = E0.j_invariant()


def H(preimage):
    prev_j_invariant = E0_j_invariant
    walk = set()
    E = E0.isogeny(E0(0, 0)).codomain()

    result = 0
    # Lets surf through the graphs.
    for idx, bit in enumerate(preimage):
        sys.stdout.write(str(idx))
        sys.stdout.flush()

        f = E.division_polynomial(2)

        kernels = [
            cand
            for cand in sorted([E.lift_x(x) for x in f.roots(multiplicities=False)])
            if E.isogeny(cand).codomain().j_invariant() != prev_j_invariant
        ]
        assert len(kernels) == 2
        kernel = kernels[bit]

        isogeny = E.isogeny(kernel)
        domain = isogeny.domain()
        domain_j_invariant = domain.j_invariant()
        codomain = isogeny.codomain()
        codomain_j_invariant = codomain.j_invariant()
        assert domain_j_invariant != codomain_j_invariant

        prev_j_invariant = domain_j_invariant
        E = codomain

        # Please, become a trailblazer.
        assert codomain_j_invariant not in walk
        walk.add(codomain_j_invariant)

        sys.stdout.write(".")
        sys.stdout.flush()

    h = E.j_invariant()
    walk.remove(h)

    return h, walk


if __name__ == "__main__":
    msg_cnt = 3

    bit_lens = [int(sys.stdin.readline().strip()) for _ in range(msg_cnt)]
    # The preimage must be plenty long.
    assert all(bit_len >= 1024 for bit_len in bit_lens)

    preimages = [
        [
            int(c)
            for c in list(
                format(abs(int(sys.stdin.readline().strip())), f"0{bit_lens[idx]}b")
            )
        ]
        for idx in range(msg_cnt)
    ]
    # Each preimage must be unique.
    assert all(a != b for a, b in itertools.combinations(preimages, r=2))

    # Takes long. Grab some coffee!
    hs, walks = zip(*map(H, preimages))

    # I need a triple collision, which makes it triple the difficulty.
    assert len(set(hs)) == 1
    # Can you walk?
    assert all(len(a & b) <= msg_cnt for a, b in itertools.combinations(walks, r=2))
    assert all(len(a) >= bit_lens[idx] - msg_cnt for idx, a in enumerate(walks))

    # Here is your treat.
    sys.stdout.write(open("flag.txt").read())
    sys.stdout.flush()
```

In 2009, Charles et al. proposed an expander hash, called CGL, which is based on the isogeny graph of supersingular elliptic curves over finite fields. Supersingular isogeny graphs are excellent expander graphs with asymptotically optimal expansion constant. The security of CGL is based on the hardness of computing isogenies of
large degree between supersingular elliptic curves. [Ref](https://eprint.iacr.org/2017/1202.pdf)

Later, it was investigated that the CGL hash function on isogeny graphs of supersingular elliptic curves is insecure under collision attack when the endomorphism ring of the starting curve is known. [Ref](https://www.kpqc.or.kr/images/pdf/FIBS.pdf)

This challenge implements CGL hash function with the starting curve `E0` used in SQISign which the endomorphism ring is known. Therefore we can find collisions with KLPT algorithm, resulting in a sequence of elliptic curves (`E0`, `E1`, ..., `E_{n−1}`, `En` = `E0`) which corresponds to the collision of the CGL hash function.
[Ref](https://eprint.iacr.org/2017/962)

Specifically, challenge asks us(see `__main__`) to input three isogeny paths expressed by bit strings which follow below constraints:

- Each preimage length is larger than 1024.
- Bit string must be all different.
- All these three path's resulting codomain's j invariant must be identical.
- Avoid intermediate step for going back the graph using dual isogeny.
- All path must be composed of degree 2 isogenies.
- All path must not share more than 3 intermediate elliptic curves.

Apply KLPT algorithm by using https://github.com/LearningToSQI/SQISign-SageMath/tree/main. Simply speaking about SQISign, it applys the KLPT algorithm to find a path which the final codomain is equivalent to `EA -> E0 -> E1 -> E2`. [Ref](https://yx7.cc/docs/deuring/deuring_oberseminar_slides.pdf). On the intermediate steps, we contain smooth paths: `E0 -> EA` and `EA -> E2`. By fixing random kernels and torsion basis of `E0 -> E1` and `E1 -> E2`, and randomizing `EA`, we produce path `E0 -> E2` which `E2` is fixed, resulting in hash collision.

Implementation is given as a patch file located at `exploit/exploit.patch`:
```sh
git clone https://github.com/LearningToSQI/SQISign-SageMath/tree/main
cd SQISign-SageMath
git checkout 1217b8fd68dc750364ab5096cb14bce6e2df1d1d
git apply exploit.patch
sage example_SQISign.sage
```
The exploit take quite a time; single instance per at most 10 minutes but we can always run multiple instances at once. Gather preimage pairs until we satisfy upper constraints. The script not always succeeds so you will need to run multiple times, to gather three preimage pairs which passes the checks.

`exploit/solve.py` contains three preimages that satisfies the conditions, which were produced by upper script.

## Flag

`codegate2025{I_swam_here,_all_day_through_the_surging_waves,_the_wave_that_is_you}`

## Stats

- General Division: 2 solves (nowebzone, Kalmarunionen)
