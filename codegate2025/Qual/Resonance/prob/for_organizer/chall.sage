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
