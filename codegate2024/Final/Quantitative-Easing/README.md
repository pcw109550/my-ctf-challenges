# Crypto - Quantitative Easing

### Author
- Park Changwan (@diff72840089)

### Infra

```sh
cd prob/for_organizer
# setup port by tweaking docker compose
docker compose up --build -d
```

Connect with

```sh
nc 54.180.139.83 13337
```

### Description

```
I rolled my own b{lockchain|ank}. Please stimulate our economy!
```

### Writeup

Keywords: Zero Knowledge, Range Proofs, Weak Fiat-Shamir Transformation, Mimblewimble Transaction

The challenge implements basic blockchain with mimblewimble protocol enabled. Mimblewimble transactions gives privacy, by leveraging pederson commitments, schnorr signatures, and range proofs(or bulletproofs) scheme. Range proofs are zk scheme, which requires Fiat-Shamir transformation for non-interactive protocols.

- [1] BulletProof paper: https://eprint.iacr.org/2017/1066.pdf
- [2] Mimblewimble transactions: https://tlu.tarilabs.com/protocols/mimblewimble-transactions-explained

When weak Fiat-Shamir transformation is used for range proofs, the attacker may forge range proofs and the scheme becomes provably insecure. Article [4] amounts the actual attack on range proofs(not aggregated).

- [3] Weak Fiat-Shamir Attacks on
Modern Proof Systems: Section 4: https://eprint.iacr.org/2023/691.pdf
- [4] Frozen Heart Vulnerability in bulletproofs: https://blog.trailofbits.com/2022/04/15/the-frozen-heart-vulnerability-in-bulletproofs/

The challenge is implemented based on open source range proof implementations that is vulnerable to weak Fiat-Shamir transformation.

- [5] Range proof implementation: https://github.com/wborgeaud/python-bulletproofs

By mounting the attack introduced at [3], we may forge aggregated range proofs, eventually forging `tx_fees` to random value sampled at `GF(secp256k1.order)`.

The main implementation of the attack is at `exploit/src/solve.py`'s `Agent::request_with_forgery` method implementation, which uses `exploit/src/rangeproofs/rangeproof_aggregate_prover_forgery.py`. You may compare the attack code with original `Agent::request` implementation.

Run solver script by

```sh
cd exploit/src
python3 -m pip install requirements.txt
python3 solve.py
```

Example stdout:
```log
[<] Opening connection to localhost on port 13337: Trying 127.0.0.
[+] Opening connection to localhost on port 13337: Done
[*] PoW token = s.AAfQ.AACYZXwYSfPurIbV2NIn5pfw
[*] PoW solution = s.AABRUfkKJVF9ume9LRFRTpRISn17UVySLaiRYfb3qHIuP17D7C8mfVEkeUF0ua6NM/uNU055KGNYBSZj7sQtx46IhvOtMibNyr1fBePF0pD7bYqcznHR4AzomzYOVAsvO0St91aFSSIwvUtY6IA4YxJGYPyR8EkJctgthXgJ7C591PCf4SJWBsjpmsu1ZRS2IR97G9Q8IOnwKX/3iDgoyvHX
[*] PoW validation = 'Correct'
[*] Received Protocol Parameters
[*] Received transaction
[*] Received spending key
[*] Sent transaction
[*] Check flag
{'flag': 'CODEGATE{Times_29/Aug/2024_Chancellor_on_brink_of_third_bailout_for_banks}'}
CODEGATE{Times_29/Aug/2024_Chancellor_on_brink_of_third_bailout_for_banks}
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

### Flag

```
CODEGATE{Times_29/Aug/2024_Chancellor_on_brink_of_third_bailout_for_banks}
```

## Stats

- General Division: 2 solves (DiceGang, Oops)

### External Writeups

- 0ops: https://github.com/hch257/CTF-Writeups/tree/main/2024-Codegate/Quantitative%20Easing
    - Unintended using Arithmetic overflow attack
