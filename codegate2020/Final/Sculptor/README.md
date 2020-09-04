# [Sculptor](https://ctftime.org/task/12953) (Crypto 804)

## Description

The old man and the lattice.

## Flag

`CODEGATE2020{Lattices_are_so_fxxking_cool}`

## Challenge setup

Deploy [chall.py](binary_flag/chall.py) and [output](binary_flag/output) which is in [binary_flag](binary_flag) directory.

If you want to generate different output, simply run the below command in [prob_src](prob_src) directory(obviously replace the output file :D).

`sage chall_debug.py | tee output`

## Exploit

- Cracking truncated LCG with mutiple states via LLL
- Generalization of attacking truncated LCG 
	- https://www.math.cmu.edu/~af1p/Texfiles/RECONTRUNC.pdf

### External Writeups

- TBD