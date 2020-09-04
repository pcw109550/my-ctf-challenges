# [MUNCH](https://ctftime.org/task/10413) (Crypto 750)

## Description

Munch out the bits!

## Flag

`CODEGATE2020{5e7c462214d48ea48045add289f70b0619a0552bdd4201d8c20cedbfd9ce43cd}`

## Challenge setup

Deploy [chall.py](binary_flag/chall.py) and [output](binary_flag/output) which is in [binary_flag](binary_flag) directory.

If you want to generate different output, simply run the below command in [prob_src](prob_src) directory(obviously replace the output file :D).

`python3 chall.py > output`

## Exploit

### Outline

Two stages:

- Stage 1
	- Solve the hidden number problem by knowing the bit length of hidden numbers(exposed as output)
	- Solve four times to recover four bit chunks of RSA prime p.
- Stage 2
	- Apply generalized coppersmith attack. See the entire paper [here](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_25).

### Vulnerability

I gave bitlength of hidden four chunks. Also, I gave `200 / 4 = 50` queries(which exposes information of each chunks) to solve the hidden number problem. I tested that 50 queries are enough to fully recover each chunks.

Now the chunks are prepared to recover entire RSA prime p. Recover p and decrypt ciphertext to get flag.

### External Writeups

- [https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/#munch](https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/#munch)
- [https://github.com/0ops/ctfs-2020/tree/master/codegate-quals/Crypto/MUNCH](https://github.com/0ops/ctfs-2020/tree/master/codegate-quals/Crypto/MUNCH)
- [https://gist.github.com/hellman/019de1367f39ba73583d55aaddcbc1f8](https://gist.github.com/hellman/019de1367f39ba73583d55aaddcbc1f8)