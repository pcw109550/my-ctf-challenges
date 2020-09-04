# [Polynomials](https://ctftime.org/task/10414) (Crypto 810)

## Description

Something is wrong...

## Flag

`CODEGATE2020{86f94100f760b45e9c0f6925f5b474b24387ff6be5732ab88d74b4bfbff35951}`

## Challenge setup

Deploy [chall.sage](binary_flag/chall.sage) and [output](binary_flag/output) which is in [binary_flag](binary_flag) directory.

If you want to generate different output, simply run the below command in [prob_src](prob_src) directory(obviously replace the output file :D).(Do not run `chall.sage`). It is because the polynomials([secret.py](prob_src/secret.py): secret, public keys for the cryptosystem) are meticulously chosen.

`sage chall_genoutput.sage > output`

## Exploit

### Outline

- 16 bytes are generated from urandom, which will be the key of AES-CBC encryption
- The key will be divided to two equilengthed chunks(8 bytes)
- Each key chunk will be encrypted by plain [NTRUEncrypt cryptosystem](https://en.wikipedia.org/wiki/NTRUEncrypt).
- Publickey and encrypted result will be given to user, with additional information(number of positive/negative/zero coeffients of private key polynomial)
- Given setup will be broken by LLL.

### Vulnerability

- Public keys are selected to make the given cryptosystem broken by LLL algorithm
	- See section 4 in this [paper](https://link.springer.com/chapter/10.1007/3-540-69053-0_5).
- First break the NTRUEncrypt cryptosystem, recover key for AES and decrypt and get  profit.

### External Writeups

- [https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/#polynomial](https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/#polynomial)
- [https://github.com/0ops/ctfs-2020/blob/master/codegate-quals/Crypto/Polynomials/solve.sage](https://github.com/0ops/ctfs-2020/blob/master/codegate-quals/Crypto/Polynomials/solve.sage)
- [https://gist.github.com/hellman/019de1367f39ba73583d55aaddcbc1f8](https://gist.github.com/hellman/019de1367f39ba73583d55aaddcbc1f8)