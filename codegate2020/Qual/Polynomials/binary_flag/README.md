# Exploit

## Outline

- 16 bytes are generated from urandom, which will be the key of AES-CBC encryption
- The key will be divided to two equilengthed chunks(8 bytes)
- Each key chunk will be encrypted by plain [NTRUEncrypt cryptosystem](https://en.wikipedia.org/wiki/NTRUEncrypt).
- Publickey and encrypted result will be given to user, with additional information(number of positive/negative/zero coeffients of private key polynomial)

## Vulnerability

- Public keys are meticuluously selected by broken by LLL algorithm
	- See section 4 in this [paper](https://link.springer.com/chapter/10.1007/3-540-69053-0_5)
- The **attack is most easiest(oldest)** among attacks on this particular cryptosystem(paper from 1999).
- First break the NTRUEncrypt cryptosystem, recover key for AES and decrypt and get  profit.

## Output

```
[*] Performing LLL
[+] Key cands:[b'\xb0\xe2LtC\xd6\x18\xe5', b'].\xba\xf6&%d1\x7ful', b'\x89G\xb7\x91\x87\xb3|\xa6\xbd\n\x9c', b'r\xae\xfdS\xf7\xaa\xfa|=\x92\x86', b'ER\x19_\xa6C\xc5!\x87F\xbe']
[*] Performing LLL
[+] Key cands:[b'Fv\x96_\x96\xff(\xef', b'C\x0f\xc0"\xe1_J\xf5S\xd54\xef', b'\x16wo ^\x1bO\xcf\xa5\x86K\x92', b'0\xe5:\xee4\x93\xd7\xb9\xc8\x86\xbe\x9f', b'\x16_\x0f\x14\xa6\x95\xf2\x07\xady\xf1 ', b'5\xb6\xe3\xcd\xec\x12\xd0\x18c\xe7B/', b'Z\x813\x8d\xd5\xe8\xfb\x0f5\x1a}\xf4']
[+] CODEGATE2020{86f94100f760b45e9c0f6925f5b474b24387ff6be5732ab88d74b4bfbff35951}

real	0m10.836s
user	0m10.524s
sys	0m0.375s
```

Done on my old laptop computer :D
