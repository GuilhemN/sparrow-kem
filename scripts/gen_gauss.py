"""
gen_gauss.py
Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

=== Code for re-creating the Gaussian table constants used in gauss_sample.c.
"""

from sage.all import *
from random import randrange
from polyr import *

R = RealField(200)
sigy = R(4)
# sigy = R(2**9)

sigy = R(sigy)

bitsec = 128
C = sqrt(log(2) * (bitsec + 1))
maxy = ceil(sigy*C)


def gauss(x, sig):
    return exp(-x**2/(2*sig**2))

s = R(1)
for i in range(1, maxy+1):
    s += gauss(i, sigy)


table = []
acc = 0
for i in range(maxy, 0, -1):
    acc += gauss(i, sigy)/s
    table.append(acc)

table = table[::-1]
nbbits = 63*3
inttable = list(map(lambda x: int(round(x * (1<<nbbits))), table))

# print table, with 64bits integers per element
for c in inttable:
    # decompose c = v3 + 2**63 * (v2 + 2**63 * v1)
    v3 = c % (1 << 63)
    c >>= 63
    v2 = c % (1 << 63)
    c >>= 63
    v1 = c % (1 << 63)

    print(f"    {v1}, {v2}, {v3},")