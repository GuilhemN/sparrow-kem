import operator as op
from math import factorial as fac
from math import sqrt, log
import sys
from proba_util import *


bitsec = 128

(n, k, l, sigA, sigB, sigy) = (1024, 1, 1, 5, 5, 512)


pB = build_centered_normal(sigB)
pA = build_centered_normal(sigA)

pAB = law_product(pA, pB)
f = (find_tail_for_probability(pAB, 1e-128/min(n, 256)))
print(f, "or, 2^", log(f, 2))

psum = iter_law_convolution(pAB, n*(k+l))

pY = build_centered_normal(sigy)
pnoise = law_convolution(pY, pA)
pfin = law_convolution(psum, pnoise)

f = (find_tail_for_probability(pfin, 1e-128/min(n, 256)))
print(f, "or, 2^", log(f, 2))
