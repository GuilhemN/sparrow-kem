"""
gen_cutoffs.py
Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

=== Code for re-creating the CUTOFFS variable in sparrow_rec.c.
"""

q = 260609
B = 2

def helprec(v):
    return (((1 << B) * v) // q) & 1

cutoffs = [0]

for v in range(1, 2*q+1):
    if helprec(v) != helprec(cutoffs[-1]):
        cutoffs.append(v)
    
print(cutoffs)