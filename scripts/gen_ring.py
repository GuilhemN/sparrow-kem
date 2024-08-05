from sage.all import *

"""
Find h the generator of a group of order 2*n in Z_q.
"""
def find_h(q, n):

    F = GF(q)

    # We search the smallest x > 1 generating Z_{q_1}* and Z_{q_2}*
    x = 2
    while True:
        m = F(x).multiplicative_order()

        if (m % (2*n)) == 0:
            break

        x += 1

    # We derive an element of 2*n in Z_q
    assert(m % 2*n == 0) # 2*n divides m
    h = pow(x, m//(2*n), q)

    assert((h**n) % q - q == -1)
    assert((h**(2*n))%q == 1)

    return h

class ConcreteParameters:
    def __init__(self, logn, q) -> None:
        self.logn = logn
        self.n = 2**self.logn
        self.q = q

        self.compute_params()

    def compute_params(self):
        n = 2**self.logn
        self.h = find_h(self.q, n)

        # compute parameters for NTT
        self.compute_w()

    def compute_w(self):

        def _modexp(x, e, n):
            """(TESTING) Modular exponentiation: Compute x**e (mod n)."""
            y = 1
            while e > 0:
                if e & 1 == 1:
                    y = (y * x) % n
                x = (x * x) % n
                e >>= 1
            return y

        def _bitrev(x, l):
            """(TESTING) Return x with bits 0,1,..(l-1) in reverse order."""
            y = 0
            for i in range(l):
                y |= ((x >> i) & 1) << (l - i - 1)
            return y

        """(TESTING) Re-generate the NTT "tweak" table."""
        q   = self.q
        lgn = self.logn                 #   log2(n)
        n   = 2**lgn                    #   length of the transform
        h   = self.h                    #   Generates a subgroup of order 2*n
                                        #   obtained with test_params.py
        self.w   = []
        for i in range(n):
            j = _bitrev(i, lgn)
            x = (_modexp(h, j, q)) % q
            self.w.append(x)

    def __repr__(self) -> str:
        s = ""
        s += f"Concrete parameters: \n"
        s += f"    n = {2**self.logn}\n"
        s += f"    q = {self.q} (log = {float(log(self.q)/log(2))})\n"

        return s

    def _repr_w_for_c(self):
        w = [(c*2**64)%self.q for c in self.w]

        s = ""
        s += f"\t{w[1]:15}, {w[2]:15}, {w[3]:15},\n"
        for i in range(4, 2**self.logn, 4):
            s += f"\t{w[i]:15}, {w[i+1]:15}, {w[i+2]:15}, {w[i+3]:15},\n"
        return s

    def gen_c(self):
        n = 2**self.logn

        r = (2**64) % self.q
        rr = (r*r) % self.q
        ni = (rr * pow(n, -1, self.q)) % self.q
        qi = pow(-self.q, -1, 2**64)

        with open("generated/mont64.h", "w") as f:
            f.write(f"""// file generated with scripts/gen_ring.py

#if (SPARROW_N != {n} || SPARROW_Q != {self.q}l)
#error "Unrecognized polynomial parameters N, Q"
#endif

/*
    n   = {n}
    q  = {(self.q)}
    r   = 2^64 % q
    rr  = r^2 % q
    ni  = lift(rr * Mod(n,q)^-1)
    qi  = lift(Mod(-q,2^64)^-1)
*/

//  Montgomery constants. These depend on Q and N
#define MONT_R {r}L
#define MONT_RR {rr}L
#define MONT_NI {ni}L
#define MONT_QI {qi}L        

// end generated      
""")
            
        with open("generated/ntt64.c", "w") as f:
            f.write(f"""// file generated with scripts/gen_ring.py

static const int64_t sparrow_w_64[{n-1}] = {{
{self._repr_w_for_c()}}};

// end generated      
""")


p = ConcreteParameters(
    logn=7, # n = 128 
    q=260609, 
)
print(p)

p.gen_c()