from estimator.estimator import LWE, lwe_parameters
import contextlib
from math import log, log2, sqrt, pi, exp, floor, ceil
import os
from sage.all import is_prime

def supress_stdout(func):
    """
    Silence the stdout of a function in Python without
    trashing sys.stdout and restoring each function call.
    See https://stackoverflow.com/a/28321717
    """
    def wrapper(*a, **ka):
        with open(os.devnull, 'w') as devnull:
            with contextlib.redirect_stdout(devnull):
                return func(*a, **ka)
    return wrapper

def printmydataclass(label, obj, log=False):
    """
    Function for pretty-printing dataclass objects
    """
    print("\n" + label)
    xlen = max(len(x) for x in obj.__dataclass_fields__) + 5
    ylen = max(len(str(obj.__getattribute__(x))) for x in obj.__dataclass_fields__) + 5
    if log:
        for x in obj.__dataclass_fields__:
            print("{x} = {y} (log = {z:.2f})".format(
                x=x.ljust(xlen),
                y=str(obj.__getattribute__(x)).ljust(ylen),
                z=log2(obj.__getattribute__(x))
            ))
    else:
        for x in obj.__dataclass_fields__:
            print("{x} = {y}".format(
                x=x.ljust(xlen),
                y=str(obj.__getattribute__(x))
            ))

def dimensionsforfree(B):
    """
    Number of "dimensions for free", called d in [Duc18].
    """
    return round(B * log(4 / 3) / log(B / (2 * pi * exp(1))))

def convert_blocksize_to_security(bkz_blocksize):
    """
    Compute the classical and quantum hardness from the BKZ blocksize
    - Classical: use [BDGL16]
    - Quantum: use [CL21]
    """
    bitsec_classical = round(bkz_blocksize * 0.292, 1)
    bitsec_quantum = round(bkz_blocksize * 0.250, 1)
    return bitsec_classical, bitsec_quantum


@supress_stdout
def LWE_estimate_rough_silent(LWE_instance):
    return LWE.estimate.rough(LWE_instance)

def compute_MLWE_hardness(k, l, n, q, sig_reduc):
    LWEGaussian = lwe_parameters.NoiseDistribution.DiscreteGaussian
    # Generate and estimate hardness of LWE instance
    LWE_instance = lwe_parameters.LWEParameters(
        n=l*n, q=q,
        Xs=LWEGaussian(sig_reduc),
        Xe=LWEGaussian(sig_reduc),
        m=k*n, tag="",
    )
    LWE_hardness = LWE_estimate_rough_silent(LWE_instance)
    blocksize = min(LWE_hardness[key]["beta"] for key in LWE_hardness)
    # Apply dimensions for free
    blocksize -= dimensionsforfree(blocksize)
    classic, quantum = convert_blocksize_to_security(blocksize)
    return classic, quantum

"""
Search a prime modulo q such 2n | q-1
"""
def find_q(logq, n):
    q = 2**logq
    while q >= 0:
        if is_prime(q) and (q-1) % (2*n) == 0:
            return q
        q -= 1

# Bound on decapsulation error
decaps_errors = {
    # n, k, ell, sigA, sigB, sigy, q, qA => err
    (1024, 1, 1, 2, 2, 128): 5571,

    (128, 7, 7, 4, 4, 512): 15683,
    (128, 7, 7, 2, 2, 512): 13133,
    (128, 6, 6, 6, 6, 512): 38940,

    (64, 18, 18, 2, 2, 128): 5777,
    (1024, 1, 1, 4, 4, 512): 22288,
}

class Param:
    """
    This class stores all parameters and metrics relative to an instance of PLOVER-RLWE.
    """

    def __init__(self, bitsec, n, ell, k, q, sigA, sigB, sigy, ctbits=None):
        """
        Initialize a Param object.
        """
        verbose = True
        verbosehardness = True
        self.bitsec = bitsec
        self.n = n
        self.ell = ell
        self.k = k
        self.q = q
        self.sigA = sigA
        self.sigB = sigB
        self.sigy = sigy
        self.ctbits = ctbits
        if self.ctbits == None:
            self.ctbits = self.n

        self.complete_params(verbose=verbose)
        self.compute_security(verbosehardness)
        self.compute_sizes()

    def complete_params(self, verbose=False):
        """
        Complete the core parameter set by computing B
        """

        n = self.n
        ell = self.ell
        k = self.k
        q = self.q
        sigA = self.sigA
        sigB = self.sigB
        sigy = self.sigy

        # First compute bound on error |v_A-v_B|_inf            
        ctx = (n, k, ell, sigA, sigB, sigy)
        if not ctx in decaps_errors:
            print("Decapsulation error has not been evaluated for", ctx)
            print("Compute it using the script security/correctness/eval_sparrow.py")
            exit(0)
        else:
            self.err = decaps_errors[ctx]

        if verbose:
            print(f"overwhelming bound on |v_A-v_B|_inf: 2^{log(self.err, 2)}")

        ## Find B
        for B in range(10, 0, -1):
            if self.err <= floor(q/2**(B+2)):
                self.B = B
                break
    
    def compute_security(self, verbosehardness=False):
        bitsec = self.bitsec
        n = self.n
        k = self.k
        ell = self.ell
        q = self.q
        sigA = self.sigA
        sigB = self.sigB
        sigy = self.sigy

        # Factor loss in tail bound inequalities to achieve overwhelming probability
        C = sqrt(log(2) * (bitsec + 1) + log(n * (k + ell)))

        def bound_spectral_gauss(sigma, l):
            D = (log(n) + (bitsec - 1) * log(2)) / l
            tau = sqrt(1+D)
            
            return tau**2 * n * l * sigma**2

        # deniability
        B_deny = bound_spectral_gauss(sigA, k + ell)
        sig_deny = sqrt(1 / ( 1 / sigB**2 +  B_deny / sigy**2))
        self.sec_deniability = compute_MLWE_hardness(ell, k, n, q, sig_deny)

        # ow-cpa
        self.sec_owcpa_mlwe1 = compute_MLWE_hardness(k, ell, n, q, sigA)
        self.sec_owcpa_mlwe2 = compute_MLWE_hardness(ell + 1, k, n, q, sigB)

        # decaps-ow-cpa
        self.delta_cpa_n = (2**(-self.B) + 1/q)**self.ctbits

        # proven regime
        self.sec_decapsowcpa_mlwe1 = compute_MLWE_hardness(ell, k, n, q, sigB)
        self.sec_decapsowcpa_mlwe2 = compute_MLWE_hardness(k + 1, ell, n, q, sigA)

        # heuristic regime
        self.heur_sec_decapsowcpa_mlwe1 = compute_MLWE_hardness(ell * n, k * n - self.ctbits, 1, q, sigB)
        self.heur_sec_decapsowcpa_mlwe2 = compute_MLWE_hardness((k + 1) * n, ell * n - self.ctbits, 1, q, sigA)


    def compute_sizes(self):
        """
        Computing the average size of the verification key and the signature.
        """
        bitsec = self.bitsec
        n = self.n
        k = self.k
        ell = self.ell
        q = self.q

        hash_sz = (2*bitsec) // 8

        self.pk_alice = k*n*ceil(log(q, 2))//8
        self.pk_bob = ell*n*ceil(log(q, 2))//8

        self.ct_sz = self.ctbits // 8 + hash_sz

    def __repr__(self):
        # Print parameters
        print("=" * 70)
        print("Parameters:")
        print(f"  kappa:      {self.bitsec}")
        print(f"  n:          {self.n}")
        print(f"  (ell, k):   {self.ell, self.k}")
        print(f"  q:          {self.q}")
        print(f"  sigA:       2^{log2(self.sigA)}")
        print(f"  sigB:       2^{log2(self.sigB)}")
        print(f"  sigy:       2^{log2(self.sigy)}")
        print(f"  B:          {self.B}                (entropy of shared key: {self.ctbits*self.B})")
        print(f"  ctbits:     {self.ctbits}                (entropy of shared key: {self.ctbits*self.B})")

        print("=" * 70)
        print("Security:")
        print(f"  deniability:   {self.sec_deniability}")
        print(f"  OW-CPA:")
        print(f"      MLWE 1: {self.sec_owcpa_mlwe1}")
        print(f"      MLWE 2: {self.sec_owcpa_mlwe2}")
        print(f"  Decaps-OW-CPA:")
        print(f"      Entropy: {-log2(self.delta_cpa_n) - self.ctbits}")
        print(f"      Proven: ")
        print(f"           MLWE 1: {self.sec_decapsowcpa_mlwe1} - {self.ctbits} = {list(map(lambda x: x-self.ctbits, self.sec_decapsowcpa_mlwe1))}")
        print(f"           MLWE 2: {self.sec_decapsowcpa_mlwe2} - {self.ctbits} = {list(map(lambda x: x-self.ctbits, self.sec_decapsowcpa_mlwe2))}")
        print(f"      Heuristic: ")
        print(f"           MLWE 1: {self.heur_sec_decapsowcpa_mlwe1}")
        print(f"           MLWE 2: {self.heur_sec_decapsowcpa_mlwe2}")

        print("=" * 70)
        print("Sizes:")
        print(f"  pk_A: {self.pk_alice} B")
        print(f"  pk_B: {self.pk_bob} B")
        print(f"  ct:   {self.ct_sz} B")

        print("=" * 70)
        return ""

n = 64
q = find_q(18, n) # find closest q below 2**16
proved_scheme = Param(
    bitsec=128,
    n=n,
    ell=18, k=18, 
    q=q,
    sigA=2,
    sigB=2,
    sigy=2**7,
    ctbits=64)
print(proved_scheme)

n = 128
q = find_q(18, n) # find closest q below 2**16
heuristic_scheme = Param(
    bitsec=128,
    n=n,
    ell=7, k=7, 
    q=q,
    sigA=4,
    sigB=4,
    sigy=2**9)
print(heuristic_scheme)

n = 1024
q = find_q(22, n) # find closest q below 2**16
proved_sim_scheme = Param(
    bitsec=128,
    n=n,
    ell=1, k=1,
    q=q,
    sigA=4,
    sigB=4,
    sigy=2**9,
    ctbits=32)
print(proved_sim_scheme)

n = 1024
q = find_q(17, n) # find closest q below 2**16
heuristic_sim_scheme = Param(
    bitsec=128,
    n=1024,
    ell=1, k=1,
    q=q,
    sigA=2,
    sigB=2,
    sigy=2**7,
    ctbits=128)
print(heuristic_sim_scheme)
