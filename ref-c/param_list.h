

#if defined(SPARROW_128_1_)
#define SPARROW_(s)    SPARROW_128_1__##s
#define SPARROW_NAME   "Sparrow-128-1"
#define SPARROW_KAPPA  128
#define SPARROW_Q      260609l
#define SPARROW_N      128
#define SPARROW_ELL    7
#define SPARROW_K      7
#define SPARROW_B      2
#define SPARROW_CTBITS 128
#define SPARROW_K_SZ   32
#define SPARROW_PK_SZ  2016
#define SPARROW_SK_SZ  4032
#define SPARROW_CT1_SZ 16
#define SPARROW_CT_SZ  32 + SPARROW_CT1_SZ
#endif
