#ifndef BHJL_GEN_HEADER
#define BHJL_GEN_HEADER

int bhjl_gen(mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         const int l, const int k,
	         gmp_randstate_t gmpRandState);

int bhjl_precom(mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         const mpz_t p, const int k);

#endif
