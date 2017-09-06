#ifndef LABHE_GEN_HEADER
#define LABHE_GEN_HEADER

int labhe_gen_sk(unsigned char *sk,
					  mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         		  const int l, const int k,
	         		  mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         		  mpz_t enc1,
	         		  gmp_randstate_t gmpRandState);

int labhe_setup(mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         		  const int l, const int k,
	         		  mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         		  mpz_t enc1,
	         		  gmp_randstate_t gmpRandState);

int labhe_gen(mpz_t pk,unsigned char *sk,
	             	const mpz_t n,const mpz_t y, const int k,
	             	const mpz_t _2k, 
	             	gmp_randstate_t gmpRandState);

#endif