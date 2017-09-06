#ifndef PAILLIER_GEN_HEADER
#define PAILLIER_GEN_HEADER

int paillier_gen(mpz_t p, mpz_t q, mpz_t n, mpz_t n2, mpz_t lambda, mpz_t alpha, mpz_t g, 
				 const int l, const int lalpha);
int paillier_precom(mpz_t galpha, mpz_t gn, 
	             const mpz_t n, const mpz_t n2, const mpz_t g, const mpz_t alpha);

#endif
