#ifndef BHJL_HEADER
#define BHJL_HEADER

int bhjl_encrypt(mpz_t c,const mpz_t m,
	             const mpz_t n,const mpz_t y, const int k,
	             const mpz_t _2k, 
	             gmp_randstate_t gmpRandState);

int bhjl_decrypt(mpz_t m,const mpz_t c,
	             const mpz_t p,const mpz_t D,const int k,
	             const mpz_t _2k1,const mpz_t pm12k);

int bhjl_homadd(mpz_t c, const mpz_t c1, const mpz_t c2, 
	            const mpz_t n);

int bhjl_homsub(mpz_t c, const mpz_t c1, const mpz_t c2, 
	            const mpz_t n);

int bhjl_homsmul(mpz_t c, const mpz_t c1, const mpz_t s, 
	            const mpz_t n);

#endif
