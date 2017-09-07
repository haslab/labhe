#include <gmp.h>

#include "bhjl_gen.h"

/*
 * Prime generator for BHJL scheme
 * Inputs: 
 *   - Bit-length of primes p and q: l
 *   - Bit-length of messages: k
 *   - State of GMP randomness generator
 * Outputs: primes p and q
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
static int gen_rsa_primes(mpz_t p, mpz_t q, int l, int k,gmp_randstate_t gmpRandState) {
	mpz_t _2l,t1,t2;

   	mpz_init(t1);
   	mpz_init(t2);

   	mpz_init(_2l);
    mpz_set_ui(t1,1);
    mpz_mul_2exp(_2l,t1,l-1); // _2l = 2^l

	for(;;) {
	    mpz_urandomb(t1,gmpRandState,l-k); // 0 <= t1 < 2^{l-k-1}
	    mpz_mul_2exp(t2,t1,k);  // 0 <= t1 < 2^{l-1}
	    mpz_add(p,t2,_2l); // 2^l <= t1 < 2^l+2^{l-1}
	    mpz_setbit(p,0); // 2^l+1 <= t1 < 2^l+2^{l-1} and odd

	    if(mpz_probab_prime_p(p,128)!=0) { break; }
	}

    mpz_set_ui(q, 0);

	for(;;) {
	    mpz_urandomb(t1,gmpRandState,l); // 0 <= t1 < 2^{l-1}
	    mpz_add(q,t1,_2l); // 2^l <= t1 < 2^l+2^{l-1}
	    mpz_setbit(q,0); // 2^l+1 <= t1 < 2^l+2^{l-1} and odd

	    if(mpz_probab_prime_p(q,128)!=0) { break; }
	}

    mpz_clears(_2l,t1,t2,NULL);

    return 0;
}

/*
 * Parameter generator for BHJL scheme
 * Inputs: 
 *   - Bit-length of modulus: l
 *   - Bit-length of messages: k
 *   - State of GMP randomness generator
 * Outputs: secret/public parameters p, n, y, D
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int bhjl_gen(mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         const int l, const int k,
	         gmp_randstate_t gmpRandState)
{
	int jp,jq;
	mpz_t q, t1, t2;

	mpz_init(q);
	gen_rsa_primes(p,q,l>>1,k,gmpRandState);

	mpz_mul(n,p,q);

	for(;;) {
		mpz_urandomm(y,gmpRandState,n);
		jp = mpz_jacobi(y,p);
		jq = mpz_jacobi(y,q);
		if ((jp==-1)&&(jq==-1)) { break; }
	}

	mpz_init(t1);
	mpz_init(t2);

	mpz_sub_ui(t1,p,1);
	mpz_tdiv_q_2exp(t2,t1,k);
	mpz_powm(t1,y,t2,p);
	mpz_invert(D,t1,p);

  	mpz_clears(q,t1,t2,NULL);

	return 0;
}

/*
 * Precomputation of intermediate values used in BHJL scheme
 * Inputs: 
 *   - Prime: p
 *   - Bit-length of messages: k
 * Outputs: _2k1, _2k, pm12k (see inlined comments)
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 */
int bhjl_precom(mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         const mpz_t p, const int k)
{
	mpz_t t1;
   	
    mpz_init_set_ui(t1,1);
    mpz_mul_2exp(_2k1,t1,k-1); // _2k1 = 2^{k-1}
    mpz_mul_ui(_2k,_2k1,2); // _2k = 2^{k}

    mpz_sub_ui(t1,p,1);
	mpz_tdiv_q_2exp(pm12k,t1,k); // pm12k = (p-1)/2^{k}

    mpz_clear(t1);

	return 0;
}
