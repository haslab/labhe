#include <gmp.h>

#include "bhjl.h"

/*
 * BHJL encryption
 * Inputs: 
 *   - Message to encrypt: m
 *   - Public parameters and precomputed values: n, y, _2k
 *   - Bit-length of messages: k
 *   - State of GMP randomness generator
 * Outputs: ciphertext c
 * Assumptions: 
 *   - message is within the valid range 0 <= m < 2^{k}
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int bhjl_encrypt(mpz_t c,const mpz_t m,
	             const mpz_t n,const mpz_t y, const int k,
	             const mpz_t _2k, 
	             gmp_randstate_t gmpRandState) 
{
	mpz_t x, t1, t2, t3;

   	mpz_init(x);
    mpz_urandomm(x,gmpRandState,n);

   	mpz_init(t1);
    mpz_powm(t1,x,_2k,n);

   	mpz_init(t2);
    mpz_powm(t2,y,m,n);

   	mpz_init(t3);
    mpz_mul(t3,t1,t2);

    mpz_mod(c,t3,n);

    mpz_clears(x,t1,t2,t3,NULL);

   	return 0;
}

/*
 * BHJL decryption
 * Inputs: 
 *   - Ciphertext to decrypt: c
 *   - Secret parameters and precomputed values: p, D, _2k1, pm12k
 *   - Bit-length of messages: k
 *   - State of GMP randomness generator
 * Outputs: recovered message m
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - ciphertext is in the correct range 0 <= c < n
 *   - GMP randomness state is managed by the caller
 */
int bhjl_decrypt(mpz_t m,const mpz_t c,
	             const mpz_t p,const mpz_t D,const int k,
	             const mpz_t _2k1,const mpz_t pm12k)
{
	int j;
	mpz_t t1, t2, Bloop, Dloop, Cloop, Eloop;

	mpz_init(t1);
	mpz_init(t2);
	mpz_init(Cloop);

	mpz_powm(Cloop,c,pm12k,p); // c^{(p-1)/2^k}

    mpz_set_ui(m,0);

	mpz_init_set_ui(Bloop,1);	
	mpz_init_set(Dloop,D);	

   	mpz_init_set(Eloop,_2k1);

	for (j=1;j<k;j++) {
		mpz_powm(t1,Cloop,Eloop,p);
		if (mpz_cmp_ui(t1,1)!=0) {
			// Not equal to 1
			mpz_add(m,m,Bloop);
			mpz_mul(t1,Cloop,Dloop);
			mpz_mod(Cloop,t1,p);
		}
		mpz_add(Bloop,Bloop,Bloop);
		mpz_powm_ui(Dloop,Dloop,2,p);
		mpz_tdiv_q_2exp(Eloop,Eloop,1);
	}
	if (mpz_cmp_ui(Cloop,1)!=0) {
		// Not equal to 1
		mpz_add(m,m,Bloop);
	}

  mpz_clears(t1, t2, Bloop, Dloop, Cloop, Eloop, NULL);

	return 0;
}

/*
 * BHJL homomorphic addition
 * Inputs: 
 *   - Ciphertexts containing messages to add: c1, c2
 *   - Modulus: n
 * Outputs: ciphertext encoding addition
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - ciphertexts c1, c2 are in the correct range 0 <= c1,c2 < n
 */
int bhjl_homadd(mpz_t c, const mpz_t c1, const mpz_t c2, 
	            const mpz_t n) {
	mpz_t t;

	mpz_init(t);

	mpz_mul(t,c1,c2);

	mpz_mod(c,t,n);

    mpz_clear(t);
	return 0;
}

/*
 * BHJL homomorphic subtraction
 * Inputs: 
 *   - Ciphertexts containing messages to subtract: c1, c2
 *   - Modulus: n
 * Outputs: ciphertext encoding difference
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - ciphertexts c1, c2 are in the correct range 0 <= c1,c2 < n
 */
int bhjl_homsub(mpz_t c, const mpz_t c1, const mpz_t c2, 
	            const mpz_t n) {
	mpz_t t1,t2;

	mpz_init(t1);
	mpz_init(t2);

	mpz_invert(t1, c2, n);
	mpz_mul(t2,c1,t1);

	mpz_mod(c,t2,n);

	mpz_clears(t1,t2,NULL);
	return 0;
}

/*
 * BHJL homomorphic scalar multiplication
 * Inputs: 
 *   - Ciphertext containing message multiply: c1
 *   - The scalar: s
 *   - Modulus: n
 * Outputs: ciphertext encoding scalar multiplication
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - ciphertexts c1, c2 are in the correct range 0 <= c1 < n
 */

int bhjl_homsmul(mpz_t c, const mpz_t c1, const mpz_t s, 
	            const mpz_t n) {
  
	mpz_powm(c,c1,s,n);

	return 0;
}
