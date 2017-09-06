#include <stdio.h>
#include <gmp.h>

#include "prf.h"
#include "bhjl.h"
#include "bhjl_gen.h"
#include "labhe_gen.h"

/*
 * Master key generator for public-key LabHE-BHJL scheme
 * Inputs: 
 *   - Bit-length of BHJL modulus: l
 *   - Bit-length of BHJL messages: k
 *   - State of GMP randomness generator
 * Outputs: 
 *   - Secret/public BHJL parameters p, n, y, D
 *   - Precomputed BHJL parameters: _2k1, mpz_t _2k, mpz_t pm12k
 *   - Precomputed encryption of 1: enc1
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int labhe_setup(mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         		  const int l, const int k,
	         		  mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         		  mpz_t enc1,
	         		  gmp_randstate_t gmpRandState) 
{
	int rc;
	mpz_t one;

	rc=bhjl_gen(p,n,y,D,l,k,gmpRandState);

	if (rc != 0) { return 1; }

    bhjl_precom(_2k1,_2k,pm12k,p,k);

    mpz_init_set_ui(one,1);
    bhjl_encrypt(enc1,one,n,y,k,_2k,gmpRandState);

    mpz_clear(one);

    return 0;
}

/* 
 *Encryptor key generator for public-key LabHE-BHJL scheme
 * Inputs: 
 *   - BHJL public/precomputed parameters: n, y, k, _2k
 *   - State of GMP randomness generator
 * Outputs: 
 *   - Sender public/secret key (using BHJL to hide sk in pk)
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int labhe_gen(mpz_t pk,unsigned char *sk,
	             	const mpz_t n,const mpz_t y, const int k,
	             	const mpz_t _2k, 
	             	gmp_randstate_t gmpRandState) 
{
	FILE *fp;
	mpz_t sk_num;

	fp = fopen("/dev/urandom", "r");
	if (!fp) { return 1; }

	if (fread(sk, SK_SIZE, 1, fp) != 1)  { return 1; }
	if (fclose(fp)) { return 1; }

	mpz_init(sk_num);
	mpz_import (sk_num, SK_SIZE, 1, sizeof(sk[0]), 0, 0, sk);
	bhjl_encrypt(pk,sk_num,n,y,k,_2k,gmpRandState);
    mpz_clear(sk_num);
	return 0;
}

/*
 * Master key generator for symmetric LabHE-BHJL scheme
 * Inputs: 
 *   - Bit-length of BHJL modulus: l
 *   - Bit-length of BHJL messages: k
 *   - State of GMP randomness generator
 * Outputs: 
 *   - Secret PRF key sk[SK_SIZE]
 *   - Secret/public BHJL parameters p, n, y, D
 *   - Precomputed BHJL
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int labhe_gen_sk(unsigned char *sk,
			     	mpz_t p, mpz_t n, mpz_t y, mpz_t D, 
	         		const int l, const int k,
	         		mpz_t _2k1, mpz_t _2k, mpz_t pm12k, 
	         		mpz_t enc1,
	         		gmp_randstate_t gmpRandState) 
{
	FILE *fp;

	fp = fopen("/dev/urandom", "r");
	if (!fp) { return 1; }

	if (fread(sk, SK_SIZE, 1, fp) != 1)  { return 1; }
	if (fclose(fp)) { return 1; }

	labhe_setup(p,n,y,D,l,k,_2k1,_2k,pm12k,enc1,gmpRandState);
	
    return 0;
}

