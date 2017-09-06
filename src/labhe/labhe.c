#include <gmp.h>
#include <stdlib.h>

#include "prf.h"
#include "bhjl.h"
#include "labhe.h"

/*
 * Batch Labelled HE encryption for #count messages using sequencial
 * labels starting at start_label. This is the offline stage.
 * Inputs: 
 *   - Batch parameters: start_label, count
 *   - The secret key of the encryptor: sk (use labhe_gen to create on the fly)
 *   - BHJK public/precomputed parameters: n, y, k, _2k
 *   - State of GMP randomness generator
 * Outputs:
 *   - #count instances of the precomputed parameters b_masks and 
 *     eb_masks (eb_masks are part of the final ciphertext)
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 *   - GMP randomness state is managed by the caller
 */
int labhe_encrypt_offline_batch(mpz_t *b_masks, mpz_t *eb_masks, const int start_label, const int count,
								const unsigned char *sk,
	             				const mpz_t n,const mpz_t y, const int k,
	             				const mpz_t _2k, 
	             				gmp_randstate_t gmpRandState) 
{
	int i;
	mpz_t b_mask_num;
	unsigned char b_mask_buf[NONCE_SIZE], label[LABEL_SIZE];

	for(i=0;i<LABEL_SIZE;i++) { label[i] = 0; }

	mpz_init(b_mask_num);
	for (i=0;i<count;i++) {
		*(int *)label = start_label + i;
		prf(b_mask_buf,label,sk);
		mpz_import(b_mask_num, NONCE_SIZE, 1, sizeof(b_mask_buf[0]), 0, 0, b_mask_buf);
		bhjl_encrypt(eb_masks[i],b_mask_num,n,y,k,_2k,gmpRandState);
		mpz_sub(b_masks[i],_2k,b_mask_num);
	}
  	mpz_clear(b_mask_num);

	return 0;
}

/*
 * Batch Labelled HE encryption for #count messages using sequencial
 * labels starting at start_label. This is the online stage.
 * Inputs: 
 *   - Batch parameter: count
 *   - #count instances of the precomputed parameter b_masks
 *   - #count messages to encrypt
 *   - BHJK public parameter: k
 * Outputs:
 *   - #count masked messages: cs
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_encrypt_online_batch(mpz_t *cs,const mpz_t *b_masks,const mpz_t *ms,const int count,
									 const int k) 
{
	int i;
	for (i=0;i<count;i++) {
		mpz_add(cs[i],b_masks[i],ms[i]);
		mpz_clrbit(cs[i],k);
	}
	return 0;
}

/*
 * LABHE decryption: offline, function-independent stage where
 * encryptor secret key is recovered.
 * Inputs: 
 *   - Encryptor public key: pk
 *   - BHJK public/secret/precomputed parameters: p,D,k,_2k1,pm12k
 * Outputs:
 *   - Recovered encryptor key: sk
 * Assumptions: 
 *   - Public key is in valid BHJK ciphertext range 0 <= pk < n
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_offline_indep(unsigned char *sk,
								const mpz_t pk, 
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k) {
	int i;
	size_t sk_size;
	mpz_t sk_num;
	unsigned char *sk_gmp_alloc, *aux_ptr;

  	mpz_init(sk_num);

    bhjl_decrypt(sk_num,pk,p,D,k,_2k1,pm12k);
	sk_gmp_alloc=mpz_export(NULL, &sk_size, 1, sizeof(unsigned char), 0, 0, sk_num);
	if (sk_size != SK_SIZE) { return 1; };

    aux_ptr = sk_gmp_alloc;
    for(i=SK_SIZE;i>0;i--)
    	*sk++ = *aux_ptr++;

  	mpz_clear(sk_num);
  	free(sk_gmp_alloc);

	return 0;
}

/*
 * LABHE decryption: offline function-dependent stage for the
 * particular case of inner product computation.
 * Inputs: 
 *   - Encryptor secret keys: sk1, sk2 (could be the same if in the symmetric case)
 *   - Starting labels for each batch of ciphertexts: start_label1, start_label2
 *   - Lengths of both batches/vectors: count
 *   - Public/precomputed BHJK parameters: k, _2k1
 * Outputs:
 *   - Precomputed mask b
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_offline_ip_sk(mpz_t b, const unsigned char*sk1, const unsigned char*sk2, 
								const int start_label1, const int start_label2, const int count,
								const int k, const mpz_t _2k1) 
{
	int i;
	mpz_t b_mask_num1,b_mask_num2, t1, t2,_2km1;
	unsigned char b_mask_buf1[NONCE_SIZE], label1[LABEL_SIZE];
	unsigned char b_mask_buf2[NONCE_SIZE], label2[LABEL_SIZE];

	for(i=0;i<LABEL_SIZE;i++) { label1[i] = 0; }
	for(i=0;i<LABEL_SIZE;i++) { label2[i] = 0; }

	mpz_init(t1);
	mpz_init(_2km1);
	mpz_mul_ui(t1,_2k1,2);
	mpz_sub_ui(_2km1,t1,1);

	mpz_init(b_mask_num1);
	mpz_init(b_mask_num2);
	mpz_init(t2);
	mpz_set_ui(b,0);
	for (i=0;i<count;i++) {
		*(int *)label1 = start_label1 + i;
		prf(b_mask_buf1,label1,sk1);
		*(int *)label2 = start_label2 + i;
		prf(b_mask_buf2,label2,sk2);
		mpz_import(b_mask_num1, NONCE_SIZE, 1, sizeof(b_mask_buf1[0]), 0, 0, b_mask_buf1);
		mpz_import(b_mask_num2, NONCE_SIZE, 1, sizeof(b_mask_buf2[0]), 0, 0, b_mask_buf2);
		mpz_mul(t1,b_mask_num1,b_mask_num2);
		mpz_add(t2,b,t1);
		mpz_and(b,_2km1,t2);
	}	

  	mpz_clears(b_mask_num1,b_mask_num2, t1, t2,_2km1, NULL);	

	return 0;
}

/*
 * LABHE decryption: full offline stage for the
 * particular case of inner product computation.
 * Inputs: 
 *   - Encryptor public keys: pk1, pk2 
 *   - Starting labels for each batch of ciphertexts: start_label1, start_label2
 *   - Lengths of both batches/vectors: count
 *   - BHJK public/secret/precomputed parameters: p,D,k,_2k1,pm12k
 * Outputs:
 *   - Precomputed mask b
 * Assumptions: 
 *   - Public keys are in valid BHJK ciphertext range 0 <= pk1,pk2 < n
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_offline_ip(mpz_t b,
								const int start_label1, const int start_label2, const int count,
								const mpz_t pk1, const mpz_t pk2,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k){
	unsigned char sk1[SK_SIZE], sk2[SK_SIZE];
	labhe_decrypt_offline_indep(sk1,pk1,p,D,k,_2k1,pm12k);
	labhe_decrypt_offline_indep(sk2,pk2,p,D,k,_2k1,pm12k);
	labhe_decrypt_offline_ip_sk(b,sk1,sk2,start_label1,start_label2,count,k,_2k1);
	return 0;
}

/*
 * LABHE decryption: offline function-dependent stage for the
 * particular case of summing a vector of 0-level encrypted 
 * messages.
 * Inputs: 
 *   - Encryptor secret key: sk
 *   - Starting label for batch of ciphertexts: start_label
 *   - Length of batch/vector: count
 *   - Public BHJK parameter: k
 * Outputs:
 *   - Precomputed mask b
 * Assumptions: 
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_offline_sum0_sk(mpz_t b, const unsigned char* sk,
								const int start_label, const int count,
								const int k)
{
	int i;
	mpz_t b_mask_num, t;
	unsigned char b_mask_buf[NONCE_SIZE], label[LABEL_SIZE];

	for(i=0;i<LABEL_SIZE;i++) { label[i] = 0; }

	mpz_init(t);
	mpz_init(b_mask_num);
  	mpz_set_ui(b, 0);
	for(i=0;i<count;i++) {
		*(int *)label = start_label + i;
		prf(b_mask_buf,label,sk);
		mpz_import(b_mask_num, NONCE_SIZE, 1, sizeof(b_mask_buf[0]), 0, 0, b_mask_buf);
		mpz_add(t,b,b_mask_num);
		mpz_clrbit(t,k);
		mpz_set(b,t);
	}	

	mpz_clears(b_mask_num, t, NULL);
	
	return 0;
}

/*
 * LABHE decryption: full offline stage for the
 * particular case of of summing a vector of 0-level encrypted 
 * messages.
 * Inputs: 
 *   - Encryptor public key: pk
 *   - Starting label for batch of ciphertexts: start_label
 *   - Length of batches/vector: count
 *   - BHJK public/secret/precomputed parameters: p,D,k,_2k1,pm12k
 * Outputs:
 *   - Precomputed mask b
 * Assumptions: 
 *   - Public key is in valid BHJK ciphertext range 0 <= pk < n
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_offline_sum0(mpz_t b,
								const int start_label, const int count,
								const mpz_t pk, 
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k){
	unsigned char sk[SK_SIZE];
	labhe_decrypt_offline_indep(sk,pk,p,D,k,_2k1,pm12k);
	labhe_decrypt_offline_sum0_sk(b,sk,start_label,count,k);
	return 0;
}

/*
 * LABHE decryption: online stage for 1-level encrypted 
 * result.
 * Inputs: 
 *   - Level-1 ciphertext: c
 *   - Precomputed mask: b
 *   - BHJK public/secret/precomputed parameters: p,D,k,_2k1,pm12k
 * Outputs:
 *   - Decrypted message: m
 * Assumptions: 
 *   - Ciphertext is in valid BHJK ciphertext range 0 <= pk < n
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_online1(mpz_t m, const mpz_t c,const mpz_t b,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k) 
{
	mpz_t t1;
	mpz_init(t1);
	bhjl_decrypt(t1,c,p,D,k,_2k1,pm12k);
	mpz_add(m,t1,b);
	mpz_clrbit(m,k);
  	mpz_clear(t1);
	return 0;
}

/*
 * LABHE decryption: online stage for 0-level encrypted 
 * result.
 * Inputs: 
 *   - Level-0 ciphertext: c
 *   - Precomputed mask: b
 *   - BHJK public/secret/precomputed parameters: k
 * Outputs:
 *   - Decrypted message: m
 * Assumptions: 
 *   - Ciphertext is in valid BHJK message range 0 <= c < 2^{k}
 *   - all I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_online0(mpz_t m, const mpz_t c,const mpz_t b,
	             				const int k) 
{
	mpz_t t;
	mpz_init(t);
	mpz_add(t,c,b);
	mpz_clrbit(t,k);
	mpz_set(m,t);
  	mpz_clear(t);
	return 0;
}

/*
 * LABHE decryption: full procedure for fresh 0-level encrypted 
 * result.
 * Inputs: 
 *   - Level-0 ciphertext: c, mb
 *   - BHJK public/secret/precomputed parameters: p,D,k,_2k1,pm12k
 * Outputs:
 *   - Decrypted message: m
 * Assumptions: 
 *   - Ciphertext is in valid range 0 <= mb < 2^{k}, 0 <= c < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_decrypt_nooff0(mpz_t m, const mpz_t mb,const mpz_t c,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k) 
{
	mpz_t t1;
	mpz_init(t1);
	bhjl_decrypt(t1,c,p,D,k,_2k1,pm12k);
	mpz_add(m,t1,mb);
	mpz_clrbit(m,k);
  	mpz_clear(t1);
	return 0;
}

/*
 * LABHE batch homomorphic multiplication.
 * Inputs: 
 *   - Size of batch: count
 *   - Many pairs of level-0 ciphertexts: bm1[], c1[], mb2[], c2[]
 *   - BHJK public/secret/precomputed parameters: n,k, enc1
 * Outputs:
 *   - Many level 1 ciphertexts: c
 * Assumptions: 
 *   - Ciphertexts are in valid range 0 <= bm1[],bm2[] < 2^{k}, 0 <= c1[],c2[] < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_hommul_lev0_batch(mpz_t *c,
	                           const mpz_t *bm1, const mpz_t *c1, const mpz_t *bm2, const mpz_t *c2,const int count,
	                           const mpz_t n, const int k, const mpz_t enc1) 
{
	int i;
	mpz_t t1,t2,t3;

  	mpz_inits(t1,t2,t3,NULL);

	for(i=0;i<count;i++) {
		bhjl_homsmul(t1,enc1,bm1[i],n);
		bhjl_homsmul(t2,t1,bm2[i],n);
		bhjl_homsmul(t1,c1[i],bm2[i],n);
		bhjl_homadd(t3,t1,t2,n);
		bhjl_homsmul(t1,c2[i],bm1[i],n);
		bhjl_homadd(c[i],t1,t3,n);
	}

  	mpz_clears(t1,t2,t3,NULL);

	return 0;
}

/*
 * LABHE batch homomorphic level 0 addition.
 * Inputs: 
 *   - Size of batch: count
 *   - Many level-0 ciphertexts: bm[], c[]
 *   - BHJK public/secret/precomputed parameters: n,k
 * Outputs:
 *   - One level 0 ciphertext: bmred, cred
 * Assumptions: 
 *   - Ciphertexts are in valid range 0 <= bm[] < 2^{k}, 0 <= c[] < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_homadd_lev0_batch(mpz_t bmred, mpz_t cred,
	                              const mpz_t *bm, const mpz_t *c, const int count,
	                              const int k, const mpz_t n) 
{
	int i;
	mpz_t t;
	mpz_init(t);
	mpz_set(bmred,bm[0]);
	mpz_set(cred,c[0]);
	for(i=1;i<count;i++) {
		mpz_add(t,bmred,bm[i]);
		mpz_clrbit(t,k);
		mpz_set(bmred,t);
		bhjl_homadd(t,cred,c[i],n);
		mpz_set(cred,t);
	}
 	mpz_clear(t);
	return 0;
}

/*
 * LABHE batch homomorphic level 0 addition 
 * (no further homomorphic multiplication intended)
 * Inputs: 
 *   - Size of batch: count
 *   - Many partial level-0 ciphertexts: bm[]
 *   - BHJK public/secret/precomputed parameters: n,k
 * Outputs:
 *   - One partial level 0 ciphertext: bmred
 * Assumptions: 
 *   - Partial ciphertexts are in valid range 0 <= bm[] < 2^{k}
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_homadd_lev0_batch_flat(mpz_t bmred, 
	                              const mpz_t *bm, const int count,
	                              const int k, const mpz_t n) 
{
	int i;
	mpz_t t;
	mpz_init(t);
	mpz_set(bmred,bm[0]);
	for(i=1;i<count;i++) {
		mpz_add(t,bmred,bm[i]);
		mpz_clrbit(t,k);
		mpz_set(bmred,t);
	}

  	mpz_clear(t);

	return 0;
}

/*
 * LABHE batch homomorphic level 1 addition 
 * Inputs: 
 *   - Size of batch: count
 *   - Many level-1 ciphertexts: c[]
 *   - BHJK public/secret/precomputed parameters: n
 * Outputs:
 *   - One level 1 ciphertext: cred
 * Assumptions: 
 *   - Input ciphertext is in valid range 0 <= c < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_homadd_lev1_batch(mpz_t cred, const mpz_t *c,const int count, 
								  const mpz_t n) 
{
	int i;
	mpz_t t;
    mpz_init(t);
	mpz_set(cred,c[0]);
	for(i=1;i<count;i++) {
		bhjl_homadd(t,cred,c[i],n);
		mpz_set(cred,t);
	}
  	mpz_clear(t);
	return 0;
}

/*
 * LABHE homomorphic level 1 subtraction 
 * Inputs: 
 *   - Two level-1 ciphertexts: c1,c2
 *   - BHJK public/secret/precomputed parameters: n
 * Outputs:
 *   - One level 1 ciphertext: cred
 * Assumptions: 
 *   - Input ciphertexts are in valid range 0 <= c1,c2 < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_homsub_lev1(mpz_t csub, const mpz_t c1, const mpz_t c2, 
								  const mpz_t n) 
{
	bhjl_homsub(csub,c1,c2,n);
	return 0;
}

/*
 * LABHE homomorphic level 1 scalar multiplication 
 * Inputs: 
 *   - One level-1 ciphertext: c
 *   - Scalar: s
 *   - BHJK public/secret/precomputed parameters: n
 * Outputs:
 *   - One level 1 ciphertext: cres
 * Assumptions: 
 *   - Input ciphertext are in valid range 0 <= c < n
 *   - All I/O pointers are allocated and initialized by caller
 */
int labhe_homsmul_lev1(mpz_t cres, const mpz_t c, const mpz_t s, 
								  const mpz_t n) 
{
	bhjl_homsmul(cres,c,s,n);
	return 0;
}
