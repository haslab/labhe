#ifndef LABHE_HEADER
#define LABHE_HEADER

int labhe_encrypt_offline_batch(mpz_t *b_masks, mpz_t *eb_masks, const int start_label, const int count,
								const unsigned char *sk,
	             				const mpz_t n,const mpz_t y, const int k,
	             				const mpz_t _2k, 
	             				gmp_randstate_t gmpRandState);

int labhe_encrypt_online_batch(mpz_t *cs,const mpz_t *b_masks,const mpz_t *ms,const int count,
	                                 const int k);

int labhe_decrypt_offline_indep(unsigned char *sk,
								const mpz_t pk, 
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k);

int labhe_decrypt_offline_ip(mpz_t b,
								const int start_label1, const int start_label2, const int count,
								const mpz_t pk1, const mpz_t pk2,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k);

int labhe_decrypt_offline_sum0(mpz_t b,
								const int start_label, const int count,
								const mpz_t pk, 
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k);

int labhe_decrypt_offline_sum0_sk(mpz_t b, const unsigned char* sk,
								const int start_label, const int count,
								const int k);

int labhe_decrypt_offline_ip_sk(mpz_t b, const unsigned char*sk1, const unsigned char*sk2, 
								const int start_label1, const int start_label2, const int count,
								const int k, const mpz_t _2k1);

int labhe_decrypt_online1(mpz_t m, const mpz_t C,const mpz_t b,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k);

int labhe_decrypt_online0(mpz_t m, const mpz_t c,const mpz_t b,
	             				const int k);

int labhe_decrypt_nooff0(mpz_t m, const mpz_t mb,const mpz_t c,
	             				const mpz_t p,const mpz_t D,const int k,
	             				const mpz_t _2k1,const mpz_t pm12k);

int labhe_hommul_lev0_batch(mpz_t *c,
	                              const mpz_t *bm1, const mpz_t *c1, const mpz_t *bm2, const mpz_t *c2,const int count,
	                              const mpz_t n, const int k, const mpz_t enc1);

int labhe_homadd_lev0_batch(mpz_t bmred, mpz_t cred,
	                              const mpz_t *bm, const mpz_t *c, const int count,
	                              const int k, const mpz_t n);

int labhe_homadd_lev0_batch_flat(mpz_t bmred, 
	                              const mpz_t *bm, const int count,
	                              const int k, const mpz_t n);

int labhe_homadd_lev1_batch(mpz_t cred, const mpz_t *c,const int count, 
								  const mpz_t n);


int labhe_homsub_lev1(mpz_t csub, const mpz_t c1, const mpz_t c2, 
								  const mpz_t n);

int labhe_homsmul_lev1(mpz_t cres, const mpz_t c, const mpz_t s, 
								  const mpz_t n) ;
#endif