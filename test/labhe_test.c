#include <stdlib.h> 
#include <stdio.h>
#include <gmp.h>

#include "prf.h"
#include "bench.h"
#include "labhe.h"
#include "labhe_gen.h"

#define COUNT 1000

int main(int argc, char* argv[])
{
	mpz_t p, n, y, D,seed,pk1,pk2,_2k,_2k1,pm12k, enc1, t1, t2, mp,cred,b,m;
	long long before, after;
	int l, k,i;
	FILE *fp;
	unsigned char rand_buff[16];
	unsigned char sk1[SK_SIZE];
	unsigned char sk2[SK_SIZE];
	mpz_t *b_masks1, *eb_masks1, *cs1, *ms1;
	mpz_t *b_masks2, *eb_masks2, *cs2, *ms2;
	mpz_t *c;

	mpz_inits(p, n, y, D,seed,pk1,pk2,_2k,_2k1,pm12k, enc1, t1, t2, mp,cred,b,m,NULL);
	
	b_masks1=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	eb_masks1=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	cs1=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	ms1=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	b_masks2=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	eb_masks2=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	cs2=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	ms2=(mpz_t*)malloc(COUNT*sizeof(mpz_t));
	c=(mpz_t*)malloc(COUNT*sizeof(mpz_t));

	for (i=0;i<COUNT;i++) {
		mpz_inits(c[i],cs1[i],ms1[i],b_masks1[i],eb_masks1[i],cs2[i],ms2[i],b_masks2[i],eb_masks2[i],NULL);
	}

	fp = fopen("/dev/urandom", "r");
	if (!fp) { exit(1); }

	if (fread(rand_buff, sizeof(rand_buff), 1, fp) != 1)  { exit(1); }

	mpz_import(seed, sizeof(rand_buff), 1, sizeof(rand_buff[0]), 0, 0, rand_buff);

	gmp_randstate_t gmpRandState;
	gmp_randinit_default(gmpRandState);
	gmp_randseed(gmpRandState, seed);

	l = 2048;
	k = 128;

	// setup
	if (labhe_setup(p,n,y,D,l,k,_2k1,_2k,pm12k,enc1,gmpRandState)!=0) { exit(1); } 

	if (labhe_gen(pk1,sk1,n,y,k,_2k,gmpRandState)!=0) { exit(1); } 
	if (labhe_gen(pk2,sk2,n,y,k,_2k,gmpRandState)!=0) { exit(1); } 

	// output key
	fprintf(stdout,"p=0x"); mpz_out_str(stdout,16,p); fprintf(stdout,"\n");
	fprintf(stdout,"n=0x"); mpz_out_str(stdout,16,n); fprintf(stdout,"\n");
	fprintf(stdout,"y=0x"); mpz_out_str(stdout,16,y); fprintf(stdout,"\n");
	fprintf(stdout,"D=0x"); mpz_out_str(stdout,16,D); fprintf(stdout,"\n");

	fprintf(stdout,"PK1=0x"); mpz_out_str(stdout,16,pk1); fprintf(stdout,"\n");
	fprintf(stdout,"PK2=0x"); mpz_out_str(stdout,16,pk2); fprintf(stdout,"\n");

	for (i=0;i<COUNT;i++) {
		mpz_urandomb(ms1[i],gmpRandState,k);
	}

	for (i=0;i<COUNT;i++) {
		mpz_urandomb(ms2[i],gmpRandState,k);
	}

	before=cpucycles();
	labhe_encrypt_offline_batch(b_masks1,eb_masks1,0 /* start label */,COUNT,sk1,n,y,k,_2k,gmpRandState);
	labhe_encrypt_offline_batch(b_masks2,eb_masks2,COUNT /* start label */,COUNT,sk2,n,y,k,_2k,gmpRandState);
	after=cpucycles();

	fprintf(stdout,"\n\nOffline Encrypt cycles=%lld\n\n",after-before);

	before=cpucycles();
	labhe_encrypt_online_batch(cs1,b_masks1,ms1,COUNT,k);
	labhe_encrypt_online_batch(cs2,b_masks2,ms2,COUNT,k);
	after=cpucycles();

	fprintf(stdout,"\n\nOnline Encrypt cycles=%lld\n\n",after-before);

	before=cpucycles();
	labhe_decrypt_offline_ip(b,0 /* start label */,COUNT /* start label */,COUNT,pk1,pk2,p,D,k,_2k1,pm12k);
	after=cpucycles();

	fprintf(stdout,"\n\nOffline Decrypt cycles=%lld\n\n",after-before);

	before=cpucycles();
	labhe_hommul_lev0_batch(c,cs1,eb_masks1,cs2,eb_masks2,COUNT,n,k,enc1);
	after=cpucycles();

	fprintf(stdout,"\n\nMap cycles=%lld\n\n",after-before);

	before=cpucycles();
	labhe_homadd_lev1_batch(cred,c,COUNT,n);
	after=cpucycles();

	fprintf(stdout,"\n\nReduce cycles=%lld\n\n",after-before);

	before=cpucycles();
	labhe_decrypt_online1(m,cred,b,p,D,k,_2k1,pm12k);
	after=cpucycles();

	fprintf(stdout,"\n\nOnline Decrypt cycles=%lld\n\n",after-before);

	fprintf(stdout,"m=0x"); mpz_out_str(stdout,16,m); fprintf(stdout,"\n");

	mpz_set_ui(mp,0);

	for (i=0;i<COUNT;i++) {
		mpz_mul(t1,ms1[i],ms2[i]);
		mpz_add(t2,mp,t1);
		mpz_mod(mp,t2,_2k);
	}

	fprintf(stdout,"mp=0x"); mpz_out_str(stdout,16,mp); fprintf(stdout,"\n");

	if (mpz_cmp(m,mp)!=0) {
		printf("Error.\n");
		exit(1);
	}
	else 
	{
		printf("OK!\n");
	}

	if (fclose(fp)) { exit(1); }

    mpz_clears(p, n, y, D,seed,pk1,pk2,_2k,_2k1,pm12k, enc1, t1, t2, mp,cred,b,m,NULL);
    for (i=0;i<COUNT;i++) {
       mpz_clears(c[i],cs1[i],ms1[i],b_masks1[i],eb_masks1[i],cs2[i],ms2[i],b_masks2[i],eb_masks2[i], NULL);
    }
    gmp_randclear(gmpRandState);

	free(b_masks1);
	free(eb_masks1);
	free(cs1);
	free(ms1);
	free(b_masks2);
	free(eb_masks2);
	free(cs2);
	free(ms2);
	free(c);

	exit(0);
}
