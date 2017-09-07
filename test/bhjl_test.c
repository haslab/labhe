#include <stdlib.h> 
#include <stdio.h>
#include <gmp.h>

#include "bhjl.h"
#include "bhjl_gen.h"
#include "bench.h"

int main(int argc, char* argv[])
{
	mpz_t p, n, y, D,msg1, cph1, msg2, cph2, msgp, cpha, msga, aux, seed, _2k,_2k1,pm12k;
	long long before, after;
	int l, k;
	FILE *fp;
	unsigned char rand_buff[16];

	mpz_inits(p, n, y, D,msg1, cph1, msg2, cph2, msgp, cpha, msga, aux, seed, _2k,_2k1,pm12k,NULL);


	fp = fopen("/dev/urandom", "r");
	if (!fp) { exit(1); }

	if (fread(rand_buff, sizeof(rand_buff), 1, fp) != 1)  { exit(1); }
	if (fclose(fp)) { exit(1); }

	mpz_import(seed, sizeof(rand_buff), 1, sizeof(rand_buff[0]), 0, 0, rand_buff);

	gmp_randstate_t gmpRandState;
	gmp_randinit_default(gmpRandState);
	gmp_randseed(gmpRandState, seed);

	l = 2048;
	k = 128;

	// generation
	if (bhjl_gen(p,n,y,D,l,k,gmpRandState)!=0) { exit(1); } 

	bhjl_precom(_2k1,_2k, pm12k, p, k);

	// output key
	fprintf(stdout,"p=0x"); mpz_out_str(stdout,16,p); fprintf(stdout,"\n");
	fprintf(stdout,"n=0x"); mpz_out_str(stdout,16,n); fprintf(stdout,"\n");
	fprintf(stdout,"y=0x"); mpz_out_str(stdout,16,y); fprintf(stdout,"\n");
	fprintf(stdout,"D=0x"); mpz_out_str(stdout,16,D); fprintf(stdout,"\n");

	// Gen random plaintext and test encryption

	mpz_urandomb(msg1,gmpRandState,k);

	before=cpucycles();
	bhjl_encrypt(cph1,msg1,n,y,k,_2k,gmpRandState);
	after=cpucycles();

	fprintf(stdout,"\n\nEncrypt cycles=%lld\n\n",after-before);

	before=cpucycles();
    bhjl_decrypt(msgp,cph1,p,D,k,_2k1,pm12k);
	after=cpucycles();

	fprintf(stdout,"\n\nDecrypt cycles=%lld\n\n",after-before);

    fprintf(stdout,"\n\nm=0x");
	mpz_out_str(stdout,16,msg1); 	
	fprintf(stdout,"\n\nmp=0x");
	mpz_out_str(stdout,16,msgp); 		
	fprintf(stdout,"\n");

	if (mpz_cmp(msg1,msgp)!=0) {
		printf("Error.\n");
		exit(1);
	}
	else 
	{
		printf("OK!\n");
	}

	// Check homomorphic operation

	mpz_urandomb(msg2,gmpRandState,k);

	bhjl_encrypt(cph2,msg2,n,y,k,_2k,gmpRandState);

	before=cpucycles();
	bhjl_homadd(cpha,cph1,cph2,n);
	after=cpucycles();

	fprintf(stdout,"\n\nHom add cycles=%lld\n\n",after-before);

    bhjl_decrypt(msgp,cpha,p,D,k,_2k1,pm12k);

    mpz_add(aux,msg1,msg2);
    mpz_mod(msga,aux,_2k);

    fprintf(stdout,"\n\nma=0x");
	mpz_out_str(stdout,16,msga); 	
	fprintf(stdout,"\n\nmo=0x");
	mpz_out_str(stdout,16,msgp); 		
	fprintf(stdout,"\n");

	if (mpz_cmp(msga,msgp)!=0) {
		printf("Error.\n");
		exit(1);
	}
	else 
	{
		printf("OK!\n");
	}

	before=cpucycles();
	bhjl_homsmul(cpha,cph1,msg2,n);
	after=cpucycles();

	fprintf(stdout,"\n\nHom smul cycles=%lld\n\n",after-before);

    bhjl_decrypt(msgp,cpha,p,D,k,_2k1,pm12k);

    mpz_mul(aux,msg1,msg2);
    mpz_mod(msga,aux,_2k);

    fprintf(stdout,"\n\nma=0x");
	mpz_out_str(stdout,16,msga); 	
	fprintf(stdout,"\n\nmp=0x");
	mpz_out_str(stdout,16,msgp); 		
	fprintf(stdout,"\n");

	if (mpz_cmp(msga,msgp)!=0) {
		printf("Error.\n");
		exit(1);
	}
	else 
	{
		printf("OK!\n");
	}

    mpz_clears(p, n, y, D,msg1, cph1, msg2, cph2, msgp, cpha, msga, aux, seed, _2k,_2k1,pm12k,NULL);
    gmp_randclear(gmpRandState);

	exit(0);
}
