#include <stdlib.h> 
#include <stdio.h>

#include "bench.h"
#include "prf.h"

#define TEST_NONCES 10

int main(int argc, char* argv[])
{
	long long before, after;
	FILE *fp;
	int i;
	unsigned char seed[SK_SIZE];
	unsigned char label[LABEL_SIZE] = { 0 };
	unsigned char nonces[NONCE_SIZE*TEST_NONCES];

	fp = fopen("/dev/urandom", "r");
	if (!fp) { exit(1); }

	if (fread(seed, sizeof(seed), 1, fp) != 1)  { exit(1); }
	if (fclose(fp)) { exit(1); }

	PRINT_ARRAY("seed: ", seed,sizeof(seed));

	before=cpucycles();
	for (i = 0; i < TEST_NONCES; i++) {
		*(int *)label=i;
		prf(nonces+NONCE_SIZE*i,label,seed);
	}
	after=cpucycles();

	PRINT_TIME("PRF",after,before);
	
	PRINT_ARRAY("nonces: ", nonces,sizeof(nonces));

	exit(0);
}
