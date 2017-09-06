#include <stdlib.h>

#include "KeccakPRGWidth1600.h"

#include "prf.h"

/*  PRF based on Keccak hash function
 *  Inputs: key[SK_SIZE],label[LABEL_SIZE])
 *  Outputs: nonce[NONCE_SIZE]
 *  Computes: nonce = Keccak(key,label)
 *  Assumptions: all I/O pointers point to correctly allocated and disjoint regions. 
 */
int prf(unsigned char *nonce, const unsigned char *label, const unsigned char *key) {
	KeccakWidth1600_SpongePRG_Instance instance;

	KeccakWidth1600_SpongePRG_Initialize(&instance, 254);
	KeccakWidth1600_SpongePRG_Feed(&instance, key, SK_SIZE);
	KeccakWidth1600_SpongePRG_Feed(&instance, label, LABEL_SIZE);
	KeccakWidth1600_SpongePRG_Fetch(&instance, nonce, NONCE_SIZE);

	return 0;
}
