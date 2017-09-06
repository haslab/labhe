#ifndef PRF_HEADER
#define PRF_HEADER

#define SK_SIZE 16 // 128 bits
#define LABEL_SIZE 16 // 128 bits
#define NONCE_SIZE 16 // 128 bits

int prf(unsigned char *nonce, const unsigned char *label, const unsigned char *key);

#endif