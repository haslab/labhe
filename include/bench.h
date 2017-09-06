#ifndef BHJL_BENCH
#define BHJL_BENCH

#define PRINT_ARRAY(a,b,n) \
	{  fprintf(stdout,"%s",a); \
	   for (int _i = 0; _i < n; _i++) \
		fprintf(stdout,"%02X", b[_i]); \
		fprintf(stdout,"\n\n"); \
	}

#define PRINT_TIME(e,b,a) fprintf(stdout,"%s cycles: %lld\n\n",e,a-b)

long long cpucycles(void);

#endif
