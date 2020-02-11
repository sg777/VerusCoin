#if __linux
#include <sys/syscall.h>
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h> 
#endif

#include <unistd.h>

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"
#include "internal.h"
#include "asn/OCTET_STRING.h"
#include "include/falcon/falcon.h"

struct CCType CC_Falcon512Type;


int cc_MakeFalcon512Signature(const unsigned char *msg32, const unsigned char *privateKey, unsigned char **signatureOut) {
  
    shake256_context rng;
    shake256_init_prng_from_system(&rng);

    void *pubkey, *sig;
    size_t pubkey_len, privkey_len, sig_len;
    size_t  tmpsd_len, tmpmp_len, tmpvv_len;
    uint8_t *tmpsd, *tmpmp, *tmpvv;

    unsigned logn = 9; // 9 is falcon 512
    pubkey_len = FALCON_PUBKEY_SIZE(logn); // not sure if we are using these lengths?
	privkey_len = FALCON_PRIVKEY_SIZE(logn);
	sig_len = FALCON_SIG_VARTIME_MAXSIZE(logn);
	
    tmpsd_len = FALCON_TMPSIZE_SIGNDYN(logn);
   	tmpmp_len = FALCON_TMPSIZE_MAKEPUB(logn);
    tmpvv_len = FALCON_TMPSIZE_VERIFY(logn);
       
    sig = malloc(sig_len);
    tmpsd = malloc(tmpsd_len);
	pubkey = malloc(pubkey_len);
    tmpmp = malloc(tmpmp_len);
    tmpvv = malloc(tmpvv_len);

    memset(sig, 0, sig_len);
    int error;
    error = falcon_make_public(pubkey, pubkey_len,
			privateKey, privkey_len, tmpmp, tmpmp_len);
		if (error != 0) {
			fprintf(stderr, "Falcon512 makepub failed: %d\n", error);
            return 0;
		}
    error = falcon_sign_dyn(&rng, sig, &sig_len,
			privateKey, privkey_len,
			(const void*)msg32, sizeof(msg32), 0, tmpsd, tmpsd_len);
     if (error != 0) {
			fprintf(stderr, "Falcon512 keygen failed: %d\n", error);
            return 0;
		}

    error = falcon_verify(sig, sig_len,
			pubkey, pubkey_len, (const void*)msg32, sizeof(msg32), tmpvv, tmpvv_len);
		if (error != 0) {
			fprintf(stderr, "Falcon512 verify failed: %d\n", error);
            return 0;
		}



    *signatureOut = calloc(1, FALCON_SIG_CT_SIZE(logn)); //not sure of length of falcon signture out are we using duynamic?

    memcpy(signatureOut,sig,sig_len);

    free(sig);
    free(tmpsd);
	free(pubkey);
    free(tmpmp);
    free(tmpvv);
    
    return 1;
}

int cc_MakeFalcon512KeyPair(unsigned char *privateKey, unsigned char *publicKey)
{
    shake256_context rng; uint8_t *tmpkg;
    unsigned logn = 9; // 9 is falcon 512
    shake256_init_prng_from_system(&rng);
    tmpkg = xmalloc(FALCON_TMPSIZE_KEYGEN(logn));

    //privateKey and publicKey need memory allocated to them before falcone_keygen_make can run
    int success = falcon_keygen_make(rng, logn, privateKey, FALCON_PRIVKEY_SIZE(logn),
			publicKey, FALCON_PUBKEY_SIZE(logn), tmpkg, FALCON_TMPSIZE_KEYGEN(logn));

    if (success != 0) {
			fprintf(stderr, "keygen failed: %d\n", success);
			return 0;
		}

    return 1;    
}

int cc_VerifyFalcon512Key(const unsigned char *msg32, const unsigned char *publicKey, unsigned char *signature){  
    
    shake256_context rng;
    shake256_init_prng_from_system(&rng);

    size_t pubkey_len, sig_len;
    size_t tmpmp_len, tmpvv_len;
    uint8_t *tmpvv;

    unsigned logn = 9; // 9 is falcon 512
    pubkey_len = FALCON_PUBKEY_SIZE(logn); // not sure if we are using these lengths?

	sig_len = FALCON_SIG_VARTIME_MAXSIZE(logn);
   	tmpmp_len = FALCON_TMPSIZE_MAKEPUB(logn);
    tmpvv_len = FALCON_TMPSIZE_VERIFY(logn);

    tmpvv = malloc(tmpvv_len);

   int  error = falcon_verify(signature, sig_len,
			publicKey, pubkey_len, (const void*)msg32, sizeof(msg32), tmpvv, tmpvv_len);
		if (error != 0) {
			fprintf(stderr, "Falcon512 verify failed: %d\n", error);
            return 0;
		}
}