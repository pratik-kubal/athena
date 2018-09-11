#include<wmmintrin.h>
#include<stdint.h>
#include<string.h>
#include<stdio.h>

void main(){
	// Using Pre Defined Key
	uint64_t _k[2] __attribute__((aligned(16))) = { 0x73C72C94F441776D, 0xBA547024B4D4ED70 };
	uint64_t _out[2] __attribute__((aligned(16))) = { 0, 0 };
	
	__m128i aes128_keyexpand(__m128i key, __m128i keygened)
	{
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
		return _mm_xor_si128(key, keygened);
	}

	#define KEYEXP(K, I) aes128_keyexpand(K, _mm_aeskeygenassist_si128(K, I))

	/* The initial part of the expanded key is the key itself. */
        __m128i K0  = _mm_load_si128((__m128i *)(_k));
	/* then every step generate more part of the key */
	__m128i K1  = KEYEXP(K0, 0x01);
        __m128i K2  = KEYEXP(K1, 0x02);
        __m128i K3  = KEYEXP(K2, 0x04);
        __m128i K4  = KEYEXP(K3, 0x08);
        __m128i K5  = KEYEXP(K4, 0x10);
        __m128i K6  = KEYEXP(K5, 0x20);
        __m128i K7  = KEYEXP(K6, 0x40);
        __m128i K8  = KEYEXP(K7, 0x80);
        __m128i K9  = KEYEXP(K8, 0x1B);
        __m128i K10 = KEYEXP(K9, 0x36);

        _mm_store_si128((__m128i *) _out, K0);
    	for (int i = 0; i < 2; i++) {
        	printf("%llu", _out[i]);
    	}
    	printf("\n");
}
