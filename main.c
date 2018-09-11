// Compile with  gcc main.c -march=native -maes -o hardware_aes
// NOTE: This is a proof of concept aes code, it basically displays the message,key,ciphertext,and then decodes the ciphertext to get back the message or plaintext
// Reference: http://tab.snarc.org/posts/technical/2012-04-12-aes-intrinsics.html
#include<wmmintrin.h>
#include<stdint.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include <inttypes.h>

int main(){
	
	// Using Pre Defined Key
	uint8_t _k[16] __attribute__((aligned(2))) = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xFF,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0xFF};
	uint8_t _out[16] __attribute__((aligned(2))) = { 0, 0 };
	uint8_t _m[16] __attribute__((aligned(2))) = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0xFF};
	//uint64_t _ct[2] __attribute__((aligned(16))) = { 0, 0 };
	
	printf("Message is:\n");
    	for (int i = 0; i < 16; i++) {
        	printf("%x", _m[i]);
    	}
    	printf("\n");
    	
	printf("Key to be Used is:\n");
    	for (int i = 0; i < 16; i++) {
        	printf("%x", _k[i]);
    	}
    	printf("\n");
	
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
    	
    	__m128i m = _mm_load_si128((const __m128i *) _m);
    	 m = _mm_xor_si128(m, K0);
	/* then do 9 rounds of aesenc, using the associated key parts */
        m = _mm_aesenc_si128(m, K1);
        m = _mm_aesenc_si128(m, K2);
        m = _mm_aesenc_si128(m, K3);
        m = _mm_aesenc_si128(m, K4);
        m = _mm_aesenc_si128(m, K5);
        m = _mm_aesenc_si128(m, K6);
        m = _mm_aesenc_si128(m, K7);
        m = _mm_aesenc_si128(m, K8);
        m = _mm_aesenc_si128(m, K9);
	/* then 1 aesenclast rounds */
        m = _mm_aesenclast_si128(m, K10);
	/* and then we store the result in an out variable */
	
	printf("The CipherText is as follows:\n");
        _mm_store_si128((__m128i *) _out, m);
	for (int i = 0; i < 16; i++) {
        	printf("%x", _out[i]);
    	}
    	printf("\n");
    	
    	printf("Decryption:\n");

	// Inverse Key Gen
    	
    	__m128i INVK1 = _mm_aesimc_si128(K9);
    	__m128i INVK2 = _mm_aesimc_si128(K8);
    	__m128i INVK3 = _mm_aesimc_si128(K7);
    	__m128i INVK4 = _mm_aesimc_si128(K6);
    	__m128i INVK5 = _mm_aesimc_si128(K5);
    	__m128i INVK6 = _mm_aesimc_si128(K4);
    	__m128i INVK7 = _mm_aesimc_si128(K3);
    	__m128i INVK8 = _mm_aesimc_si128(K2);
    	__m128i INVK9 = _mm_aesimc_si128(K1);
    	
    	__m128i ct = _mm_load_si128((const __m128i *) _out);
    	ct = _mm_xor_si128(ct,K10);
    	ct = _mm_aesdec_si128(ct,INVK1);
    	ct = _mm_aesdec_si128(ct,INVK2);
    	ct = _mm_aesdec_si128(ct,INVK3);
    	ct = _mm_aesdec_si128(ct,INVK4);
    	ct = _mm_aesdec_si128(ct,INVK5);
    	ct = _mm_aesdec_si128(ct,INVK6);
    	ct = _mm_aesdec_si128(ct,INVK7);
    	ct = _mm_aesdec_si128(ct,INVK8);
    	ct = _mm_aesdec_si128(ct,INVK9);
    	ct = _mm_aesdeclast_si128(ct,K0);
    	
    	printf("The Plaintext is as follows:\n");
    	_mm_store_si128((__m128i *) _out, ct);
    		for (int i = 0; i < 16; i++) {
        	printf("%x", _out[i]);
    	}
    	printf("\n");
}
