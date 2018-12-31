/*
    Original Author(s): GitHub contributors
    Edited by: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

//      #####     #####     #####     #####      #####     #####     #####     #####     #####      //
#include <stdio.h>
#include <string.h> //for memcpy()
#include <stdlib.h> //for free(), malloc()
#include "AES_CCM.h"

//      #####     #####     #####     #####      #####     #####     #####     #####     #####      //
//Internal function(s) added by the Great Alireza Sameni
Alireza_wpa_hexdump_key(const u8 str_data[], int str_data_size)
{
	int i;
	for(i=0 ; i<str_data_size ; i++)	
		printf("%02x ", str_data[i]);
	printf("\n");
}
//      #####     #####     #####     #####      #####     #####     #####     #####     #####      //
 void xor_aes_block(u8 *dst, const u8 *src)
{
	int i;
	u32 *d = (u32 *) dst;
	u32 *s = (u32 *) src;
	
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	
	
}

 void aes_ccm_auth_start( u8 *aes_key, size_t M, size_t L, const u8 *nonce,
			       const u8 *aad, size_t aad_len, size_t plain_len,
			       u8 *x)
{
	u8 aad_buf[2 * AES_BLOCK_SIZE];
	u8 b[AES_BLOCK_SIZE];

	/* Authentication */
	/* B_0: Flags | Nonce N | l(m) */
	b[0] = aad_len ? 0x40 : 0 /* Adata */;
	b[0] |= (((M - 2) / 2) /* M' */ << 3);
	b[0] |= (L - 1) /* L' */;
	memcpy(&b[1], nonce, 15 - L);
	WPA_PUT_BE16(&b[AES_BLOCK_SIZE - L], plain_len);

	//wpa_hexdump_key(MSG_EXCESSIVE, "CCM B_0", b, AES_BLOCK_SIZE);
	//printf("\n%s", "CCM B_0       : ");

	//Alireza_wpa_hexdump_key(b, AES_BLOCK_SIZE);
	
	//aes_encrypt(aes, b, x); /* X_1 = E(K, B_0) */
	AES_128(aes_key, b, x);
	

	if (!aad_len)
		return;

	WPA_PUT_BE16(aad_buf, aad_len);
	memcpy(aad_buf + 2, aad, aad_len);
	memset(aad_buf + 2 + aad_len, 0, sizeof(aad_buf) - 2 - aad_len);
	
	//printf("\n%s", "CCM B_1       : ");
	//Alireza_wpa_hexdump_key(aad_buf, AES_BLOCK_SIZE);
	xor_aes_block(aad_buf, x);
	//aes_encrypt(aes, aad_buf, x); /* X_2 = E(K, X_1 XOR B_1) */
	AES_128(aes_key, aad_buf, x);

	if (aad_len > AES_BLOCK_SIZE - 2) {
		//printf("\nCCM B_2       : ");
		//Alireza_wpa_hexdump_key(&aad_buf[AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		xor_aes_block(&aad_buf[AES_BLOCK_SIZE], x);
		/* X_3 = E(K, X_2 XOR B_2) */
		//aes_encrypt(aes, &aad_buf[AES_BLOCK_SIZE], x);
		AES_128(aes_key, &aad_buf[AES_BLOCK_SIZE], x);
	}
}


 void aes_ccm_auth( u8 *aes_key, const u8 *data, size_t len, u8 *x)
{
	size_t last = len % AES_BLOCK_SIZE;
	size_t i;

	for (i = 0; i < len / AES_BLOCK_SIZE; i++) {
		/* X_i+1 = E(K, X_i XOR B_i) */
		xor_aes_block(x, data);
		data += AES_BLOCK_SIZE;
		//aes_encrypt(aes, x, x);
		AES_128(aes_key, x, x);
	}
	if (last) {
		///////////////////////////////////////////////////////////////////
		for (i = 0; i < last; i++)
			x[i] ^= *data++;
		///////////////////////////////////////////////////////////////////
		
		//aes_encrypt(aes, x, x);
		AES_128(aes_key, x, x);
	}
}


 void aes_ccm_encr_start(size_t L, const u8 *nonce, u8 *a)
{
	/* A_i = Flags | Nonce N | Counter i */
	a[0] = L - 1; /* Flags = L' */
	memcpy(&a[1], nonce, 15 - L);
}


 void aes_ccm_encr( u8 *aes_key, size_t L, const u8 *in, size_t len, u8 *out,
			 u8 *a)
{
	size_t last = len % AES_BLOCK_SIZE;
	size_t i;

	/* crypt = msg XOR (S_1 | S_2 | ... | S_n) */
	for (i = 1; i <= len / AES_BLOCK_SIZE; i++) {
		WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], i);
		/* S_i = E(K, A_i) */
		//aes_encrypt(aes, a, out);
		AES_128(aes_key, a, out);
		xor_aes_block(out, in);
		out += AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
	}
	if (last) {
		WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], i);
		//aes_encrypt(aes, a, out);
		AES_128(aes_key, a, out);
		
		
		//////////////////////////////////////////////////////////////////////
		for (i = 0; i < last; i++)
			*out++ ^= *in++;
		//////////////////////////////////////////////////////////////////////
	}
}


 void aes_ccm_encr_auth( u8 *aes_key, size_t M, u8 *x, u8 *a, u8 *auth)
{
	size_t i;
	u8 tmp[AES_BLOCK_SIZE];

	//wpa_hexdump_key(MSG_EXCESSIVE, "CCM T", x, M);
	//printf("\n%s", "CCM T         : ");

	//Alireza_wpa_hexdump_key(x, M);
	/* U = T XOR S_0; S_0 = E(K, A_0) */
	WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], 0);
	//aes_encrypt(aes, a, tmp);
	AES_128(aes_key, a, tmp);
	
	///////////////////////////////////////////////////////////////////
	/* XOR zero-padded last block */
	for (i = 0; i < M; i++)
		auth[i] = x[i] ^ tmp[i];
	///////////////////////////////////////////////////////////////////

	//wpa_hexdump_key(MSG_EXCESSIVE, "CCM U", auth, M);
	//printf("\n%s", "CCM U         : ");	
	
	//Alireza_wpa_hexdump_key(auth, M);
}


 void aes_ccm_decr_auth( u8 *aes_key, size_t M, u8 *a, const u8 *auth, u8 *t)
{
	size_t i;
	u8 tmp[AES_BLOCK_SIZE];

	//wpa_hexdump_key(MSG_EXCESSIVE, "CCM U", auth, M);
	//printf("\n%s", "CCM U         : ");	
	
	//Alireza_wpa_hexdump_key(auth, M);
	/* U = T XOR S_0; S_0 = E(K, A_0) */
	WPA_PUT_BE16(&a[AES_BLOCK_SIZE - 2], 0);
	//aes_encrypt(aes, a, tmp);
	AES_128(aes_key, a, tmp);
	//printf("\nOutofXORBlock aes_ccm_decr_auth()\n");
	for (i = 0; i < M; i++)
		t[i] = auth[i] ^ tmp[i];
	//wpa_hexdump_key(MSG_EXCESSIVE, "CCM T", t, M);
	//printf("\n%s", "CCM T         : ");	
	
	//Alireza_wpa_hexdump_key(t, M);
}


/* AES-CCM with fixed L=2 and aad_len <= 30 assumption */
int aes_ccm_ae( u8 *aes_key, size_t key_len, const u8 *nonce,
	       size_t M, const u8 *plain, size_t plain_len,
	       const u8 *aad, size_t aad_len, u8 *crypt, u8 *auth)
{
	const size_t L = 2;
	
	//void *aes;

	u8 x[AES_BLOCK_SIZE], a[AES_BLOCK_SIZE];

	if (aad_len > 30 || M > AES_BLOCK_SIZE)
		return -1;

	//aes = aes_encrypt_init(key, key_len);
	
	//if (aes == NULL)
	//	return -1;

	//aes_ccm_auth_start(aes, M, L, nonce, aad, aad_len, plain_len, x);
	aes_ccm_auth_start(aes_key, M, L, nonce, aad, aad_len, plain_len, x);
	
	//aes_ccm_auth(aes, plain, plain_len, x);
	aes_ccm_auth(aes_key, plain, plain_len, x);
	
	/* Encryption */
	aes_ccm_encr_start(L, nonce, a);
	
	//aes_ccm_encr(aes, L, plain, plain_len, crypt, a);
	aes_ccm_encr(aes_key, L, plain, plain_len, crypt, a);
	
	//aes_ccm_encr_auth(aes, M, x, a, auth);
	aes_ccm_encr_auth(aes_key, M, x, a, auth);
	//////////	aes_encrypt_deinit(aes);

	return 0;
}


// AES-CCM with fixed L=2 and aad_len <= 30 assumption //
int aes_ccm_ad(u8 *aes_key, size_t key_len, const u8 *nonce,
	       size_t M, const u8 *crypt, size_t crypt_len,
	       const u8 *aad, size_t aad_len, const u8 *auth, u8 *plain)
{
	const size_t L = 2;
	u8 x[AES_BLOCK_SIZE], a[AES_BLOCK_SIZE];
	u8 t[AES_BLOCK_SIZE];

	if (aad_len > 30 || M > AES_BLOCK_SIZE)
		return -1;

	// Decryption //
	aes_ccm_encr_start(L, nonce, a);
	aes_ccm_decr_auth(aes_key, M, a, auth, t);

	// plaintext = msg XOR (S_1 | S_2 | ... | S_n) //
	aes_ccm_encr(aes_key, L, crypt, crypt_len, plain, a);

	aes_ccm_auth_start(aes_key, M, L, nonce, aad, aad_len, crypt_len, x);
	aes_ccm_auth(aes_key, plain, crypt_len, x);

	//////////	aes_encrypt_deinit(aes);

	if (memcmp(x, t, M) != 0) {
		//wpa_printf(MSG_EXCESSIVE, "CCM: Auth mismatch");
		//printf("\n%s\n", "CCM: Auth mismatch");
		return -1;
	}

	return 0;
}

//      #####     #####     #####     #####      #####     #####     #####     #####     #####      //













