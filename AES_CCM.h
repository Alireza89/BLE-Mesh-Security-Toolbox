/*
    Original Author(s): GitHub contributors
    Edited by: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

#ifndef 	AES_CCM_header
	#define AES_CCM_header
	#include "AES_128.h"
	#define AES_BLOCK_SIZE 16
	#define AES_PRIV_SIZE (4 * 44)
	
	typedef unsigned char u8;
	typedef unsigned short u16;
	typedef unsigned int u32;
	
	#define WPA_PUT_BE16(a, val)			\
		do {					\
			(a)[0] = ((u16) (val)) >> 8;	\
			(a)[1] = ((u16) (val)) & 0xff;	\
		} while (0)
	
	//      #####     #####     #####     #####      #####     #####     #####     #####     #####      //
	void xor_aes_block(u8 *dst, const u8 *src);
	void aes_ccm_auth_start( u8 *aes_key, size_t M, size_t L, const u8 *nonce,
				       const u8 *aad, size_t aad_len, size_t plain_len, u8 *x);
	void aes_ccm_auth( u8 *aes_key, const u8 *data, size_t len, u8 *x);
	void aes_ccm_encr_start(size_t L, const u8 *nonce, u8 *a);
	void aes_ccm_encr( u8 *aes_key, size_t L, const u8 *in, size_t len, u8 *out, u8 *a);
	void aes_ccm_encr_auth( u8 *aes_key, size_t M, u8 *x, u8 *a, u8 *auth);
	void aes_ccm_decr_auth( u8 *aes_key, size_t M, u8 *a, const u8 *auth, u8 *t);
	/* AES-CCM with fixed L=2 and aad_len <= 30 assumption */
	int aes_ccm_ae( u8 *aes_key, size_t key_len, const u8 *nonce,
		       size_t M, const u8 *plain, size_t plain_len, const u8 *aad, size_t aad_len, u8 *crypt, u8 *auth);
	// AES-CCM with fixed L=2 and aad_len <= 30 assumption //
	int aes_ccm_ad(u8 *aes_key, size_t key_len, const u8 *nonce,
		       size_t M, const u8 *crypt, size_t crypt_len, const u8 *aad, size_t aad_len, const u8 *auth, u8 *plain);
#endif	       
	       

