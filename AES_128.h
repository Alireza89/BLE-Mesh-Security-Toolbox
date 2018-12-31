/*
    Original Author(s): GitHub contributors
    Edited by: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

#ifndef 	AES_128_header
	#define AES_128_header
	#include <stdint.h>
	#define AES_keyExpSize 176
	struct AES_ctx
	{
	  uint8_t RoundKey[AES_keyExpSize];
	};
	
	void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
	
	// buffer size is exactly AES_BLOCKLEN=16 bytes; 
	// you need only AES_init_ctx as IV is not used in ECB 
	void AES_ECB_encrypt(struct AES_ctx* ctx, const uint8_t* buf);
	void AES_ECB_decrypt(struct AES_ctx* ctx, const uint8_t* buf);
	void AES_128(unsigned char *key, unsigned char *Y, unsigned char *X);
#endif
