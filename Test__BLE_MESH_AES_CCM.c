/*
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

#include <stdio.h>
#include "AES_CCM.h"

int main()
{
	int i=0;
	/*
 =============== Packet Vector #3 ==================
   AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
   Nonce =    00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5
   Total packet length = 33. [Input with 8 cleartext header octets==aditional data]
              00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
              10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F
              20
   Total packet length = 41. [Authenticated and Encrypted Output]
              00 01 02 03  04 05 06 07  51 B1 E5 F4  4A 19 7D 1D
              A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96
              57 4A DA A7  6F BD 9F B0  C5
    */    
	#define L_value 2 //size of Length field
	#define nonce_length_value (15-L_value) //size of nonce
	#define key_len_value 16 //sized of the key, for aes-128
	#define M_value 						8 //size of the authentication field
	#define Total_packet_length 			33 //the whole unencrypted packet, including the header(=size of IV index)
	#define	aad_len_value 					8 //size of the header(=size of IV index)
	#define plain_len_value (Total_packet_length-aad_len_value) //the message portion of the whole packet
	
	const size_t L = L_value;
	//C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
	const size_t key_len = key_len_value;
	u8 key[key_len_value] =  {
						0xC0, 0xC1, 0xC2, 0xC3, 
						0xC4, 0xC5, 0xC6, 0xC7,
					    0xC8, 0xC9, 0xCA, 0xCB, 
	 				    0xCC, 0xCD, 0xCE, 0xCF
						};
	
	//00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5
	const size_t M = M_value; //size of auth (i.e. MAC)
	u8 nonce[nonce_length_value] =  {
						0x00, 0x00, 0x00, 0x05,
	 				   	0x04, 0x03, 0x02, 0xA0,
	 				   	0xA1, 0xA2, 0xA3, 0xA4,
	  				   	0xA5
					};
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	//aditional data is the header i.e. initialization vector or IV or IVI (IV index in BLE mesh)
	//00 01 02 03  04 05 06 07
	const size_t aad_len = aad_len_value;
	u8 aad[aad_len_value] =  {      
			  			0x00, 0x01, 0x02, 0x03,
						0x04, 0x05, 0x06, 0x07,
						};
						
	//08 09 0A 0B  0C 0D 0E 0F 10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F 20
	const size_t plain_len = plain_len_value;
	u8 plain[plain_len_value] =  {    
			  			0x08, 0x09, 0x0A, 0x0B, 
						0x0C, 0x0D, 0x0E, 0x0F,
              			0x10, 0x11, 0x12, 0x13, 
						0x14, 0x15, 0x16, 0x17,
						0x18, 0x19, 0x1A, 0x1B, 
						0x1C, 0x1D, 0x1E, 0x1F,
						0x20
						};					
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	u8 crypt[plain_len]; 
	u8 auth[M]; 
	
	printf("Additional data||plain text is: \n");
	for( i=0 ; i<aad_len ; i++)	
		printf("%02x ", aad[i]);
	
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", plain[i]);	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	
	u8 x_enc[AES_BLOCK_SIZE], a_enc[AES_BLOCK_SIZE];
	
	aes_ccm_auth_start(key, M, L, nonce, aad, aad_len, plain_len, x_enc);
	aes_ccm_auth(key, plain, plain_len, x_enc);
	// Encryption 
	aes_ccm_encr_start(L, nonce, a_enc);
	aes_ccm_encr(key, L, plain, plain_len, crypt, a_enc);
	aes_ccm_encr_auth(key, M, x_enc, a_enc, auth);
	
		
	printf("\n\nAdditional data||Crypt text||Authentication tag is: \n");	
	for( i=0 ; i<aad_len ; i++)	
		printf("%02x ", aad[i]);
	
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", crypt[i]);
	
	for( i=0 ; i<M ; i++)	
		printf("%02x ", auth[i]);	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	u8 x_dcr[AES_BLOCK_SIZE], a_dcr[AES_BLOCK_SIZE]; u8 t_dcr[AES_BLOCK_SIZE];
	const size_t crypt_len = plain_len; //crypt length is the same as the plain length
	u8 recovered_plain[crypt_len];

	// Decryption //
	aes_ccm_encr_start(L, nonce, a_dcr);
	aes_ccm_decr_auth(key, M, a_dcr, auth, t_dcr);
	// plaintext = msg XOR (S_1 | S_2 | ... | S_n) //
	aes_ccm_encr(key, L, crypt, crypt_len, recovered_plain, a_dcr);
	aes_ccm_auth_start(key, M, L, nonce, aad, aad_len, crypt_len, x_dcr);
	aes_ccm_auth(key, recovered_plain, crypt_len, x_dcr);

	printf("\n\nDecryption Authentication is: \n");
	for( i=0 ; i<M ; i++)	
		printf("%02x ", t_dcr[i]);
	printf("\nAuthentication from recovered plain text is: \n");
	for( i=0 ; i<M ; i++)	
		printf("%02x ", x_dcr[i]);
	if (memcmp(x_dcr, t_dcr, M) == 0) 
		printf("\n%s\n", "Hooray!!! CCM: Authentication match!");
	else
		printf("\n%s\n", "Oh No! CCM: Authentication mismatch!");
	
	printf("\nAdditional data||recovered plain text is: \n");
	for( i=0 ; i<aad_len ; i++)	
		printf("%02x ", aad[i]);	
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", recovered_plain[i]);

	return 0;
}
