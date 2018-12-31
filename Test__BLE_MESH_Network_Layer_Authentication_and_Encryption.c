/*
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

/**
Network layer authentication and encryption
The destination address and the TransportPDU are encrypted and authenticated using AES-CCM. 
This is identical to the way that Bluetooth low energy encryption and authentication works.
All Network PDUs are encrypted using an Encryption Key that is derived from a network key

inputs: 
Network_Nonce 
Encryption_Key 
DST_concat_with_TransportPDU
note: There is no additional data as header!!!!!

outputs:
Encrypted_Data as EncDST_concat_with_EncTransportPDU,
NetMIC which is the authenticated Tag and is 4 Bytes for the access messages and
is 8 Bytes for the Control messages
**/

#include <stdio.h>
#include "aes_ccm.h"

int main()
{
	int i=0; 
	#define L_value 2 //size of Length field
	#define nonce_length_value (15-L_value) //size of nonce
	#define key_len_value 16 //sized of the key, for aes-128
	
	#define M_value 						4 //size of the authentication field
											  //i.e. NetMIC Size : 64 bits or 32 bits
											  //4 octets for the access messages
											  //8 octets for the Control messages
	
	#define TranportPDU_length_value		9 //TranportPDU has a length from 1 to (16 for access 12 for control)
	#define DST_length_value				2 //Destination address has a fixed length of 2 octets
	
	#define Total_packet_length 			DST_length_value + TranportPDU_length_value 
	#define	aad_len_value 					0 //There is no cleartext header in this specifications!
	#define plain_len_value (Total_packet_length-aad_len_value) //the message portion of the whole packet
	
	
	const size_t L = L_value;
	
	const size_t key_len = key_len_value;
	//EncryptionKey : ca 6f 70 19 e9 bd f4 85 9d 53 27 c8 92 2e cd 09
	u8 EncryptionKey[key_len_value] =  {
						0xca, 0x6f, 0x70, 0x19, 
						0xe9, 0xbd, 0xf4, 0x85,
					    0x9d, 0x53, 0x27, 0xc8, 
	 				    0x92, 0x2e, 0xcd, 0x09
						};
	
	
	const size_t M = M_value; //size of auth (i.e. MAC)
	//Network Nonce : 00 03 00 00 00 00 17 00 00 00 00 00 00
	
	//Network_Nonce = 
	//Nonce_Type||CTL_and_TTL||SEQ||SRC||Pad||IV_index
	//Nonce_Type = 0x00 for the Network Nonce Type
	//CTL_and_TTL = CTL||TTL
	//Pad = 0x0000
	
	//Nonce_Type     = 00
	//CTL_and_TTL    = 03
	//SEQ 			 = 00 00 00
	//SRC			 = 00 17
	//Pad			 = 00 00
	//IV_index		 = 00 00 00 00
	//Network Nonce  = 00 03 00 00 00 00 17 00 00 00 00 00 00
	u8 NetNonce[nonce_length_value] =  {
						0x00, 
						0x03, 
						0x00, 0x00, 0x00, 
						0x00, 0x17, 
						0x00, 0x00, 
						0x00, 0x00, 0x00, 0x00
					};
								
	printf("Nonce_Type     =  %02x ", NetNonce[0]);	
	printf("\nCTL_and_TTL    =  %02x ", NetNonce[1]);	
	printf("\nSEQ            =  %02x %02x %02x ", NetNonce[2],
				NetNonce[3], NetNonce[4]);	
	printf("\nSRC            =  %02x %02x ", NetNonce[5],
				NetNonce[6]);	
	printf("\nPad            =  %02x %02x ", NetNonce[7],
				NetNonce[8]);	
	printf("\nIV_index       =  %02x %02x %02x %02x ", NetNonce[9],
				NetNonce[10], NetNonce[11], NetNonce[12]);		
	
				
	printf("\nSo the Network Nonce is \n               =  ");
	for( i=0 ; i<nonce_length_value ; i++)	
		printf("%02x ", NetNonce[i]);				
	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	//There is no cleartext header in this specifications!
	const size_t aad_len = aad_len_value;
	u8 aad[aad_len_value]; 
						
	const size_t plain_len = plain_len_value;
	//DST : 01 0D
	//TransportPDU : 4c a8 b6 b7 3b 53 37 05 07 for par = 0x00
	//TransportPDU : 4c a8 b6 b7 3a 8a 2c bc 2c for par = 0x01
	u8 plain[plain_len_value] =  {    
			  			0x01, 0x0D, 
						0x4c, 0xa8, 0xb6, 0xb7, 0x3a, 0x8a, 0x2c, 0xbc, 0x2c 
						};
	printf("\n\nDST            =  %02x %02x ", plain[0], plain[1]);
	printf("\nTransportPDU is=  ");
	for( i=2 ; i<plain_len ; i++)	
		printf("%02x ", plain[i]);						
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //

	u8 crypt[plain_len]; 
	u8 auth[M]; 

	
	
	printf("\nSo the plain DST_concat_TransportPDU is: \n               =  ");
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", plain[i]);	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	
	u8 x_enc[AES_BLOCK_SIZE], a_enc[AES_BLOCK_SIZE];
	
	aes_ccm_auth_start(EncryptionKey, M, L, NetNonce, aad, aad_len, plain_len, x_enc);
	aes_ccm_auth(EncryptionKey, plain, plain_len, x_enc);
	// Encryption 
	aes_ccm_encr_start(L, NetNonce, a_enc);
	aes_ccm_encr(EncryptionKey, L, plain, plain_len, crypt, a_enc);
	aes_ccm_encr_auth(EncryptionKey, M, x_enc, a_enc, auth);
	
		
	printf("\n\nEncDST_concat_EncTransportPDU is: \n               =  ");	
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", crypt[i]);
	
	printf("\n\nNetMIC is: \n               =  ");
	for( i=0 ; i<M ; i++)	
		printf("%02x ", auth[i]);
 		
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //

	return 0;
}
