/*
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

/**
In order to obfuscate the Network Header (CTL, TTL, SEQ, SRC), 
these values shall be combined with a result of a single encryption function e, 
designed to prevent a passive eavesdropper from determining the identity of a node by
listening to Network PDUs.

The obfuscation occurs after the application and network message integrity check values
 have been calculated. 
The obfuscation is calculated using information available from within the Network PDU.

To obfuscate the Network PDU, 
the first six octets of the Network PDU that have already been encrypted 
are combined with the 
IV Index and a 
Privacy Key.
These first six octets of the Network PDU that have been encrypted includes 
the DST, and can include up to four octets of the EncTransportPDU and/or NetMIC fields. 
These octets are known as the PrivacyRandom value.

The Privacy Key is derived using a key derivation function from the network key 
to protect the network key even if the Privacy Key is compromised.

Privacy Random = (EncDST || EncTransportPDU || NetMIC)[0–6]
PECB = e (PrivacyKey, 0x0000000000 || IV Index || Privacy Random)
ObfuscatedData = (CTL || TTL || SEQ || SRC) ⊕ PECB[0–5]
**/

#include <stdio.h>
#include "AES_128.h"

int main()
{
int i;

	//PrivacyKey : 76 94 61 92 be b9 41 b4 cb d5 f1 82 dc 58 6e 55
	unsigned char PrivacyKey[16] =  {
						0x76, 0x94, 0x61, 0x92, 
						0xbe, 0xb9, 0x41, 0xb4,
					    0xcb, 0xd5, 0xf1, 0x82, 
	 				    0xdc, 0x58, 0x6e, 0x55
						};
 	printf("PrivacyKey = ");
 	for( i=0 ; i<16 ; i++)	
		printf("%02x ", PrivacyKey[i]);						
						
	//five0x00octets_concat_4IVoctets_concat_7octetsofPrivacyRandom : 
	//5 0x00 octets = 00 00 00 00 00
	//IV index  = 00 00 00 00
	//Privacy Random = 7 octetes of (EncDST || EncTransportPDU || NetMIC)[0�6]
	//EncDST = dc f2
	//EncTransportPDU = 
	//EncTransportPDU =  28 18 32 da e6 49 4e 30 ba for par=0x1
	//NetMIC =
	//Privacy Random = dc f2 28 18 32 da e6	
	unsigned char Concatinated_Privacy_Random[16] =  
						{
						0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 
						0xdc, 0xf2,
						0x28, 0x18, 0x32, 0xda, 0xe6
						};						
	printf("\n\nfive 0x00 octets  = ");
	for( i=0 ; i<5 ; i++)	
		printf("%02x ", Concatinated_Privacy_Random[i]);
	printf("\nIV index          = ");
	for( i=5 ; i<9 ; i++)	
		printf("%02x ", Concatinated_Privacy_Random[i]);
	printf("\nEncDST            = ");
	for( i=9 ; i<11 ; i++)	
		printf("%02x ", Concatinated_Privacy_Random[i]);
	printf("\nfirst 5 octetes of (EncTransportPDU||NetMIC) is \n                  = ");
	for( i=11 ; i<16 ; i++)	
		printf("%02x ", Concatinated_Privacy_Random[i]);
		
	printf("\nSo the Concatinated_Privacy_Random is \n                  = ");
	for( i=0 ; i<16 ; i++)	
		printf("%02x ", Concatinated_Privacy_Random[i]);
	
	
	unsigned char PECB[16];					
	AES_128(PrivacyKey, Concatinated_Privacy_Random, PECB);
	printf("\n\nPECB = ");
	for( i=0 ; i<6 ; i++)	
		printf("%02x ", PECB[i]);
 
	//preObfuscation = 6 octetes : ((CTL||TTL) || SEQ || SRC)
	//(CTL||TTL) = 0x03
	//SEQ = 0x000000
	//SRC = 0x0017
	// preObfuscation = 03   00 00 00   00 17
	unsigned char preObfuscation[6] =  {
						0x03,
						0x00, 0x00, 0x00, 
						0x00, 0x17
						};	
	printf("\n\nCTL_concat_TTL           = %02x ", preObfuscation[0]);		
	printf("\nSEQ                      = %02x %02x %02x ", preObfuscation[1],
				preObfuscation[2], preObfuscation[3]);	
	printf("\nSRC                      = %02x %02x ", preObfuscation[4],
				preObfuscation[5]);	

									
 	printf("\nSo the preObfuscation is = ");
 	for( i=0 ; i<6 ; i++)	
		printf("%02x ", preObfuscation[i]);							
									
	unsigned char ObfuscatedData[6];
	for( i=0 ; i<6 ; i++)	
		ObfuscatedData[i] = (PECB[i]^preObfuscation[i]);
						
	 printf("\n\nObfuscatedData = ");
 	 for( i=0 ; i<6 ; i++)	
		printf("%02x ", ObfuscatedData[i]);
}
