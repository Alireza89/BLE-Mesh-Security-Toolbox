/*
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "AES_128.h"
#include "AES_CMAC.h"

int main()
{

	int i=0;
    unsigned char IdentityKey[16], BeaconKey[16], 
				  NID, EncryptionKey[16], PrivacyKey[16], NetworkID[8], 
				  AID,
				  
				  L[16], K1[16], K2[16], K3[16], K4[16],
				  T[16],
				  SALT_IdentityKey[16], SALT_BeaconKey[16], SALT2[16], SALT3[16], SALT4[16],
				  T1[16], T2[16], T3[16], TT[12];
	
	//NetKey 
    unsigned char NetKey[16] = {
         0xB4,  0xFA,  0x7F,  0x7B,
		 0x5D,  0xAD,  0x48,  0xB2,
         0x9F,  0x80,  0x7E,  0xC8,      
		 0x63,  0x80,  0x8D,  0xCD
    };
    //AppKey 
    unsigned char AppKey[16] = {
         0x9B,  0x1A,  0x25,  0x9D,
		 0x89,  0x56,  0x98,  0x3A,
         0x73,  0x01,  0xCB,  0x05,      
		 0x2B,  0x21,  0xFF,  0x38
    };
// ############################     k1 function for IdentityKey and BeaconKey      ############################# //
	//salt = s1(“nkik”)
	//The IdentityKey is derived from the network key such that each network key generates one IdentityKey.
	unsigned char SALT_IdentityKey_string[4] = {
         'n',  'k',  'i',  'k'
    };	
    //salt = s1(“nkbk”)
    //The BeaconKey is derived from the network key such that each network key generates one BeaconKey.
    unsigned char SALT_BeaconKey_string[4] = {
         'n',  'k',  'b',  'k'
    };	
	
    unsigned char P[6] = {
		 'i',  'd',  '1',  '2',  '8',  0x01
    };	
	
	
	AES_CMAC(const_Zero,SALT_IdentityKey_string,4,SALT_IdentityKey);
	AES_CMAC(SALT_IdentityKey,NetKey,16,T);
	AES_CMAC(T,P,6,IdentityKey);
	
	AES_CMAC(const_Zero,SALT_BeaconKey_string,4,SALT_BeaconKey);
	AES_CMAC(SALT_BeaconKey,NetKey,16,T);
	AES_CMAC(T,P,6,BeaconKey);
// ############################################################################################################# //


// ####################    k2 function (master) for NID, EncryptionKey and PrivacyKey      #####################//
	uint8_t Concat_T1[ 0+1+1];
    uint8_t Concat_T2[16+1+1];
	uint8_t Concat_T3[16+1+1];

	unsigned char Text_Message2[4] = {'s', 'm', 'k', '2'};
	AES_CMAC(const_Zero, Text_Message2, 4, SALT2);

	AES_CMAC(SALT2, NetKey, 16, T);

	Concat_T1[0] =  0x00;
    Concat_T1[1] =  0x01;
	AES_CMAC(T, Concat_T1 ,  0+1+1, T1);

	memcpy(Concat_T2, T1, 16);
	Concat_T2[16+0] =  0x00;
    Concat_T2[16+1] =  0x02;
	AES_CMAC(T, Concat_T2 , 16+1+1, T2);
	
	memcpy(Concat_T3, T2, 16);
	Concat_T3[16+0] =  0x00;
    Concat_T3[16+1] =  0x03;
	AES_CMAC(T, Concat_T3 , 16+1+1, T3);

	NID = T1[15]%128;
	memcpy(EncryptionKey, T2, 16);
	memcpy(PrivacyKey, T3, 16);
// ############################################################################################################# //	


// #####################################     k3 function for NetworkID    ##################################### //
	unsigned char Text_Message3[4] = {'s', 'm', 'k', '3'};
	AES_CMAC(const_Zero, Text_Message3, 4, SALT3);
	
	AES_CMAC(SALT3, NetKey, 16, T);

	unsigned char Concat_K3[5] = {'i', 'd', '6', '4', 0x01};
	AES_CMAC(T, Concat_K3, 5, K3);
	
	memcpy(NetworkID, K3+8, 8);
// ############################################################################################################# //	

// ########################################     k4 function for AID     ######################################## //

    
	unsigned char Text_Message4[4] = {'s', 'm', 'k', '4'};
	AES_CMAC(const_Zero, Text_Message4, 4, SALT4);
	
	AES_CMAC(SALT4, AppKey, 16, T);
	
	unsigned char Concat_K4[4] = {'i', 'd', '6', 0x01};
	AES_CMAC(T, Concat_K4, 4, K4);

	AID = K4[15]%64;
// ############################################################################################################# //	
	//Print All Results
	printf("NetKey        = ");
	for(i=0;i<16;i++)
		printf("%02x ", NetKey[i]);

	printf("\nAppKey        = ");
	for(i=0;i<16;i++)
		printf("%02x ", AppKey[i]);
	
	printf("\n\nIdentityKey   = ");
	for(i=0;i<16;i++)
		printf("%02x ", IdentityKey[i]);
	
	printf("\nBeaconKey     = ");
	for(i=0;i<16;i++)
		printf("%02x ", BeaconKey[i]);
	
	printf("\nNID           = %02x\n", NID);
	
	printf("EncryptionKey = ");
	for(i=0;i<16;i++)
		printf("%02x ", EncryptionKey[i]);	
	
	printf("\nPrivacyKey    = ");
	for(i=0;i<16;i++)
		printf("%02x ", PrivacyKey[i]);
		
	printf("\nNetwork ID    = ");
	for(i=0;i<8;i++)
		printf("%02x ", NetworkID[i]);
    
	printf("\nAID           = %02x", AID);	
// ############################################################################################################# //	
    return 0;
}
