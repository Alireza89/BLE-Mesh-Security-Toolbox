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
#include "aes_ccm.h"

int main()
{
// ############################################################################################################# //
	#define Network_Nonce 	  0x00
	#define Application_Nonce 0x01
	#define Device_Nonce 	  0x02

	#define MSG_Opcode_Size							3 //Opcode_Size could be 1,2 or 3 octets
	unsigned char Opcode[MSG_Opcode_Size] 		  = { 0xC1, 0x00, 0x59 };
	#define MSG_Parameters_Size						1 //can be 0 or more(up to 8 for unsegmented...?)
	unsigned char parameters[MSG_Parameters_Size] = { 0x01 };

	unsigned char 	Nonce_Type_App[1] 	= { Application_Nonce };
	unsigned char 	ASZMIC_and_Pad[1] 	= { 0x00};
	unsigned char	SEQ[3] 				= { 0x00, 0x00, 0x0 };
	unsigned char	SRC[2] 				= { 0x00, 0x17 };
	unsigned char	DST[2] 				= { 0x01, 0x0D };
	unsigned char	IV_index[4] 		= { 0x00, 0x00, 0x00, 0x00 };
	
	unsigned char 	Nonce_Type_Net[1] 	= { Network_Nonce};
	unsigned char 	CTL_and_TTL[1] 		= { 0x03};
	

	unsigned char SEG = 0x00; //0x00 if message is unsegmented
	unsigned char AFK = 0x01; //0x00 if AppKey is used
	
	#define L_value 			2 			//this value is fixed.  size of Length field
	#define nonce_length_value (15-L_value) //this value is fixed. size of nonce
	#define key_len_value 		16 			//this value is fixed. sized of the AppKey_or_DevKey, for aes-128
	#define	aad_len_value 		0 			//this value is fixed. There is no cleartext header in this specifications!
	#define DST_length_value	2 			//this value is fixed. Destination address has a fixed length of 2 octets
	
	#define AppKey_or_DevKey_should_used		1 //if 1 AppKey should be used, if 0 DevKey
	#define Sizeof_TransMIC 					4 
	#define Access_Payload_len_value 			( MSG_Opcode_Size + MSG_Parameters_Size )

	#define UpperTransportPDU_len_value     	( Access_Payload_len_value+Sizeof_TransMIC )
	#define LowerTransportPDU_len_value     	1+UpperTransportPDU_len_value
	
	#define Sizeof_NetMIC 						4 
	#define Network_encryption_Total_packet_length 			( DST_length_value + LowerTransportPDU_len_value )
		
// ############################################################################################################# //	
	int i=0;
	
	for( i=0 ; i<100 ; i++)	
		printf("#");	
	printf("\n");
    unsigned char IdentityKey[16], BeaconKey[16], 
				  NID, EncryptionKey[16], PrivacyKey[16], NetworkID[8], 
				  AID,
				  
				  K1[16], K2[16], K3[16], K4[16],
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
	
	//P = “id128” || 0x01
    unsigned char P[6] = {
		 'i',  'd',  '1',  '2',  '8',  0x01
    };	
	
	
	AES_CMAC(const_Zero,SALT_IdentityKey_string,4,SALT_IdentityKey);
	AES_CMAC(SALT_IdentityKey,NetKey,16,T);
	AES_CMAC(T,P,6,IdentityKey);
	
	AES_CMAC(const_Zero,SALT_BeaconKey_string,4,SALT_BeaconKey);
	AES_CMAC(SALT_BeaconKey,NetKey,16,T);
	AES_CMAC(T,P,6,BeaconKey);
	
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
	
// #####################################     k3 function for NetworkID    ##################################### //
	unsigned char Text_Message3[4] = {'s', 'm', 'k', '3'};
	AES_CMAC(const_Zero, Text_Message3, 4, SALT3);
	
	AES_CMAC(SALT3, NetKey, 16, T);

	unsigned char Concat_K3[5] = {'i', 'd', '6', '4', 0x01};
	AES_CMAC(T, Concat_K3, 5, K3);
	
	memcpy(NetworkID, K3+8, 8);
	
// ########################################     k4 function for AID     ######################################## //

	unsigned char Text_Message4[4] = {'s', 'm', 'k', '4'};
	AES_CMAC(const_Zero, Text_Message4, 4, SALT4);
	
	AES_CMAC(SALT4, AppKey, 16, T);
	
	unsigned char Concat_K4[4] = {'i', 'd', '6', 0x01};
	AES_CMAC(T, Concat_K4, 4, K4);

	AID = K4[15]%64;

// ########################################      Print All Results      ######################################## //	
	
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
    
	printf("\nAID           = %02x\n\n", AID);	
	
// ############################################################################################################# //
	printf("\n");
	for( i=0 ; i<100 ; i++)	
		printf("#");
	printf("\n");	
	
	size_t L;
	size_t key_len;
	size_t aad_len;
	
	L = L_value;
	key_len = key_len_value;
	aad_len = aad_len_value;
	
	//AppKey
    unsigned char AppKey_or_DevKey[16];
	memcpy(AppKey_or_DevKey, AppKey, 16);

	
	if (AppKey_or_DevKey_should_used==1)
		printf("AppKey is: \n");
	else
		printf("DevKey is: \n");
	for( i=0 ; i<key_len ; i++)	
		printf("%02x ", AppKey_or_DevKey[i]);

	u8 AppNonce_or_DevNonce [nonce_length_value];
	memcpy(AppNonce_or_DevNonce + 0, Nonce_Type_App, 1);
	memcpy(AppNonce_or_DevNonce + 1, ASZMIC_and_Pad, 1);
	memcpy(AppNonce_or_DevNonce + 2, SEQ, 	  		 3);
	memcpy(AppNonce_or_DevNonce + 5, SRC,			 2);
	memcpy(AppNonce_or_DevNonce + 7, DST,			 2);
	memcpy(AppNonce_or_DevNonce + 9, IV_index,		 4);

	printf("\nNonce_Type     =  %02x ", AppNonce_or_DevNonce[0]);	
	printf("\nASZMIC_and_Pad =  %02x ", AppNonce_or_DevNonce[1]);	
	printf("\nSEQ            =  %02x %02x %02x ", AppNonce_or_DevNonce[2],
				AppNonce_or_DevNonce[3], AppNonce_or_DevNonce[4]);	
	printf("\nSRC            =  %02x %02x ", AppNonce_or_DevNonce[5],
				AppNonce_or_DevNonce[6]);	
	printf("\nDST            =  %02x %02x ", AppNonce_or_DevNonce[7],
				AppNonce_or_DevNonce[8]);	
	printf("\nIV_index       =  %02x %02x %02x %02x ", AppNonce_or_DevNonce[9],
				AppNonce_or_DevNonce[10], AppNonce_or_DevNonce[11], AppNonce_or_DevNonce[12]);		
			
	if (AppKey_or_DevKey_should_used==1)
		printf("\nSo the Application Nonce is: \n               =  ");
	else
		printf("\nSo the Device Nonce is (note: In Mesh Profile Specification v1.0.pdf, Device Nonce sometimes wrongly referred to as Application Nonce): \n               =  ");
	for( i=0 ; i<nonce_length_value ; i++)	
		printf("%02x ", AppNonce_or_DevNonce[i]);
	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //
	
	//There is no cleartext header in this specifications!
	u8 aad[aad_len_value]; 

	//Access_Payload = Opcode||parameters
	//Opcode 				 = C1 00 59 
	//parameters = 01
	u8 Access_Payload[Access_Payload_len_value];
	memcpy(Access_Payload + 0, Opcode, 	   MSG_Opcode_Size);
	memcpy(Access_Payload + MSG_Opcode_Size, parameters, MSG_Parameters_Size);
	
	
	printf("\n\nOpcode                 = ");
	for( i=0 ; i<MSG_Opcode_Size ; i++)	
		printf("%02x ", Access_Payload[i]);		
	printf("\nApplication_parameters = ");
	for( i=MSG_Opcode_Size ; i<Access_Payload_len_value ; i++)	
		printf("%02x ", Access_Payload[i]);	
	
	printf("\nSo the Plain Access Payload  is:\n                         ");
	for( i=0 ; i<Access_Payload_len_value ; i++)	
		printf("%02x ", Access_Payload[i]);	
							
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //

	u8 crypt[Access_Payload_len_value]; 
	u8 auth[Sizeof_TransMIC]; 

	u8 x_enc[AES_BLOCK_SIZE], a_enc[AES_BLOCK_SIZE];
	
	aes_ccm_auth_start(AppKey_or_DevKey, Sizeof_TransMIC, L, AppNonce_or_DevNonce, aad, aad_len, Access_Payload_len_value, x_enc);
	aes_ccm_auth(AppKey_or_DevKey, Access_Payload, Access_Payload_len_value, x_enc);
	// Encryption 
	aes_ccm_encr_start(L, AppNonce_or_DevNonce, a_enc);
	aes_ccm_encr(AppKey_or_DevKey, L, Access_Payload, Access_Payload_len_value, crypt, a_enc);
	aes_ccm_encr_auth(AppKey_or_DevKey, Sizeof_TransMIC, x_enc, a_enc, auth);
	
	unsigned char EncAccessPayload[Access_Payload_len_value];
	memcpy(EncAccessPayload, crypt, Access_Payload_len_value);
	printf("\n\nEncAccessPayload is: \n");	
	for( i=0 ; i<Access_Payload_len_value ; i++)	
		printf("%02x ", EncAccessPayload[i]);
	
	unsigned char TransMIC[Sizeof_TransMIC];
	memcpy(TransMIC, auth, Sizeof_TransMIC);
	printf("\n\nTransMIC is: \n");
	for( i=0 ; i<Sizeof_TransMIC ; i++)	
		printf("%02x ", TransMIC[i]); 
		
	unsigned char UpperTransportPDU[UpperTransportPDU_len_value];
	memcpy(UpperTransportPDU,                          EncAccessPayload, Access_Payload_len_value);	
	memcpy(UpperTransportPDU+Access_Payload_len_value, TransMIC,         Sizeof_TransMIC);	
	printf("\n\nUpperTransportPDU is: \n");
	for( i=0 ; i<UpperTransportPDU_len_value ; i++)	
		printf("%02x ", UpperTransportPDU[i]);

	//u8 AID= 0x0c;
	//SEG_concat_AFK_concat_AID = SEG || AFK ||AID
	//SEG = 0; //1 if Message is segmented
	//AFK = 1; //1 if AppKey is used, 0 if DevKey is utilized
	//AID =0x0c //if (AFK==1) then DeviceID shall be used instead
	
	printf("\n\nSEG is: %01x", SEG);
	printf("\nAFK is: %01x", AFK);
	printf("\nAID is: %02x", AID);
	unsigned char SEG_concat_AFK_concat_AID[1] = {128*SEG + 64*AFK + AID};
	printf("\nSo the SEG_concat_AFK_concat_AID is: %02x", SEG_concat_AFK_concat_AID[0]);
	
	
	unsigned char LowerTransportPDU[LowerTransportPDU_len_value];
	memcpy(LowerTransportPDU+0, SEG_concat_AFK_concat_AID, 1);
	memcpy(LowerTransportPDU+1, UpperTransportPDU,         UpperTransportPDU_len_value);
	printf("\nSo the LowerTransportPDU is: ");
	for( i=0 ; i<LowerTransportPDU_len_value ; i++)	
		printf("%02x ", LowerTransportPDU[i]);
	printf("\n");

// ############################################################################################################# //
	
	printf("\n");
	for( i=0 ; i<100 ; i++)	
		printf("#");	
	printf("\n");
	
	unsigned char	Pad[2] 				= { 0x00, 0x00 };
	
	u8 NetNonce[nonce_length_value]; 
	memcpy(NetNonce + 0, Nonce_Type_Net, 1);
	memcpy(NetNonce + 1, CTL_and_TTL,    1);
	memcpy(NetNonce + 2, SEQ, 	  		 3);
	memcpy(NetNonce + 5, SRC,			 2);
	memcpy(NetNonce + 7, Pad,			 2);
	memcpy(NetNonce + 9, IV_index,		 4);
					
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
	
	//DST : 01 0D
	//TransportPDU : 4c a8 b6 b7 3b 53 37 05 07 for par = 0x00
	//TransportPDU : 4c a8 b6 b7 3a 8a 2c bc 2c for par = 0x01
	u8 Network_encryption_plain[Network_encryption_Total_packet_length];
	memcpy(Network_encryption_plain + 0,                DST,               DST_length_value);
	memcpy(Network_encryption_plain + DST_length_value, LowerTransportPDU, LowerTransportPDU_len_value);
	
	printf("\n\nDST            =  %02x %02x ", Network_encryption_plain[0], Network_encryption_plain[1]);
	printf("\nLowerTransportPDU is=  ");
	for( i=DST_length_value ; i<Network_encryption_Total_packet_length ; i++)	
		printf("%02x ", Network_encryption_plain[i]);						
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //

	u8 crypt_Network_encryption[Network_encryption_Total_packet_length]; 
	u8 NetMIC[Sizeof_NetMIC]; 

	printf("\nSo the plain DST_concat_TransportPDU is: \n               =  ");
	for( i=0 ; i<Network_encryption_Total_packet_length ; i++)	
		printf("%02x ", Network_encryption_plain[i]);	
		
	aes_ccm_auth_start(EncryptionKey, Sizeof_NetMIC, L, NetNonce, aad, aad_len, Network_encryption_Total_packet_length, x_enc);
	aes_ccm_auth(EncryptionKey, Network_encryption_plain, Network_encryption_Total_packet_length, x_enc);
	// Encryption 
	aes_ccm_encr_start(L, NetNonce, a_enc);
	aes_ccm_encr(EncryptionKey, L, Network_encryption_plain, Network_encryption_Total_packet_length, crypt_Network_encryption, a_enc);
	aes_ccm_encr_auth(EncryptionKey, Sizeof_NetMIC, x_enc, a_enc, NetMIC);
	
		
	printf("\n\nEncDST_concat_EncTransportPDU is: \n               =  ");	
	for( i=0 ; i<Network_encryption_Total_packet_length ; i++)	
		printf("%02x ", crypt_Network_encryption[i]);
	
	printf("\n\nNetMIC is: \n               =  ");
	for( i=0 ; i<Sizeof_NetMIC ; i++)	
		printf("%02x ", NetMIC[i]);
 	printf("\n");	 

// ############################################################################################################# //	
	printf("\n");
	for( i=0 ; i<100 ; i++)	
		printf("#");
	printf("\n");
			
 	printf("PrivacyKey = ");
 	for( i=0 ; i<16 ; i++)	
		printf("%02x ", PrivacyKey[i]);						
			
	unsigned char	Enc_DST[2];
	memcpy(Enc_DST, crypt_Network_encryption, 2);
	unsigned char	Five0x00octets[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char	Five_MSBs_of_EncTransportPDU_concat_NetMIC[5];
	
	int Sizeof_crypt_Network_encryption = sizeof(crypt_Network_encryption);
	if(Sizeof_crypt_Network_encryption >= 5)
	{
		memcpy(Five_MSBs_of_EncTransportPDU_concat_NetMIC, crypt_Network_encryption+2, 5);
	}
	else
	{
		memcpy(		Five_MSBs_of_EncTransportPDU_concat_NetMIC, 
					crypt_Network_encryption + 2, 
					Sizeof_crypt_Network_encryption);
			   
		memcpy(		Five_MSBs_of_EncTransportPDU_concat_NetMIC+Sizeof_crypt_Network_encryption, 
					NetMIC + 0, 
					5 - Sizeof_crypt_Network_encryption);
	}
	
	//five0x00octets_concat_4IVoctets_concat_7octetsofPrivacyRandom : 
	//5 0x00 octets = 00 00 00 00 00
	//IV index  = 00 00 00 00
	//Privacy Random = 7 octetes of (EncDST || EncTransportPDU || NetMIC)[0ֶ]
	//EncDST = dc f2
	//EncTransportPDU = 
	//EncTransportPDU =  28 18 32 da e6 49 4e 30 ba for par=0x1
	//NetMIC =
	//Privacy Random = dc f2 28 18 32 da e6	
	unsigned char Concatinated_Privacy_Random[16];
	memcpy(Concatinated_Privacy_Random, Five0x00octets, 								5);
	memcpy(Concatinated_Privacy_Random+5, IV_index, 									4);
	memcpy(Concatinated_Privacy_Random+9, Enc_DST, 										2);
	memcpy(Concatinated_Privacy_Random+11, Five_MSBs_of_EncTransportPDU_concat_NetMIC, 	5);

						
	printf("\n\nFive 0x00 octets  = ");
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
	unsigned char preObfuscation[6];
	memcpy(preObfuscation + 0, CTL_and_TTL,	1);
	memcpy(preObfuscation + 1, SEQ,			3);
	memcpy(preObfuscation + 4, SRC,			2);
					
	printf("\n\nCTL_and_TTL              = %02x ", preObfuscation[0]);		
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
		
// ############################################################################################################# //

	printf("\n\n");
	for( i=0 ; i<100 ; i++)	
		printf("#");
	printf("\n");
	
	int lsb_of_IV_index = (IV_index[3]%2);
	unsigned char IVI_and_NID[1] = {128*lsb_of_IV_index + NID};
	printf("lsb_of_IV_index        = %d \n", lsb_of_IV_index);
	printf("NID                    = %02x \n", NID);
	printf("so the IVI_and_NID     = %02x \n", IVI_and_NID[0]);
	
	unsigned char Sizeof_Network_PDU = 1 + 6 + Sizeof_crypt_Network_encryption + Sizeof_NetMIC;
	unsigned char Network_PDU [Sizeof_Network_PDU];
	memcpy(Network_PDU + 0, 								IVI_and_NID, 											1);
	memcpy(Network_PDU + 1, 								ObfuscatedData, 										6);
	memcpy(Network_PDU + 7, 								crypt_Network_encryption, Sizeof_crypt_Network_encryption);
	memcpy(Network_PDU + 7+Sizeof_crypt_Network_encryption, NetMIC,									    Sizeof_NetMIC);
	
	printf("\nIVI and NID        = ");
		for( i=0 ; i<1 ; i++)	
		printf("%02x ", IVI_and_NID[i]);
	printf("\nObfuscated         = ");
		for( i=0 ; i<6 ; i++)	
		printf("%02x ", ObfuscatedData[i]);
	printf("\nEncrypted          = ");
		for( i=0 ; i<Sizeof_crypt_Network_encryption ; i++)	
		printf("%02x ", crypt_Network_encryption[i]);
	printf("\nNetMIC             = ");
		for( i=0 ; i<Sizeof_NetMIC ; i++)	
		printf("%02x ", NetMIC[i]);
	printf("\n\nSo the Network PDU is = \n");
		for( i=0 ; i<Sizeof_Network_PDU ; i++)	
		printf("%02x ", Network_PDU[i]);
		
	
	unsigned char Proxy_PDU_first_header [1] = {0x40};	
	unsigned char Proxy_PDU_first_seg [1 + 19];
	memcpy(Proxy_PDU_first_seg + 0, Proxy_PDU_first_header, 1);
	memcpy(Proxy_PDU_first_seg + 1, Network_PDU,            19);
	
	unsigned char Proxy_PDU_last_header [1] = {0xc0};	
	unsigned char Proxy_PDU_last_seg [1 + Sizeof_Network_PDU-19];
	memcpy(Proxy_PDU_last_seg + 0, Proxy_PDU_last_header,                      1);
	memcpy(Proxy_PDU_last_seg + 1, Network_PDU+19,         Sizeof_Network_PDU-19);
	
		
	printf("\n\nFirst segment of Proxy PDU is  = \n");
	for( i=0 ; i<sizeof(Proxy_PDU_first_seg) ; i++)	
		printf("%02x ", Proxy_PDU_first_seg[i]);
	printf("\n\nLast segment of Proxy PDU is   = \n");
	for( i=0 ; i<sizeof(Proxy_PDU_last_seg) ; i++)	
		printf("%02x ", Proxy_PDU_last_seg[i]);		

	printf("\n\n");
	for( i=0 ; i<100 ; i++)	
		printf("#");		
			
// ############################################################################################################# //		
   
    return 0;
}
