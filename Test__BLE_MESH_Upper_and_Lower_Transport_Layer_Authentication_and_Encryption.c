/*
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

/**
Every message has a minimum of 64 bits of authentication information associated with it. 
This authentication information may be split between the network layer and upper transport layer.
Some messages, known as control messages, are not authenticated at the upper transport layer and therefore have a 64-bit NetMIC.
Access messages are authenticated at the upper transport layer and therefore have a 32-bit NetMIC. 
Access messages that are sent in a single unsegmented message have a 32-bit TransMIC.
Access messages that are segmented over multiple Network PDUs can have either a 32-bit or 64-bit TransMIC. 
This allows a higher layer to determine the level of authentication required to securely deliver the access message and therefore apply the appropriate size for the TransMIC

Upper transport layer authentication and encryption
Authentication and encryption of the access payload is performed by the upper transport layer.
The access payload is encrypted and authenticated using AES-CCM.
This is identical to the way that Bluetooth low energy encryption and authentication works.

inputs:
1. plain_Application_Payload
either: 
		2. Application_Nonce
		3. AppKey
or:
		2. Device_Nonce
		3. DevKey
If the access payload is secured using the application key, 
then the access payload is encrypted using the 
application nonce and the 
application key.

If the access payload is secured using the device key, 
then the access payload is encrypted using the 
device nonce and the 
device key.

Outputs:
encryp_Application_Payload
TransMIC

The nonce uses the sequence number and the source address, 
ensuring that two different nodes cannot use the same nonce. 
The IV Index is used to provide significantly more nonce values 
than the sequence number can provide for a given node.

Note: 
The authentication and encryption of the access payload is not
dependent on the TTL value, 
meaning that as the access payload is relayed through a mesh network, 
the access payload does not need to be re-encrypted at each hop.

When using an application key and the destination address is a virtual address:
EncAccessPayload, TransMIC = AES-CCM (AppKey, Application Nonce, AccessPayload, Label UUID)
When using an application key and the destination address is a unicast address or a group address:
EncAccessPayload, TransMIC = AES-CCM (AppKey, Application Nonce, AccessPayload)
When using a device key and the destination address is a unicast address:
EncAccessPayload, TransMIC = AES-CCM (DevKey, Device Nonce, AccessPayload)

The concatenation of the encrypted access payload and the transport MIC is called the Upper Transport PDU:
Upper Transport PDU = EncAccessPayload || TransMIC
**/
/*
Types of Nounces:
0x00	Network nonce:
			Used with an encryption key for network authentication and encryption
		
0x01	Application nonce:
			Used with an application key for upper transport authentication and encryption
		
0x02	Device nonce:
			Used with a device key for upper transport authentication and encryption
		
0x03	Proxy nonce:
			Used with an encryption key for proxy authentication and encryption
*/

#include <stdio.h>
#include "AES_CCM.h"


int main()
{
	int i=0;

	#define L_value 2 //size of Length field
	#define nonce_length_value (15-L_value) //size of nonce
	#define key_len_value 16 //sized of the AppKey_or_DevKey, for aes-128
	#define AppKey_or_DevKey_should_used	1 //if 1 AppKey should be used, if 0 DevKey
	#define M_value 						4 //size of the authentication field
											  //i.e. NetMIC Size : 64 bits or 32 bits
											  //4 octets for the access messages
											  //8 octets for the Control messages
											  //dastan dareh
	
	#define MSG_Opcode_Size					3 //Opcode_Size could be 1,2 or 3 octets
	#define MSG_Parameters_Size				1 //can be 0 or more(up to 384?)
	#define Total_packet_length 			MSG_Opcode_Size + MSG_Parameters_Size
	
	#define	aad_len_value 					0 //There is no cleartext header in this specifications!
	#define plain_len_value (Total_packet_length-aad_len_value) //the message portion of the whole packet
	

	
	const size_t L = L_value;
	
	const size_t key_len = key_len_value;
	/*
	//DevKey : 9d 6d d0 e9 6e b2 5d c1 9a 40 ed 99 14 f8 f0 3f
	u8 AppKey_or_DevKey[key_len_value] =  {
						0x9d, 0x6d, 0xd0, 0xe9, 
						0x6e, 0xb2, 0x5d, 0xc1,
					    0x9a, 0x40, 0xed, 0x99, 
	 				    0x14, 0xf8, 0xf0, 0x3f
						};
	*/
	
	//AppKey
    unsigned char AppKey_or_DevKey[16] = {
         0x9B,  0x1A,  0x25,  0x9D,
		 0x89,  0x56,  0x98,  0x3A,
         0x73,  0x01,  0xCB,  0x05,      
		 0x2B,  0x21,  0xFF,  0x38
    };

	
	if (AppKey_or_DevKey_should_used==1)
		printf("AppKey is: \n");
	else
		printf("DevKey is: \n");
	for( i=0 ; i<key_len ; i++)	
		printf("%02x ", AppKey_or_DevKey[i]);
	
	const size_t M = M_value; //size of auth (i.e. MAC)
	
	//Application_Nonce = 
	//Nonce_Type||ASZMIC_and_Pad||SEQ||SRC||DST||IV_index
	//Nonce_Type = 0x01 for the Application Nonce Type
	//Nonce_Type = 0x02 for the Device Nonce Type
	//ASZMIC_and_Pad = ASZMIC||Pad
	//ASZMIC: 1 if a Segmented Access message or 0 for all other messages
	//Pad = 0b0000000
	
	////Nonce_Type   = 01
	//ASZMIC_and_Pad = 00
	//SEQ 			 = 00 00 00
	//SRC			 = 00 17
	//DST			 = 01 0D
	//IV_index		 = 00 00 00 00
	//Application Nonce : 01 00 00 00 00 00 17 01 0D 00 00 00 00
	u8 AppNonce_or_DevNonce [nonce_length_value] =  {
						0x01, 
						0x00, 
						0x00, 0x00, 0x00,
						0x00, 0x17,
						0x01, 0x0D,
						0x00, 0x00, 0x00, 0x00
					};
	

	printf("\n\nNonce_Type     =  %02x ", AppNonce_or_DevNonce[0]);	
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
	const size_t aad_len = aad_len_value;
	u8 aad[aad_len_value]; 
						
	const size_t plain_len = plain_len_value;
	
	//Access_Payload = Opcode||Application_parameters
	//Opcode 				 = C1 00 59 
	//Application_parameters = 01
	u8 plain[plain_len_value] =  {    
			  			0xC1, 0x00, 0x59, 
						0x01, 
						};
	
	printf("\n\nOpcode                 = ");
	for( i=0 ; i<MSG_Opcode_Size ; i++)	
		printf("%02x ", plain[i]);		
	printf("\nApplication_parameters = ");
	for( i=MSG_Opcode_Size ; i<plain_len_value ; i++)	
		printf("%02x ", plain[i]);	
	
	
	printf("\nSo the Plain Access Payload  is:\n                         ");
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", plain[i]);	
							
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! //

	u8 crypt[plain_len]; 
	u8 auth[M]; 
	//!!!!!!!!!!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!!!!!!!!! 
	//!!!!!!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!!!!!
	//!!!!!!!!!!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!    !!!!!!!!!!!!
	
	u8 x_enc[AES_BLOCK_SIZE], a_enc[AES_BLOCK_SIZE];
	
	aes_ccm_auth_start(AppKey_or_DevKey, M, L, AppNonce_or_DevNonce, aad, aad_len, plain_len, x_enc);
	aes_ccm_auth(AppKey_or_DevKey, plain, plain_len, x_enc);
	// Encryption 
	aes_ccm_encr_start(L, AppNonce_or_DevNonce, a_enc);
	aes_ccm_encr(AppKey_or_DevKey, L, plain, plain_len, crypt, a_enc);
	aes_ccm_encr_auth(AppKey_or_DevKey, M, x_enc, a_enc, auth);
	
		
	printf("\n\nEncAccessPayload is: \n");	
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", crypt[i]);
	
	printf("\n\nTransMIC is: \n");
	for( i=0 ; i<M ; i++)	
		printf("%02x ", auth[i]); 
		
	printf("\n\nUpperTransportPDU is: \n");
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", crypt[i]);
	for( i=0 ; i<M ; i++)	
		printf("%02x ", auth[i]);
		
		
	u8 SEG_concat_AFK_concat_AID;
	u8 SEG= 0x00;
	u8 AFK= 0x01;
	u8 AID= 0x0c;
	//SEG_concat_AFK_concat_AID = SEG || AFK ||AID
	//SEG = 0; //1 if Message is segmented
	//AFK = 1; //1 if AppKey is used, 0 if DevKey is utilized
	//AID =0x0c //if (AFK==1) then DeviceID shall be used instead
	
	printf("\n\nSEG is: %01x", SEG);
	printf("\nAFK is: %01x", AFK);
	printf("\nAID is: %02x", AID);
	SEG_concat_AFK_concat_AID = 128*SEG + 64*AFK + AID;
	printf("\nSo the SEG_concat_AFK_concat_AID is: %02x", SEG_concat_AFK_concat_AID);
	printf("\nSo the LowerTransportPDU is: ");
	printf("%02x ", SEG_concat_AFK_concat_AID);
	for( i=0 ; i<plain_len ; i++)	
		printf("%02x ", crypt[i]);
	for( i=0 ; i<M ; i++)	
		printf("%02x ", auth[i]);		

	return 0;
}
