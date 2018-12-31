/*
    Original Author(s): GitHub contributors
    Edited by: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date: June, 2018
    
    "What You Seek, is Who You Are" - Rumi
*/

#ifndef 	AES_CMAC_header
	#define AES_CMAC_header
	#include <stdio.h>
	/* For CMAC Calculation */
	extern unsigned char const_Zero[16];
	extern unsigned char const_Rb[16];
	
	/* Basic Functions */
	void print_hex(char *str, unsigned char *buf, int len);
	void print128(unsigned char *bytes);
	
	/* AES-CMAC Generation Function */
	void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2);
	void AES_CMAC ( unsigned char *key, unsigned char *input, int length, unsigned char *mac );
#endif


