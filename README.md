# BLE-Mesh-Security-Toolbox
Bluetooth Low Energy Mesh Security Toolbox
-----------------------------------------------------------------------------------------------
    Author: Alireza Sameni for an open source Bluetooth Low Energy Mesh Security Toolbox
    Email:  alireza_sameni@live.com
    Date:   June, 2018

    "What You Seek, is Who You Are" - Rumi
------------------------------------------------------------------------------------------------
This repo enebles you to Encrypt messages for transmition in a Bluetooth Low Energy Mesh Network.
This repo is self-contained and do not need to call any crypto functions from the OS

Simple demonstration:
1. Create a console C project with Dev-Cpp (be careful to select C and not C++)
2. Add the following files to the project

    AES_128.h
    
    AES_128.c
    
    AES_CCM.h
    
    AES_CCM.c
    
    AES_CMAC.h
    
    AES_CMAC.c
    
    Test__BLE_MESH_All_Security_Toolbox_Functions.c
	
3. compile the project and see the encrypted BLE Mesh network packet in the prompt console.
