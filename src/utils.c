#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "headers.h"
#include "codes.h"
#include "utils.h"

/* Returns a C string containing human-readable description of machine type */
int read_machine_type(PE_Header* pe_head, char* machine_type)
{
    switch(pe_head->Machine)
    {
        case 0x0:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_UNKNOWN, 
                strlen(IMAGE_FILE_MACHINE_UNKNOWN));
            break;
        case 0x1d3:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_AM33, 
                strlen(IMAGE_FILE_MACHINE_AM33));
            break;
        case 0x8664:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_AMD64, 
                strlen(IMAGE_FILE_MACHINE_AMD64));
            break;
        case 0x1c0:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_ARM, 
                strlen(IMAGE_FILE_MACHINE_ARM));
            break;
        case 0x1c4:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_ARMNT, 
                strlen(IMAGE_FILE_MACHINE_ARMNT));
            break;
        case 0xaa64:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_ARM64, 
                strlen(IMAGE_FILE_MACHINE_ARM64));
            break;
        case 0xebc:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_EBC, 
                strlen(IMAGE_FILE_MACHINE_EBC));
            break;
        case 0x14c:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_I386, 
                strlen(IMAGE_FILE_MACHINE_I386));
            break;
        case 0x200:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_IA64, 
                strlen(IMAGE_FILE_MACHINE_IA64));
            break;
        case 0x9041:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_M32R, 
                strlen(IMAGE_FILE_MACHINE_M32R));
            break;
        case 0x266:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_MIPS16, 
                strlen(IMAGE_FILE_MACHINE_MIPS16));
            break;
        case 0x366:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_MIPSFPU, 
                strlen(IMAGE_FILE_MACHINE_MIPSFPU));
            break;
        case 0x466:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_MIPSFPU16, 
                strlen(IMAGE_FILE_MACHINE_MIPSFPU16));
            break;
        case 0x1f0:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_POWERPC, 
                strlen(IMAGE_FILE_MACHINE_POWERPC));
            break;
        case 0x1f1:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_POWERPCFP, 
                strlen(IMAGE_FILE_MACHINE_POWERPCFP));
            break;
        case 0x166:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_R4000, 
                strlen(IMAGE_FILE_MACHINE_R4000));
            break;
        case 0x1a2:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_SH3, 
                strlen(IMAGE_FILE_MACHINE_SH3));
            break;
        case 0x1a3:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_SH3DSP, 
                strlen(IMAGE_FILE_MACHINE_SH3DSP));
            break;
        case 0x1a6:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_SH4, 
                strlen(IMAGE_FILE_MACHINE_SH4));
            break;
        case 0x1a8:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_SH5, 
                strlen(IMAGE_FILE_MACHINE_SH5));
            break;
        case 0x1c2:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_THUMB, 
                strlen(IMAGE_FILE_MACHINE_THUMB));
            break;
        case 0x169:
            strncpy(machine_type,  IMAGE_FILE_MACHINE_WCEMIPSV2, 
                strlen(IMAGE_FILE_MACHINE_WCEMIPSV2));
            break;
        default:
            strncpy(machine_type,  "...", strlen("..."));
            break;
    }
    
    return EXIT_SUCCESS;
}

int read_windows_subsystem_pe32(PE_Optional_Header* pe_opt_head, 
                                    char* subsystem)
{
    switch(pe_opt_head->Subsystem)
    {
        case 0:
            strncpy(subsystem, IMAGE_SUBSYSTEM_UNKNOWN, 
                strlen(IMAGE_SUBSYSTEM_UNKNOWN));
            break;
        case 1:
            strncpy(subsystem, IMAGE_SUBSYSTEM_NATIVE, 
                strlen(IMAGE_SUBSYSTEM_NATIVE));
            break;
        case 2:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_GUI));
            break;
        case 3:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_CUI));
            break;
        case 7:
            strncpy(subsystem, IMAGE_SUBSYSTEM_POSIX_CUI, 
                strlen(IMAGE_SUBSYSTEM_POSIX_CUI));
            break;
        case 9:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI));
            break;
        case 10:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_APPLICATION, 
                strlen(IMAGE_SUBSYSTEM_EFI_APPLICATION));
            break;
        case 11:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, 
                strlen(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER));
            break;
        case 12:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, 
                strlen(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER));
            break;
        case 13:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_ROM, 
                strlen(IMAGE_SUBSYSTEM_EFI_ROM));
            break;
        case 14:
            strncpy(subsystem, IMAGE_SUBSYSTEM_XBOX, 
                strlen(IMAGE_SUBSYSTEM_XBOX));
            break;
        default:
            strncpy(subsystem, "...", strlen("..."));
            break;
    }
  
    return EXIT_SUCCESS;
}

int read_windows_subsystem_pe32_plus(PE_Optional_Header_Plus* pe_opt_head, 
    char* subsystem)
{
    switch(pe_opt_head->Subsystem)
    {
        case 0:
            strncpy(subsystem, IMAGE_SUBSYSTEM_UNKNOWN, 
                strlen(IMAGE_SUBSYSTEM_UNKNOWN));
            break;
        case 1:
            strncpy(subsystem, IMAGE_SUBSYSTEM_NATIVE, 
                strlen(IMAGE_SUBSYSTEM_NATIVE));
            break;
        case 2:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_GUI));
            break;
        case 3:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_CUI));
            break;
        case 7:
            strncpy(subsystem, IMAGE_SUBSYSTEM_POSIX_CUI, 
                strlen(IMAGE_SUBSYSTEM_POSIX_CUI));
            break;
        case 9:
            strncpy(subsystem, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, 
                strlen(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI));
            break;
        case 10:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_APPLICATION, 
                strlen(IMAGE_SUBSYSTEM_EFI_APPLICATION));
            break;
        case 11:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, 
                strlen(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER));
            break;
        case 12:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, 
                strlen(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER));
            break;
        case 13:
            strncpy(subsystem, IMAGE_SUBSYSTEM_EFI_ROM, 
                strlen(IMAGE_SUBSYSTEM_EFI_ROM));
            break;
        case 14:
            strncpy(subsystem, IMAGE_SUBSYSTEM_XBOX, 
                strlen(IMAGE_SUBSYSTEM_XBOX));
            break;
        default:
            strncpy(subsystem, "...", strlen("..."));
            break;
    }
    
    return EXIT_SUCCESS;
}

int read_characteristics(PE_Header* pe_head, int* characteristics)
{
    //characteristics = malloc(sizeof(uint32_t) * 16);
  
    if(characteristics == NULL)
    {
        fprintf(stderr, "[ERROR] Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }
    
    int i = 0;
    
    for(i=0;i<16;i++)
    {
        if((pe_head->Characteristics & (1 << i)) == (1 << i))
        {
            characteristics[i] = 1;
        }
    }
  
    return EXIT_SUCCESS;
}

void print_characteristics(int* flags)
{
    if(flags[(int)log2(CHARACTERISTICS_RELOCS_STRIPPED)] == 1)
    {
        printf(IMAGE_FILE_RELOCS_STRIPPED);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_EXECUTABLE_IMAGE)] == 1)
    {
        printf(IMAGE_FILE_EXECUTABLE_IMAGE);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_LINE_NUMS_STRIPPED)] == 1)
    {
        printf(IMAGE_FILE_LINE_NUMS_STRIPPED);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_LOCAL_SYMS_STRIPPED)] == 1)
    {
        printf(IMAGE_FILE_LOCAL_SYMS_STRIPPED);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_AGGRESSIVE_WS_TRIM)] == 1)
    {
        printf(IMAGE_FILE_AGGRESSIVE_WS_TRIM);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_LARGE_ADDRESS_AWARE)] == 1)
    {
        printf(IMAGE_FILE_LARGE_ADDRESS_AWARE);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_reserved)] == 1)
    {
        printf("(reserved)\n");
    }

    if(flags[(int)log2(CHARACTERISTICS_BYTES_REVERSED_LO)] == 1)
    {
        printf(IMAGE_FILE_BYTES_REVERSED_LO);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_32BIT_MACHINE)] == 1)
    {
        printf(IMAGE_FILE_32BIT_MACHINE);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_DEBUG_STRIPPED)] == 1)
    {
        printf(IMAGE_FILE_DEBUG_STRIPPED);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_REMOVABLE_RUN_FROM_SWAP)] == 1)
    {
        printf(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_NET_RUN_FROM_SWAP)] == 1)
    {
        printf(IMAGE_FILE_NET_RUN_FROM_SWAP);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_SYSTEM)] == 1)
    {
        printf(IMAGE_FILE_SYSTEM);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_DLL)] == 1)
    {
        printf(IMAGE_FILE_DLL);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_UP_SYSTEM_ONLY)] == 1)
    {
        printf(IMAGE_FILE_UP_SYSTEM_ONLY);
        printf("\n");
    }
    
    if(flags[(int)log2(CHARACTERISTICS_BYTES_REVERSED_HI)] == 1)
    {
        printf(IMAGE_FILE_BYTES_REVERSED_HI);
        printf("\n");
    }
    
    //free(flags); // free the heap memory we declared in read_characteristics
}

int read_dll_characteristics_pe32(PE_Optional_Header* pe_opt_head, 
    int* characteristics)
{
    // characteristics = malloc(sizeof(uint32_t) * 16);
    
    if(characteristics == NULL)
    {
        fprintf(stderr, "[ERROR] Failed to allocate memory.\n");
        
        return EXIT_FAILURE;
    }
    
    int i = 0;
    
    for(i=0;i<16;i++)
    {
        if((pe_opt_head->DllCharacteristics & (1 << i)) == (1 << i))
        {
            characteristics[i] = 1;
        }
    }
    
    return EXIT_SUCCESS;
}

int read_dll_characteristics_pe32_plus(PE_Optional_Header_Plus* pe_opt_head, 
    int* characteristics)
{
    //characteristics = malloc(sizeof(uint32_t) * 16);
    
    if(characteristics == NULL)
    {
        fprintf(stderr, "[ERROR] Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }
    
    int i = 0;
    
    for(i=0;i<16;i++)
    {
        if((pe_opt_head->DllCharacteristics & (1 << i)) == (1 << i))
        {
        characteristics[i] = 1;
        }
    }
    
    return EXIT_SUCCESS;
}

void print_dll_characteristics(int* flags)
{
    if(flags[(int)log2(DLLCHARACTERISTICS_reserved1)] == 1)
    {
        printf("(reserved)\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_reserved2)] == 1)
    {
        printf("(reserved)\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_reserved3)] == 1)
    {
        printf("(reserved)\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_reserved4)] == 1)
    {
        printf("(reserved)\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_DYNAMIC_BASE)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_FORCE_INTEGRITY)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_NX_COMPAT)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_NO_ISOLATION)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_NO_SEH)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_NO_SEH);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_NO_BIND)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_NO_BIND);
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_reserved5)] == 1)
    {
        printf("(reserved)\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_WDM_DRIVER)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER);
        printf("\n");
    }
    
    if(flags[(int)log2(DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)] == 1)
    {
        printf(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);
        printf("\n");
    }
    
    /* free the heap memory we declared in read_dll_characteristics */
    /* free(flags); */
}                        