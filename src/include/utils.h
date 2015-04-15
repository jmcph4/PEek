#ifndef UTILS_H_
#define UTILS_H_
#include <math.h>

#include "headers.h"
#include "codes.h"

// Returns a C string containing a human-readable description of machine type
char* read_machine_type(PE_Header* pe_head)
{
  switch(pe_head->Machine)
  {
    case 0x0:
      return IMAGE_FILE_MACHINE_UNKNOWN;
      break;
    case 0x1d3:
      return IMAGE_FILE_MACHINE_AM33;
      break;
    case -31132:
      return IMAGE_FILE_MACHINE_AMD64;
      break;
    case 0x1c0:
      return IMAGE_FILE_MACHINE_ARM;
      break;
    case 0x1c4:
      return IMAGE_FILE_MACHINE_ARMNT;
      break;
    case 0xaa64:
      return IMAGE_FILE_MACHINE_ARM64;
      break;
    case 0xebc:
      return IMAGE_FILE_MACHINE_EBC;
      break;
    case 0x14c:
      return IMAGE_FILE_MACHINE_I386;
      break;
    case 0x200:
      return IMAGE_FILE_MACHINE_IA64;
      break;
    case 0x9041:
      return IMAGE_FILE_MACHINE_M32R;
      break;
    case 0x266:
      return IMAGE_FILE_MACHINE_MIPS16;
      break;
    case 0x366:
      return IMAGE_FILE_MACHINE_MIPSFPU;
      break;
    case 0x466:
      return IMAGE_FILE_MACHINE_MIPSFPU16;
      break;
    case 0x1f0:
      return IMAGE_FILE_MACHINE_POWERPC;
      break;
    case 0x1f1:
      return IMAGE_FILE_MACHINE_POWERPCFP;
      break;
    case 0x166:
      return IMAGE_FILE_MACHINE_R4000;
      break;
    case 0x1a2:
      return IMAGE_FILE_MACHINE_SH3;
      break;
    case 0x1a3:
      return IMAGE_FILE_MACHINE_SH3DSP;
      break;
    case 0x1a6:
      return IMAGE_FILE_MACHINE_SH4;
      break;
    case 0x1a8:
      return IMAGE_FILE_MACHINE_SH5;
      break;
    case 0x1c2:
      return IMAGE_FILE_MACHINE_THUMB;
      break;
    case 0x169:
      return IMAGE_FILE_MACHINE_WCEMIPSV2;
      break;
    default:
      return "...";
      break;
  }
}

char* read_windows_subsystem_pe32(PE_Optional_Header* pe_opt_head)
{
  switch(pe_opt_head->Subsystem)
  {
    case 0:
      return IMAGE_SUBSYSTEM_UNKNOWN;
      break;
    case 1:
      return IMAGE_SUBSYSTEM_NATIVE;
      break;
    case 2:
      return IMAGE_SUBSYSTEM_WINDOWS_GUI;
      break;
    case 3:
      return IMAGE_SUBSYSTEM_WINDOWS_CUI;
      break;
    case 7:
      return IMAGE_SUBSYSTEM_POSIX_CUI;
      break;
    case 9:
      return IMAGE_SUBSYSTEM_WINDOWS_CE_GUI;
      break;
    case 10:
      return IMAGE_SUBSYSTEM_EFI_APPLICATION;
      break;
    case 11:
      return IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER;
      break;
    case 12:
      return IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER;
      break;
    case 13:
      return IMAGE_SUBSYSTEM_EFI_ROM;
      break;
    case 14:
      return IMAGE_SUBSYSTEM_XBOX;
      break;
    default:
      return "...";
      break;
  }
}

char* read_windows_subsystem_pe32_plus(PE_Optional_Header_Plus* pe_opt_head)
{
  switch(pe_opt_head->Subsystem)
  {
    case 0:
      return "IMAGE_SUBSYSTEM_UNKNOWN";
      break;
    case 1:
      return "IMAGE_SUBSYSTEM_NATIVE";
      break;
    case 2:
      return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
      break;
    case 3:
      return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
      break;
    case 7:
      return "IMAGE_SUBSYSTEM_POSIX_CUI";
      break;
    case 9:
      return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
      break;
    case 10:
      return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
      break;
    case 11:
      return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
      break;
    case 12:
      return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
      break;
    case 13:
      return "IMAGE_SUBSYSTEM_EFI_ROM";
      break;
    case 14:
      return "IMAGE_SUBSYSTEM_XBOX";
      break;
    default:
      return "...";
      break;
  }
}

int* read_characteristics(PE_Header* pe_head)
{
  int* flags = (int*)malloc(16);
  int i = 0;
  int is_set = 0;
  
  for(i=0;i<16;i++)
  {
    if((pe_head->Characteristics & (1 << i)) == (1 << i))
    {
      flags[i] = 1;
    }
  }

  return flags;
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

  free(flags); // free the heap memory we declared in read_characteristics
}

#endif // UTILS_H_