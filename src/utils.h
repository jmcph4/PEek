#ifndef UTILS_H_
#define UTILS_H_
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
#endif // UTILS_H_