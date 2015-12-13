#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "headers.h"
#include "utils.h"
#include "codes.h"

int main(int argc, char** argv)
{
  if(argc < 2)
  {
    // usage
    printf("Usage: %s file\n", argv[0]);
  }

  const char* filename = argv[1];
  FILE* file = fopen(filename, "rb");
  long size = 0;
  char* data;

  if(!file)
  {
    fprintf(stderr, "[ERROR] Failed to open file.\n");

    return EXIT_FAILURE;
  }

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  rewind(file);

  data = (char*)malloc(size * sizeof(char));

  if(data == NULL)
  {
    fprintf(stderr, "[ERROR] Failed to allocate memory.\n");
  }

  int bytes_read = fread(data, sizeof(char), size, file);

  if(bytes_read < size)
  {
    fprintf(stderr, "[ERROR] Failed to read file.\n");
  }

  if(size <= 133) // minimum size for a valid PE file
  {
    fprintf(stderr, "[ERROR] Not a valid PE file.\n");
    return EXIT_SUCCESS;
  }

  union
  {
    char* ptr;
    int* num;
  }t;

  t.ptr = &data[60];

  if((*t.num + 3) > size) // check bounds
  {
    fprintf(stderr, "[ERROR] Not a valid PE file.\n");
    return EXIT_SUCCESS;
  }

  char pe_sig[4] = {data[*t.num], data[*t.num+1], 
    data[*t.num+2], data[*t.num+3]};

  union
  {
    PE_Header* pe_head;
    char* data;
  }u;

  u.data = &data[*t.num];

  if(strcmp(pe_sig, "PE") != 0)
  {
    fprintf(stderr, "[ERROR] Not a valid PE file.\n");
    return EXIT_SUCCESS;
  }

  time_t timestamp = (time_t)u.pe_head->TimeDateStamp;

  printf("%s:\n\n", argv[1]);
  printf("PE HEADER INFORMATION\n");
  printf("Machine: %s\n", read_machine_type(u.pe_head));
  printf("NumberOfSections: %d\n", u.pe_head->NumberOfSections);
  printf("TimeDateStamp: %s", ctime(&timestamp));
  printf("PointerToSymbolTable: %#x\n", u.pe_head->PointerToSymbolTable);
  printf("NumberOfSymbols: %d\n", u.pe_head->NumberOfSymbols);
  printf("SizeOfOptionalHeader: %d\n", u.pe_head->SizeOfOptionalHeader);
  printf("Characteristics:\n");
  print_characteristics(read_characteristics(u.pe_head));

  if(u.pe_head->SizeOfOptionalHeader > 0)
  {
    printf("\nPE OPTIONAL HEADER INFORMATION ");

    int opt_head_start = *t.num + (24 * sizeof(char));
    //int opt_head_end = opt_head_start + u.pe_head->SizeOfOptionalHeader;
    
    char magic_str[2] = {data[opt_head_start], data[opt_head_start+1]};

    union 
    {
      char* str;
      short* magic;
    }v;

    v.str = magic_str;
    
    if(*v.magic == 0x10b)
    {
      // PE32
      printf("(PE32)\n");

      union
      {
        PE_Optional_Header* pe_opt_head;
        char* data;
      }w;

      w.data = &data[opt_head_start];
      
      printf("MajorLinkerVersion: %d\n", w.pe_opt_head->MajorLinkerVersion);
      printf("MinorLinkerVersion: %d\n", w.pe_opt_head->MinorLinkerVersion);
      printf("SizeOfCode: %d\n", w.pe_opt_head->SizeOfCode);
      printf("SizeOfInitializedData: %d\n", w.pe_opt_head->SizeOfInitializedData);
      printf("SizeOfUninitializedData: %d\n", w.pe_opt_head->SizeOfUninitializedData);
      printf("AddressOfEntryPoint: %#x\n", w.pe_opt_head->AddressOfEntryPoint);
      printf("BaseOfCode: %#x\n", w.pe_opt_head->BaseOfCode);
      printf("ImageBase: %#x\n", w.pe_opt_head->ImageBase);
      printf("\n");
      printf("SectionAlignment: %d\n", w.pe_opt_head->SectionAlignment);
      printf("FileAlignment: %d\n", w.pe_opt_head->FileAlignment);
      printf("MajorOperatingSystemVersion: %d\n", w.pe_opt_head->MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %d\n", w.pe_opt_head->MinorOperatingSystemVersion);
      printf("MajorImageVersion: %d\n", w.pe_opt_head->MajorImageVersion);
      printf("MinorImageVersion: %d\n", w.pe_opt_head->MinorImageVersion);
      printf("MajorSubsystemVersion: %d\n", w.pe_opt_head->MajorSubsystemVersion);
      printf("MinorSubsystemVersion: %d\n", w.pe_opt_head->MinorSubsystemVersion);
      printf("Win32VersionValue: %d\n", w.pe_opt_head->Win32VersionValue);
      printf("SizeOfImage: %d\n", w.pe_opt_head->SizeOfImage);
      printf("SizeOfHeaders: %d\n", w.pe_opt_head->SizeOfHeaders);
      printf("CheckSum: %d\n", w.pe_opt_head->CheckSum);
      printf("Subsystem: %s\n", read_windows_subsystem_pe32(w.pe_opt_head));
      printf("DLLCharacteristics:\n");
      print_dll_characteristics(read_dll_characteristics_pe32(w.pe_opt_head));
      printf("SizeOfStackReserve: %d\n", w.pe_opt_head->SizeOfStackReserve);
      printf("SizeOfStackCommit: %d\n", w.pe_opt_head->SizeOfStackCommit);
      printf("SizeOfHeapReserve: %d\n", w.pe_opt_head->SizeOfHeapReserve);
      printf("LoaderFlags: %d\n", w.pe_opt_head->LoaderFlags);
      printf("NumberOfRvaAndSizes: %d\n", w.pe_opt_head->NumberOfRvaAndSizes);
      
      printf("Data Directories:\n");
      printf("  ExportTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ExportTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ExportTable.Size);
      printf("  ImportTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ImportTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ImportTable.Size);
      printf("  ResourceTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ResourceTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ResourceTable.Size);
      printf("  ExceptionTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ExceptionTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ExceptionTable.Size);
      printf("  CertificateTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->CertificateTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->CertificateTable.Size);
      printf("  BaseRelocationTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->BaseRelocationTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->BaseRelocationTable.Size);
      printf("  Debug:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->Debug.RVA);
      printf("    Size: %d\n", w.pe_opt_head->Debug.Size);
      printf("  Architecture:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->Architecture.RVA);
      printf("    Size: %d\n", w.pe_opt_head->Architecture.Size);
      printf("  GlobalPtr:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->GlobalPtr.RVA);
      printf("    Size: %d\n", w.pe_opt_head->GlobalPtr.Size);
      printf("  TLSTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->TLSTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->TLSTable.Size);
      printf("  LoadConfigTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->LoadConfigTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->LoadConfigTable.Size);
      printf("  BoundImport:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->BoundImport.RVA);
      printf("    Size: %d\n", w.pe_opt_head->BoundImport.Size);
      printf("  IAT:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->IAT.RVA);
      printf("    Size: %d\n", w.pe_opt_head->IAT.Size);
      printf("  DelayImportDescriptor:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->DelayImportDescriptor.RVA);
      printf("    Size: %d\n", w.pe_opt_head->DelayImportDescriptor.Size);
      printf("  CLRRuntimeHeader:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->CLRRuntimeHeader.RVA);
      printf("    Size: %d\n", w.pe_opt_head->CLRRuntimeHeader.Size);
      printf("  (reserved):\n");
      printf("    RVA: %#x\n", w.pe_opt_head->reserved.RVA);
      printf("    Size: %d\n", w.pe_opt_head->reserved.Size);
    }
    else if(*v.magic == 0x20b)
    {
      // PE32+
      printf("(PE32+)\n");

      union
      {
        PE_Optional_Header_Plus* pe_opt_head;
        char* data;
      }w;

      w.data = &data[opt_head_start];
      
      printf("MajorLinkerVersion: %d\n", w.pe_opt_head->MajorLinkerVersion);
      printf("MinorLinkerVersion: %d\n", w.pe_opt_head->MinorLinkerVersion);
      printf("SizeOfCode: %d\n", w.pe_opt_head->SizeOfCode);
      printf("SizeOfInitializedData: %d\n", w.pe_opt_head->SizeOfInitializedData);
      printf("SizeOfUninitializedData: %d\n", w.pe_opt_head->SizeOfUninitializedData);
      printf("AddressOfEntryPoint: %#x\n", w.pe_opt_head->AddressOfEntryPoint);
      printf("BaseOfCode: %#x\n", w.pe_opt_head->BaseOfCode);
      printf("ImageBase: %#lx\n", w.pe_opt_head->ImageBase);
      printf("\n");
      printf("SectionAlignment: %d\n", w.pe_opt_head->SectionAlignment);
      printf("FileAlignment: %d\n", w.pe_opt_head->FileAlignment);
      printf("MajorOperatingSystemVersion: %d\n", w.pe_opt_head->MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %d\n", w.pe_opt_head->MinorOperatingSystemVersion);
      printf("MajorImageVersion: %d\n", w.pe_opt_head->MajorImageVersion);
      printf("MinorImageVersion: %d\n", w.pe_opt_head->MinorImageVersion);
      printf("MajorSubsystemVersion: %d\n", w.pe_opt_head->MajorSubsystemVersion);
      printf("MinorSubsystemVersion: %d\n", w.pe_opt_head->MinorSubsystemVersion);
      printf("Win32VersionValue: %d\n", w.pe_opt_head->Win32VersionValue);
      printf("SizeOfImage: %d\n", w.pe_opt_head->SizeOfImage);
      printf("SizeOfHeaders: %d\n", w.pe_opt_head->SizeOfHeaders);
      printf("CheckSum: %d\n", w.pe_opt_head->CheckSum);
      printf("Subsystem: %s\n", read_windows_subsystem_pe32_plus(w.pe_opt_head));
      printf("DLLCharacteristics:\n");
      print_dll_characteristics(read_dll_characteristics_pe32_plus(w.pe_opt_head));
      printf("SizeOfStackReserve: %ld\n", w.pe_opt_head->SizeOfStackReserve);
      printf("SizeOfStackCommit: %ld\n", w.pe_opt_head->SizeOfStackCommit);
      printf("SizeOfHeapReserve: %ld\n", w.pe_opt_head->SizeOfHeapReserve);
      printf("LoaderFlags: %d\n", w.pe_opt_head->LoaderFlags);
      printf("NumberOfRvaAndSizes: %d\n", w.pe_opt_head->NumberOfRvaAndSizes);
      
      printf("Data Directories:\n");
      printf("  ExportTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ExportTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ExportTable.Size);
      printf("  ImportTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ImportTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ImportTable.Size);
      printf("  ResourceTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ResourceTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ResourceTable.Size);
      printf("  ExceptionTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->ExceptionTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->ExceptionTable.Size);
      printf("  CertificateTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->CertificateTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->CertificateTable.Size);
      printf("  BaseRelocationTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->BaseRelocationTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->BaseRelocationTable.Size);
      printf("  Debug:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->Debug.RVA);
      printf("    Size: %d\n", w.pe_opt_head->Debug.Size);
      printf("  Architecture:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->Architecture.RVA);
      printf("    Size: %d\n", w.pe_opt_head->Architecture.Size);
      printf("  GlobalPtr:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->GlobalPtr.RVA);
      printf("    Size: %d\n", w.pe_opt_head->GlobalPtr.Size);
      printf("  TLSTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->TLSTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->TLSTable.Size);
      printf("  LoadConfigTable:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->LoadConfigTable.RVA);
      printf("    Size: %d\n", w.pe_opt_head->LoadConfigTable.Size);
      printf("  BoundImport:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->BoundImport.RVA);
      printf("    Size: %d\n", w.pe_opt_head->BoundImport.Size);
      printf("  IAT:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->IAT.RVA);
      printf("    Size: %d\n", w.pe_opt_head->IAT.Size);
      printf("  DelayImportDescriptor:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->DelayImportDescriptor.RVA);
      printf("    Size: %d\n", w.pe_opt_head->DelayImportDescriptor.Size);
      printf("  CLRRuntimeHeader:\n");
      printf("    RVA: %#x\n", w.pe_opt_head->CLRRuntimeHeader.RVA);
      printf("    Size: %d\n", w.pe_opt_head->CLRRuntimeHeader.Size);
      printf("  (reserved):\n");
      printf("    RVA: %#x\n", w.pe_opt_head->reserved.RVA);
      printf("    Size: %d\n", w.pe_opt_head->reserved.Size);
    }
  }

  free(data);
  
  return EXIT_SUCCESS;
}
