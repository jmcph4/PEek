#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "include\headers.h"
#include "include\utils.h"
#include "include\codes.h"

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
    fprintf(stderr, "Failed to open file.\n");

    return EXIT_FAILURE;
  }

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  rewind(file);

  data = (char*)malloc(size * sizeof(char));

  if(data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory.\n");
  }

  int bytes_read = fread(data, sizeof(char), size, file);

  if(bytes_read < size)
  {
    perror("Failed to read file.\n");
  }

  if(size <= 133) // minimum size for a valid PE file
  {
    printf("Not a valid PE file.\n");
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
    printf("Not a valid PE file.\n");
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
    printf("Not a valid PE file.\n");
    return EXIT_SUCCESS;
  }

  time_t timestamp = (time_t)u.pe_head->TimeDateStamp;

  printf("PE HEADER INFORMATION\n");
  printf("Machine: %s\n", read_machine_type(u.pe_head));
  printf("NumberOfSections: %i\n", u.pe_head->NumberOfSections);
  printf("TimeDateStamp: %s", ctime(&timestamp));
  printf("PointerToSymbolTable: %#x\n", u.pe_head->PointerToSymbolTable);
  printf("NumberOfSymbols: %i\n", u.pe_head->NumberOfSymbols);
  printf("SizeOfOptionalHeader: %i\n", u.pe_head->SizeOfOptionalHeader);
  printf("Characteristics:\n");
  print_characteristics(read_characteristics(u.pe_head));

  if(u.pe_head->SizeOfOptionalHeader > 0)
  {
    printf("\nPE OPTIONAL HEADER INFORMATION ");

    int opt_head_start = *t.num + (24 * sizeof(char));
    int opt_head_end = opt_head_start + u.pe_head->SizeOfOptionalHeader;
    
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
      
      printf("MajorLinkerVersion: %i\n", w.pe_opt_head->MajorLinkerVersion);
      printf("MinorLinkerVersion: %i\n", w.pe_opt_head->MinorLinkerVersion);
      printf("SizeOfCode: %i\n", w.pe_opt_head->SizeOfCode);
      printf("SizeOfInitializedData: %i\n", w.pe_opt_head->SizeOfInitializedData);
      printf("SizeOfUninitializedData: %i\n", w.pe_opt_head->SizeOfUninitializedData);
      printf("AddressOfEntryPoint: %#x\n", w.pe_opt_head->AddressOfEntryPoint);
      printf("BaseOfCode: %#x\n", w.pe_opt_head->BaseOfCode);
      printf("ImageBase: %#x\n", w.pe_opt_head->ImageBase);
      printf("\n");
      printf("SectionAlignment: %i\n", w.pe_opt_head->SectionAlignment);
      printf("FileAlignment: %i\n", w.pe_opt_head->FileAlignment);
      printf("MajorOperatingSystemVersion: %i\n", w.pe_opt_head->MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %i\n", w.pe_opt_head->MinorOperatingSystemVersion);
      printf("MajorImageVersion: %i\n", w.pe_opt_head->MajorImageVersion);
      printf("MinorImageVersion: %i\n", w.pe_opt_head->MinorImageVersion);
      printf("MajorSubsystemVersion: %i\n", w.pe_opt_head->MajorSubsystemVersion);
      printf("MinorSubsystemVersion: %i\n", w.pe_opt_head->MinorSubsystemVersion);
      printf("Win32VersionValue: %i\n", w.pe_opt_head->Win32VersionValue);
      printf("SizeOfImage: %i\n", w.pe_opt_head->SizeOfImage);
      printf("SizeOfHeaders: %i\n", w.pe_opt_head->SizeOfHeaders);
      printf("CheckSum: %i\n", w.pe_opt_head->CheckSum);
      printf("Subsystem: %s\n", read_windows_subsystem_pe32(w.pe_opt_head));
      // DLL characteristics
      printf("SizeOfStackReserve: %i\n", w.pe_opt_head->SizeOfStackReserve);
      printf("SizeOfStackCommit: %i\n", w.pe_opt_head->SizeOfStackCommit);
      printf("SizeOfHeapReserve: %i\n", w.pe_opt_head->SizeOfHeapReserve);
      printf("LoaderFlags: %i\n", w.pe_opt_head->LoaderFlags);
      printf("NumberOfRvaAndSizes: %i\n", w.pe_opt_head->NumberOfRvaAndSizes);
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
      
      printf("MajorLinkerVersion: %i\n", w.pe_opt_head->MajorLinkerVersion);
      printf("MinorLinkerVersion: %i\n", w.pe_opt_head->MinorLinkerVersion);
      printf("SizeOfCode: %i\n", w.pe_opt_head->SizeOfCode);
      printf("SizeOfInitializedData: %i\n", w.pe_opt_head->SizeOfInitializedData);
      printf("SizeOfUninitializedData: %i\n", w.pe_opt_head->SizeOfUninitializedData);
      printf("AddressOfEntryPoint: %#x\n", w.pe_opt_head->AddressOfEntryPoint);
      printf("BaseOfCode: %#x\n", w.pe_opt_head->BaseOfCode);
      printf("ImageBase: %#x\n", w.pe_opt_head->ImageBase);
      printf("\n");
      printf("SectionAlignment: %i\n", w.pe_opt_head->SectionAlignment);
      printf("FileAlignment: %i\n", w.pe_opt_head->FileAlignment);
      printf("MajorOperatingSystemVersion: %i\n", w.pe_opt_head->MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %i\n", w.pe_opt_head->MinorOperatingSystemVersion);
      printf("MajorImageVersion: %i\n", w.pe_opt_head->MajorImageVersion);
      printf("MinorImageVersion: %i\n", w.pe_opt_head->MinorImageVersion);
      printf("MajorSubsystemVersion: %i\n", w.pe_opt_head->MajorSubsystemVersion);
      printf("MinorSubsystemVersion: %i\n", w.pe_opt_head->MinorSubsystemVersion);
      printf("Win32VersionValue: %i\n", w.pe_opt_head->Win32VersionValue);
      printf("SizeOfImage: %i\n", w.pe_opt_head->SizeOfImage);
      printf("SizeOfHeaders: %i\n", w.pe_opt_head->SizeOfHeaders);
      printf("CheckSum: %i\n", w.pe_opt_head->CheckSum);
      printf("Subsystem: %s\n", read_windows_subsystem_pe32_plus(w.pe_opt_head));
      // DLL characteristics
      printf("SizeOfStackReserve: %i\n", w.pe_opt_head->SizeOfStackReserve);
      printf("SizeOfStackCommit: %i\n", w.pe_opt_head->SizeOfStackCommit);
      printf("SizeOfHeapReserve: %i\n", w.pe_opt_head->SizeOfHeapReserve);
      printf("LoaderFlags: %i\n", w.pe_opt_head->LoaderFlags);
      printf("NumberOfRvaAndSizes: %i\n", w.pe_opt_head->NumberOfRvaAndSizes);
    }

  }

  free(data);
  
  return EXIT_SUCCESS;
}