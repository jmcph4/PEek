#ifndef HEADERS_H_
#define HEADERS_H_
// Deviating from my usual snake_case style solely to closely match the MS spec
// http://download.microsoft.com/download/e/b/a/eba1050f-a31d-436b-9281-92cdfe
// ae4b45/pecoff.doc
typedef struct PE_Header
{
  char sig[4 * sizeof(char)]; // 4B
  unsigned short Machine; // 2B
  short NumberOfSections; // 2B
  int TimeDateStamp; // 4B
  int PointerToSymbolTable; // 4B
  int NumberOfSymbols; // 4B
  short SizeOfOptionalHeader; // 2B
  short Characteristics; // 2B
} PE_Header;

typedef struct PE_Data_Directory
{
  unsigned int RVA;
  unsigned int Size;
} PE_Data_Directory;

typedef struct PE_Optional_Header
{
  // standard fields
  unsigned short Magic;
  unsigned char MajorLinkerVersion;
  unsigned char MinorLinkerVersion;
  unsigned int SizeOfCode;
  unsigned int SizeOfInitializedData;
  unsigned int SizeOfUninitializedData;
  unsigned int AddressOfEntryPoint;
  unsigned int BaseOfCode;
  unsigned int BaseOfData;

  // Windows-specific
  unsigned int ImageBase;
  unsigned int SectionAlignment;
  unsigned int FileAlignment;
  unsigned short MajorOperatingSystemVersion;
  unsigned short MinorOperatingSystemVersion;
  unsigned short MajorImageVersion;
  unsigned short MinorImageVersion;
  unsigned short MajorSubsystemVersion;
  unsigned short MinorSubsystemVersion;
  unsigned int Win32VersionValue;
  unsigned int SizeOfImage;
  unsigned int SizeOfHeaders;
  unsigned int CheckSum;
  unsigned short Subsystem;
  unsigned short DllCharacteristics;
  unsigned int SizeOfStackReserve;
  unsigned int SizeOfStackCommit;
  unsigned int SizeOfHeapReserve;
  unsigned int SizeOfHeapCommit;
  unsigned int LoaderFlags;
  unsigned int NumberOfRvaAndSizes;

  // data directories
  PE_Data_Directory ExportTable;
  PE_Data_Directory ImportTable;
  PE_Data_Directory ResourceTable;
  PE_Data_Directory ExceptionTable;
  PE_Data_Directory CertificateTable;
  PE_Data_Directory BaseRelocationTable;
  PE_Data_Directory Debug;
  PE_Data_Directory Architecture;
  PE_Data_Directory GlobalPtr;
  PE_Data_Directory TLSTable;
  PE_Data_Directory LoadConfigTable;
  PE_Data_Directory BoundImport;
  PE_Data_Directory IAT;
  PE_Data_Directory DelayImportDescriptor;
  PE_Data_Directory CLRRuntimeHeader;
  PE_Data_Directory reserved;
} PE_Optional_Header;

typedef struct PE_Optional_Header_Plus
{
  // standard fields
  unsigned short Magic;
  unsigned char MajorLinkerVersion;
  unsigned char MinorLinkerVersion;
  unsigned int SizeOfCode;
  unsigned int SizeOfInitializedData;
  unsigned int SizeOfUninitializedData;
  unsigned int AddressOfEntryPoint;
  unsigned int BaseOfCode;
  unsigned int BaseOfData;

  // Windows-specific
  unsigned long ImageBase;
  unsigned int SectionAlignment;
  unsigned int FileAlignment;
  unsigned short MajorOperatingSystemVersion;
  unsigned short MinorOperatingSystemVersion;
  unsigned short MajorImageVersion;
  unsigned short MinorImageVersion;
  unsigned short MajorSubsystemVersion;
  unsigned short MinorSubsystemVersion;
  unsigned int Win32VersionValue;
  unsigned int SizeOfImage;
  unsigned int SizeOfHeaders;
  unsigned int CheckSum;
  unsigned short Subsystem;
  unsigned short DllCharacteristics;
  unsigned long SizeOfStackReserve;
  unsigned long SizeOfStackCommit;
  unsigned long SizeOfHeapReserve;
  unsigned long SizeOfHeapCommit;
  unsigned int LoaderFlags;
  unsigned int NumberOfRvaAndSizes;

  // data directories
  PE_Data_Directory ExportTable;
  PE_Data_Directory ImportTable;
  PE_Data_Directory ResourceTable;
  PE_Data_Directory ExceptionTable;
  PE_Data_Directory CertificateTable;
  PE_Data_Directory BaseRelocationTable;
  PE_Data_Directory Debug;
  PE_Data_Directory Architecture;
  PE_Data_Directory GlobalPtr;
  PE_Data_Directory TLSTable;
  PE_Data_Directory LoadConfigTable;
  PE_Data_Directory BoundImport;
  PE_Data_Directory IAT;
  PE_Data_Directory DelayImportDescriptor;
  PE_Data_Directory CLRRuntimeHeader;
  PE_Data_Directory reserved;
} PE_Optional_Header_Plus;
#endif // HEADERS_H_
