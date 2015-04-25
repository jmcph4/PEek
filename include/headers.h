#ifndef HEADERS_H_
#define HEADERS_H_
// Deviating from my usual snake_case style solely to closely match the MS spec
// http://download.microsoft.com/download/e/b/a/eba1050f-a31d-436b-9281-92cdfe
// ae4b45/pecoff.doc
typedef struct PE_Header
{
  char sig[4 * sizeof(char)]; // 4B
  short Machine; // 2B
  short NumberOfSections; // 2B
  int TimeDateStamp; // 4B
  int PointerToSymbolTable; // 4B
  int NumberOfSymbols; // 4B
  short SizeOfOptionalHeader; // 2B
  short Characteristics; // 2B
} PE_Header;

typedef struct PE_Optional_Header
{
  // standard fields
  short Magic;
  char MajorLinkerVersion;
  char MinorLinkerVersion;
  int SizeOfCode;
  int SizeOfInitializedData;
  int SizeOfUninitializedData;
  int AddressOfEntryPoint;
  int BaseOfCode;
  int BaseOfData;

  // Windows-specific
  int ImageBase;
  int SectionAlignment;
  int FileAlignment;
  short MajorOperatingSystemVersion;
  short MinorOperatingSystemVersion;
  short MajorImageVersion;
  short MinorImageVersion;
  short MajorSubsystemVersion;
  short MinorSubsystemVersion;
  int Win32VersionValue;
  int SizeOfImage;
  int SizeOfHeaders;
  int CheckSum;
  short Subsystem;
  short DllCharacteristics;
  int SizeOfStackReserve;
  int SizeOfStackCommit;
  int SizeOfHeapReserve;
  int SizeOfHeapCommit;
  int LoaderFlags;
  int NumberOfRvaAndSizes;

  // data directories
  long ExportTable;
  long ImportTable;
  long ResourceTable;
  long ExceptionTable;
  long CertificateTable;
  long BaseRelocationTable;
  long Debug;
  long Architecture;
  long GlobalPtr;
  long TLSTable;
  long LoadConfigTable;
  long BoundImport;
  long IAT;
  long DelayImportDescriptor;
  long CLRRuntimeHeader;
  long reserved;
} PE_Optional_Header;

typedef struct PE_Optional_Header_Plus
{
  // standard fields
  short Magic;
  char MajorLinkerVersion;
  char MinorLinkerVersion;
  int SizeOfCode;
  int SizeOfInitializedData;
  int SizeOfUninitializedData;
  int AddressOfEntryPoint;
  int BaseOfCode;
  int BaseOfData;

  // Windows-specific
  long ImageBase;
  int SectionAlignment;
  int FileAlignment;
  short MajorOperatingSystemVersion;
  short MinorOperatingSystemVersion;
  short MajorImageVersion;
  short MinorImageVersion;
  short MajorSubsystemVersion;
  short MinorSubsystemVersion;
  int Win32VersionValue;
  int SizeOfImage;
  int SizeOfHeaders;
  int CheckSum;
  short Subsystem;
  short DllCharacteristics;
  long SizeOfStackReserve;
  long SizeOfStackCommit;
  long SizeOfHeapReserve;
  long SizeOfHeapCommit;
  int LoaderFlags;
  int NumberOfRvaAndSizes;

  // data directories
  long ExportTable;
  long ImportTable;
  long ResourceTable;
  long ExceptionTable;
  long CertificateTable;
  long BaseRelocationTable;
  long Debug;
  long Architecture;
  long GlobalPtr;
  long TLSTable;
  long LoadConfigTable;
  long BoundImport;
  long IAT;
  long DelayImportDescriptor;
  long CLRRuntimeHeader;
  long reserved;
} PE_Optional_Header_Plus;
#endif // HEADERS_H_