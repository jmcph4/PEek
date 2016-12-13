#ifndef UTILS_H_
#define UTILS_H_

#define DEFAULT_STR_LEN 128

int read_machine_type(PE_Header* pe_head, char* machine_type);
int read_windows_subsystem_pe32(PE_Optional_Header* pe_opt_head, 
    char* subsystem);
int read_windows_subsystem_pe32_plus(PE_Optional_Header_Plus* pe_opt_head, 
    char* subsystem);
int read_characteristics(PE_Header* pe_head, int* characteristics);
void print_characteristics(int* flags);
int read_dll_characteristics_pe32(PE_Optional_Header* pe_opt_head, 
    int* characteristics);
int read_dll_characteristics_pe32_plus(PE_Optional_Header_Plus* pe_opt_head, 
    int* characteristics);
void print_dll_characteristics(int* flags);

#endif /* UTILS_H_ */
