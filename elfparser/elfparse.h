#ifndef ELF_PARSE
#define ELF_PARSE

#define ELF64_EHDR_SIZE 64
#define ELF32_EHDR_SIZE 32

#include <elf.h>

#include <cstring>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <exception>
#include <fstream>
#include <iomanip>

/* PARSER CLASS */

class ElfParse{
    /* EXCEPTIONS */
    struct bad_elf_file : public std::exception{
        const char *err_msg;
        bad_elf_file(const char *msg) : err_msg(msg) {   }
        const char *what() const throw() { return err_msg; }
    };
    struct bad_file : public std::exception{
        const char *what() const throw(){ return "Can't open/read the file"; }
    };

    const char *elf_path;
    FILE  *elf_file; 
    Elf64_Ehdr elf_hdr;

public:

    typedef std::vector<Elf64_Phdr> phdr_vector;
    typedef std::vector<Elf64_Shdr> shdr_vector;
    typedef std::vector<Elf64_Sym>  sym_vector;

    ElfParse(const char* path);
    
	FILE *get_fd();
    
    //print formatted elf header
    void print_ehdr();
    //print formatted program headers
    void print_phdr();
    //print formatted section headers
    void print_shdr();
    //print all strings contained in the STRTAB sections (.rodata is not parsed)
    void print_strtab(bool offset, bool wich_section=false);
    //TODO: print all formatted symbols
    void print_sym();
	
    //get elf header
    Elf64_Ehdr get_ehdr();
    //get program header by index
    Elf64_Phdr get_phdr(size_t index);
    //get section header by index
    Elf64_Shdr get_shdr(size_t index);
	//get .shstrtab section
	Elf64_Shdr get_shstrtab();
	//get section name on .shstrtab
	std::string get_sh_name(size_t sh_name);
    //TODO: get symbol name 
    std::string get_sym_name(size_t st_name, size_t sh_offset);
    
    //dump all program/section headers
    phdr_vector dump_phdr();
    shdr_vector dump_shdr();
    //dump by specific program/section header type
    //check the elf manual for reference
    phdr_vector dump_phdr_type(unsigned int type);
    shdr_vector dump_shdr_type(unsigned int type);

    //dump all symbols
    sym_vector dump_sym();
    //same as print_strtab output, but returned as a stringstream
    std::stringstream dump_strtab(bool offset, bool wich_section=false);

    ~ElfParse();
};
#endif
