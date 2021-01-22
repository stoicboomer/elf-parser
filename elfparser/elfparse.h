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
    //Throwed if the file is not an actual elf file
    struct bad_elf_file : public std::exception{
        const char *err_msg;
        bad_elf_file(const char *msg) : err_msg(msg) {   }
        const char *what() const throw() { return err_msg; }
    };
    //Throwed if the program can't read the file
    struct bad_file : public std::exception{
        const char *what() const throw(){ return "Can't open/read the file"; }
    };


    const char *elf_path;
    FILE  *elf_file; 
    std::ifstream elf_ifstream;
    Elf64_Ehdr elf_hdr;

public:

    typedef std::vector<Elf64_Phdr> phdr_vector;
    typedef std::vector<Elf64_Shdr> shdr_vector;
    typedef std::vector<Elf64_Sym> sym_vector;

    ElfParse(const char* path);
    
	FILE *get_fd();

    void print_ehdr();
    void print_phdr();
    void print_shdr();
    //print all '\0' terminated strings in all STRTAB sections
    void print_strtab(bool offset);
	
    //get elf header
    Elf64_Ehdr get_ehdr();
    //get program header by index
    Elf64_Phdr get_phdr(size_t index);
    //get section header by index
    Elf64_Shdr get_shdr(size_t index);
	//get .strtab section
	Elf64_Shdr get_shstrtab();
	//read entry on .strtab at Elf64_Shdr->sh_name offset 
	std::string read_sh_name(size_t sh_name);
    
    //returns a vector containing all segments/sections
    phdr_vector dump_phdr();
    shdr_vector dump_shdr();
    //dump headers containing symbolic tables
    shdr_vector dump_symshdr();
    //dump all symbols
    sym_vector dump_sym();
    //same as print_strtab output, but returned as a stringstream
    std::stringstream dump_strtab();

    ~ElfParse();
};
#endif
