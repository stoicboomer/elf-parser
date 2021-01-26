#include "elfparse.h"
#include "decoders.h"

ElfParse::ElfParse(const char *path) : elf_path(path){
    if ((elf_file = fopen(path, "rb")) == NULL){
        throw bad_file();     
    }
    int n = fread(&elf_hdr, ELF64_EHDR_SIZE, 1, elf_file);
    //Did we at least read an entire header?
    if (!n){
        throw bad_elf_file("Invalid elf file");
    }
    //check magic bytes
    if (memcmp(elf_hdr.e_ident, ELFMAG, 4) != 0){
        throw bad_elf_file("Invalid elf file");
    } 
    //for the sake of simplicity this parser for now will
    //support only 64-bit elf files
    if (elf_hdr.e_ident[EI_CLASS] != ELFCLASS64){
        throw bad_elf_file("Invalid architecture (Use only 64-bit)");
    }
    //check elf version
    if (elf_hdr.e_ident[EI_VERSION] != EV_CURRENT){
        throw bad_elf_file("Unsupported ELF version");
    } 
    rewind(elf_file);
}

FILE *ElfParse::get_fd(){
	return elf_file;
}

/* formatting stuff, boring. */
void ElfParse::print_ehdr(){
    push_fmt();
    std::cout << std::left << std::hex << std::showbase 
              << "ELF Header:\n"					
              << std::setw(5)  << "  Magic:     ";              print_ident(elf_hdr.e_ident);
    std::cout << std::setw(35) << "  Class:"                    << decode_ei_class(elf_hdr.e_ident) 	<< std::endl
              << std::setw(35) << "  OS/ABI:"                   << decode_ei_osabi(elf_hdr.e_ident) 	<< std::endl
              << std::setw(35) << "  Type:"                     << decode_e_type(elf_hdr.e_type)        << std::endl
              << std::setw(35) << "  Machine:"                  << decode_e_machine(elf_hdr.e_machine)  << std::endl 
              << std::setw(35) << "  Data encoding:"            << decode_ei_data(elf_hdr.e_ident)      << std::endl
              << std::setw(35) << "  Version:"                  << elf_hdr.e_version                	<< std::endl
              << std::setw(35) << "  Flags:"                    << elf_hdr.e_flags                      << std::endl
              << std::setw(35) << "  Entry point addr:"         << elf_hdr.e_entry                  	<< std::endl
              << std::setw(35) << "  Elf header size:"          << elf_hdr.e_ehsize                     << std::endl
                               << "  Program header:\n" 
                               << "    - offset: "              << elf_hdr.e_phoff                      << std::endl
                               << "    - size:   "              << elf_hdr.e_phentsize                  << std::endl
                               << "    - count:  "              << elf_hdr.e_phnum                      << std::endl
                               << "  Section header:\n"
                               << "    - offset: "              << elf_hdr.e_shoff                      << std::endl
                               << "    - size:   "              << elf_hdr.e_shentsize                  << std::endl
                               << "    - count:  "              << elf_hdr.e_shnum                      << std::endl;
    pop_fmt();
}

void ElfParse::print_phdr(){
    puts("    offset      size     vaddr       vsize    perm name\n"
         "―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
    for (int i = 0; i < elf_hdr.e_phnum; i++){
        Elf64_Phdr phdr = get_phdr(i);

        printf("%-3d 0x%08x  0x%-6x 0x%08x  0x%-6x ", i, phdr.p_offset, 
                phdr.p_filesz, phdr.p_vaddr, phdr.p_memsz); 
        print_p_flags(phdr.p_flags);
        printf("  %s\n", decode_p_type(phdr.p_type));
    }
}

void ElfParse::print_shdr(){
    puts("    offset      size   vaddr       type       name         \n"
         "―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        printf("%-3d 0x%08x  0x%-6x 0x%08x  %-10s %s\n", i, shdr.sh_offset, 
                shdr.sh_size, shdr.sh_addr, decode_sh_type(shdr.sh_type),
				get_sh_name(shdr.sh_name).c_str()); 
    }
}

void ElfParse::print_strtab(bool offset, bool wich_section){
    std::cout << dump_strtab(offset, wich_section).str();
}

/*
NOTE:
    The shdr sh_link member in the SHT_SYMBTA and SHT_DYNSYM
    sections contains the section header index of the associated 
    string table where we can extract the string name of the symbols.

*/
void ElfParse::print_sym(){
    puts("     value      bind     type     size  name         \n"
         "―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM){
            //get associated strtab
            Elf64_Shdr strtab = get_shdr(shdr.sh_link);
            //start reading symbolic entries, 
            //we fseek in the loop because get_sym_name() rewinds the file
            fseek(elf_file, shdr.sh_offset, SEEK_SET);
            for (int j = 1; ftell(elf_file) < (shdr.sh_offset + shdr.sh_size); j++){
                Elf64_Sym sym;
                fread(&sym, shdr.sh_entsize, 1, elf_file); 

                printf("%-4d 0x%08x %-8s %-8s %-5d %s\n", j-1, sym.st_value,
                        decode_st_bind(sym.st_info), decode_st_type(sym.st_info),
                        sym.st_size, get_sym_name(sym.st_name, strtab.sh_offset).c_str());

                fseek(elf_file, shdr.sh_offset + (shdr.sh_entsize * j), SEEK_SET);
            }
        }
    }
}

Elf64_Ehdr ElfParse::get_ehdr(){
    return elf_hdr;
}

/* The elf header contains sizes and offsets and
    number entries for every program and section header.
    By using offsets and sizes, we can extract every single
    Elf64_Phdr and Elf64_Shdr structs. read the man elf page
    for other info about the struct itself.
*/
Elf64_Phdr ElfParse::get_phdr(size_t index){
    if (index < 0 || index >= elf_hdr.e_phnum)
        throw std::out_of_range("ElfParse::get_phdr(): program header out of range");
    
    Elf64_Phdr phdr;            
    fseek(elf_file, elf_hdr.e_phoff + (elf_hdr.e_phentsize * index), SEEK_SET);
    fread(&phdr, elf_hdr.e_phentsize, 1, elf_file);
    rewind(elf_file); 
    return phdr;
}

Elf64_Shdr ElfParse::get_shdr(size_t index){
    if (index < 0 || index >= elf_hdr.e_shnum)
        throw std::out_of_range("ElfParse::get_shdr(): section header out of range");
    
    Elf64_Shdr shdr;
    fseek(elf_file, elf_hdr.e_shoff + (elf_hdr.e_shentsize * index), SEEK_SET);
    fread(&shdr, elf_hdr.e_shentsize, 1, elf_file);
    rewind(elf_file); 
    return shdr;
}

/*
    .shstrtab is a string table section, containing the 
    sections names of the binary. es: .rodata, .text etc.
*/
Elf64_Shdr ElfParse::get_shstrtab(){
    Elf64_Shdr shdr;
    if (elf_hdr.e_shstrndx == SHN_UNDEF){
        memset(&shdr, sizeof(Elf64_Shdr), 0);
        return shdr;
    } 
    fseek(elf_file, elf_hdr.e_shoff + (elf_hdr.e_shentsize * elf_hdr.e_shstrndx), SEEK_SET);
    fread(&shdr, elf_hdr.e_shentsize, 1, elf_file);
    rewind(elf_file); 
    return shdr;
}

/*
    Elf64_Shdr->sh_name is an index in the .shstrtab section,
    thanks to that we can extract the string name of the section
*/
std::string ElfParse::get_sh_name(size_t sh_name){
    if (elf_hdr.e_shstrndx == SHN_UNDEF)
        return NULL;

	fseek(elf_file, get_shstrtab().sh_offset + sh_name, SEEK_SET);
	std::string s("");
	char c;
	while ((c = fgetc(elf_file)) != '\0'){
		s.push_back(c);
	}
	rewind(elf_file);
	return s;
}

std::string ElfParse::get_sym_name(size_t st_name, size_t strtab_off){
    fseek(elf_file, st_name + strtab_off, SEEK_SET);
    std::string s("");
    char c;
	while ((c = fgetc(elf_file)) != '\0'){
		s.push_back(c);
	}
    rewind(elf_file);
    return s;
}

ElfParse::phdr_vector ElfParse::dump_phdr(){
    ElfParse::phdr_vector v;
    for (int i = 0; i < elf_hdr.e_phnum; i++){
        v.push_back(get_phdr(i));
    }
    return v;
}

ElfParse::shdr_vector ElfParse::dump_shdr(){
    ElfParse::shdr_vector v;
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        v.push_back(get_shdr(i));
    }
    return v;
}

ElfParse::phdr_vector ElfParse::dump_phdr_type(unsigned int type){
    ElfParse::phdr_vector v;
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Phdr phdr = get_phdr(i);
        if (phdr.p_type == type){
            v.push_back(phdr);
        }
    }
    return v;
}

ElfParse::shdr_vector ElfParse::dump_shdr_type(unsigned int type){
    ElfParse::shdr_vector v;
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type == type){
            v.push_back(shdr);
        }
    }
    return v;
}

/*
    a SYMTAB or DYNSYM section contains a symbol table (array
    of Elf64_Sym structs) that holds informations for every symbolic
    definitions and references. 

    We extract every SHT_SYMTAB and SHT_DYNSYM section
    that define a symbolic table, we seek to the section
    and extract all Elf64_Sym structs.
*/
ElfParse::sym_vector ElfParse::dump_sym(){
    ElfParse::sym_vector v;
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM){
            fseek(elf_file, shdr.sh_offset, SEEK_SET); 
            while (ftell(elf_file) < shdr.sh_offset + shdr.sh_size){
                Elf64_Sym sym;
                fread(&sym, shdr.sh_entsize, 1, elf_file);
                v.push_back(sym);
            }
        }
    }
    return v;
}

/*  From man elf: 
    String table sections hold null-terminated character sequences, commonly called  strings. The  object  file
    uses  these  strings  to  represent  symbol  and section names.  One references a string as an index into the
    string table section.  The first byte, which is index zero, is defined to hold a  null  byte  ('\0').   Simi‐
    larly, a string table's last byte is defined to hold a null byte, ensuring null termination for all strings. 
*/
std::stringstream ElfParse::dump_strtab(bool offset, bool wich_section){
    std::stringstream buff;
    if (offset){
        buff << std::hex << std::showbase;
    }
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type == SHT_STRTAB){
            if (wich_section){
                buff << get_sh_name(shdr.sh_name) << ":\n"; 
            }

            char c;
            fseek(elf_file, shdr.sh_offset + 1, SEEK_SET);
            while (ftell(elf_file) < shdr.sh_offset + shdr.sh_size){
                if (offset){
                    buff << ftell(elf_file) << " ";
                }
                while ((c = fgetc(elf_file)) != '\0'){
                    buff << c;
                }
                buff << std::endl;
            }
        }
    }
    rewind(elf_file);
    return buff;
}


ElfParse::~ElfParse(){
    fclose(elf_file);
}
