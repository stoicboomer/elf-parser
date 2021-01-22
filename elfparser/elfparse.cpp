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
    elf_ifstream = std::ifstream(elf_path, std::ios_base::binary);
}

FILE *ElfParse::get_fd(){
	return elf_file;
}

//i hate formatting stuff
void ElfParse::print_ehdr(){
    push_fmt();
    std::cout << std::left << std::hex << std::showbase 
              << "ELF Header:\n"					
              << std::setw(5)  << "  Magic:     ";              print_ident(elf_hdr.e_ident);
    std::cout << std::setw(35) << "  Class:"                    << decode_ei_class(elf_hdr.e_ident) 	<< std::endl
              << std::setw(35) << "  OS/ABI:"                   << decode_ei_osabi(elf_hdr.e_ident) 	<< std::endl
              << std::setw(35) << "  Type:"                     << decode_e_type(elf_hdr.e_type)        << std::endl
			  << std::setw(35) << "  Machine:"			        << decode_e_machine(elf_hdr.e_machine) 	<< std::endl 
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

//fuck it i can't write leading zeros in hex with std::cout, embrace holyC
void ElfParse::print_phdr(){
    puts("    offset      size   vaddr       vsize  perm name        \n"
         "―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――");
    for (int i = 0; i < elf_hdr.e_phnum; i++){
        Elf64_Phdr phdr = get_phdr(i);

        printf("%-3d 0x%08x  0x%-4x 0x%08x  0x%-4x ", i, phdr.p_offset, 
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
        printf("%-3d 0x%08x  0x%-4x 0x%08x  %-10s %s\n", i, shdr.sh_offset, 
                shdr.sh_size, shdr.sh_addr, decode_sh_type(shdr.sh_type),
				read_sh_name(shdr.sh_name).c_str()); 
    }
}

void ElfParse::print_strtab(bool offset){
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type != SHT_STRTAB) continue;
        
        char c;
        fseek(elf_file, shdr.sh_offset + 1, SEEK_SET);
        while (ftell(elf_file) < shdr.sh_offset + shdr.sh_size){
            if (offset) 
                printf("%x ", ftell(elf_file));
            while ((c = fgetc(elf_file)) != '\0'){
                putchar(c);
            }
            puts("");
        }
    }
    rewind(elf_file);
}

std::stringstream ElfParse::dump_strtab(){
    std::stringstream buff;
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type != SHT_STRTAB) continue;
        
        char c;
        //note: first byte in the STRTAB section is always a '\0' 
        fseek(elf_file, shdr.sh_offset + 1, SEEK_SET);
        while (ftell(elf_file) < shdr.sh_offset + shdr.sh_size){
            while ((c = fgetc(elf_file)) != '\0'){
                buff << c;
            }
            buff << std::endl;
        }
    }
    rewind(elf_file);
    return buff;
}

Elf64_Ehdr ElfParse::get_ehdr(){
    return elf_hdr;
}

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

ElfParse::shdr_vector ElfParse::dump_symshdr(){
    ElfParse::shdr_vector v; 
    for (int i = 0; i < elf_hdr.e_shnum; i++){
        Elf64_Shdr shdr = get_shdr(i);
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM)
            v.push_back(shdr);
    }
    return v;
}

ElfParse::sym_vector ElfParse::dump_sym(){
    ElfParse::sym_vector v;
    ElfParse::shdr_vector sym_shdr = dump_symshdr();
    for (Elf64_Shdr shdr : sym_shdr){
        fseek(elf_file, shdr.sh_offset, SEEK_SET); 
        while (ftell(elf_file) < shdr.sh_offset + shdr.sh_size){
            Elf64_Sym sym;
            fread(&sym, shdr.sh_entsize, 1, elf_file);
            v.push_back(sym);
        }
    }
    return v;
}

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

std::string ElfParse::read_sh_name(size_t sh_name){
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

ElfParse::~ElfParse(){
    fclose(elf_file);
}
