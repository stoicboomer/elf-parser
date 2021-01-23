#include "decoders.h"

/* 
    print magic bytes in hex
*/
void print_ident(unsigned char *e_ident){
    push_fmt();
    for (int i = 0; i < EI_NIDENT; i++){
        std::cout << std::noshowbase << std::hex 
                  << std::setw(2)    << std::setfill('0')
                  << (int)e_ident[i] << " ";
    }
    std::cout << std::endl;
    pop_fmt(); 
}

const char *decode_ei_data(unsigned char *e_ident){
    switch (e_ident[EI_DATA]){
        case ELFDATA2LSB: return "Two's complement, little-endian";
        case ELFDATA2MSB: return "Two's complement, big-endian";
        default:
            return "Unknown data format";
    }
}

const char *decode_ei_class(unsigned char *e_ident){
    switch (e_ident[EI_CLASS]){
        case ELFCLASS32: return "32-bit";
        case ELFCLASS64: return "64-bit";
        default:
            return "Unknown class";
    }
}

const char *decode_ei_osabi(unsigned char *e_ident){
    switch (e_ident[EI_OSABI]){
		case ELFOSABI_NONE:     return "UNIX - System V";
		case ELFOSABI_HPUX:     return "UNIX - HP-UX";
		case ELFOSABI_NETBSD:   return "UNIX - NetBSD";
		case ELFOSABI_GNU:      return "UNIX - GNU";
		case ELFOSABI_SOLARIS:  return "UNIX - Solaris";
		case ELFOSABI_AIX:      return "UNIX - AIX";
		case ELFOSABI_IRIX:     return "UNIX - IRIX";
        case ELFOSABI_FREEBSD:  return "UNIX - FreeBSD";
        case ELFOSABI_TRU64:    return "UNIX - TRU64";
		case ELFOSABI_MODESTO:  return "Novell - Modesto";
		case ELFOSABI_OPENBSD:  return "UNIX - OpenBSD";
		default:
		    return "Unknown OS ABI";
	}
}

const char *decode_e_type(unsigned int e_type){
    switch (e_type){
        case ET_REL:    return "Relocatable file";
        case ET_EXEC:   return "Executable file";
        case ET_DYN:    return "Shared object";
        case ET_CORE:   return "Core object";
        default:
            return "Unknown type";
    }
}

const char *decode_e_machine(unsigned int e_machine){
    switch (e_machine){
	case EM_M32:     		return "AT&T WE 32100";
	case EM_SPARC:     		return "Sun Microsystems SPARC";          
	case EM_386:     		return "Intel 80386";
	case EM_68K:     		return "Motorola 68000";
	case EM_88K:     		return "Motorola 88000";
	case EM_860:     		return "Intel 80860";
	case EM_MIPS:     		return "MIPS RS3000 (big-endian only)";           
	case EM_PARISC:     	return "HP/PA";
	case EM_SPARC32PLUS:    return "SPARC with enhanced instruction set";    
	case EM_PPC:     		return "PowerPC";
	case EM_PPC64:     		return "PowerPC 64-bit";
	case EM_S390:     		return "IBM S/390";
	case EM_ARM:     		return "Advanced RISC Machines";            
	case EM_SH:     		return "Renesas SuperH";
	case EM_SPARCV9:     	return "SPARC v9 64-bit";
	case EM_IA_64:     		return "Intel Itanium";
	case EM_X86_64:     	return "AMD x86-64";
	case EM_VAX:     		return "DEC Vax";
	default:     		
		return "An unknown machine";
    }
}

//first time i find an use of bitwise operators, wow..
void print_p_flags(unsigned int p_flags){
    if ((p_flags & PF_R) == PF_R) std::cout << "r"; //READ
    else                          std::cout << "-";
    if ((p_flags & PF_W) == PF_W) std::cout << "w"; //WRITE
    else                          std::cout << "-";
    if ((p_flags & PF_X) == PF_X) std::cout << "x"; //EXECUTE
    else                          std::cout << "-";
}

const char *decode_p_type(unsigned int p_type){
    switch (p_type){
        case PT_NULL:           return "NULL";
        case PT_LOAD:           return "LOAD";
        case PT_DYNAMIC:        return "DYNAMIC";
        case PT_INTERP:         return "INTERP";
        case PT_NOTE:           return "NOTE";
        case PT_PHDR:           return "PHDR";
        case PT_GNU_STACK:      return "GNU_STACK";
        case PT_GNU_EH_FRAME:   return "GNU_EH_FRAME";
        case PT_GNU_RELRO:      return "GNU_RELRO";
        default:
            return "Uknown PHDR";
    }
}

const char *decode_sh_type(unsigned int sh_type){
    switch (sh_type){
		case SHT_PROGBITS:  return "PROGBITS";
		case SHT_SYMTAB:	return "SYMTAB";
		case SHT_STRTAB:    return "STRTAB";
		case SHT_RELA:     	return "RELA";
		case SHT_HASH:     	return "HASH";
		case SHT_DYNAMIC:   return "DYNAMIC";
		case SHT_NOTE:     	return "NOTE";
		case SHT_NOBITS:   	return "NOBITS";
		case SHT_REL:     	return "REL";
		case SHT_SHLIB:     return "SHLIB";
		case SHT_DYNSYM:    return "DYNSYM";
		case SHT_LOPROC:    return "LOPROC";
		case SHT_HIPROC:    return "HIPROC";
		case SHT_LOUSER:    return "LOUSER";
		case SHT_HIUSER:    return "HIUSER";
		default:
			return "NULL";
    }
}
