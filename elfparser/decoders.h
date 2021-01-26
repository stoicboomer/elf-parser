#ifndef _ELF_DEC_
#define _ELF_DEC_

#include <elf.h>
#include <iomanip>
#include <iostream>
#include <fstream>

#define push_fmt() \
    std::ofstream old_fmt;  \
    old_fmt.copyfmt(std::cout);

#define pop_fmt() \
    std::cout.copyfmt(old_fmt);

/*
    This headers is simply a collection of functions that
    decode the defined machros in /usr/include/elf.h into a 
    valid, human readble string. Useful for formatting stuff.
*/

/* ELF HEADER DECODING */
void print_ident(unsigned char *e_ident);               
const char *decode_ei_data(unsigned char *e_ident);
const char *decode_ei_class(unsigned char *e_ident);
const char *decode_ei_osabi(unsigned char *e_ident);
const char *decode_e_type(unsigned int e_type);
const char *decode_e_machine(unsigned int e_machine);

/* PROGRAM HEADER DECODING */
//print segment permission flags (es. r-x, r--, rwx)
void print_p_flags(unsigned int p_flags);       
const char *decode_p_type(unsigned int p_type);

/* SECTION HEADER DECODING */
const char *decode_sh_type(unsigned int sh_type);

/* SYMBOL DECODING */
const char *decode_st_type(unsigned int st_info);
const char *decode_st_bind(unsigned int st_info);

#endif
