#include "elfparser/elfparse.h"
#include "elfparser/decoders.h"

int main(void){
    //you can change the path to any 64-bit binary you want
    ElfParse e("/bin/ls");

    e.print_ehdr(); //print formatted Elf header
    e.print_phdr(); //print formatted Program headers
    e.print_shdr(); //print formatted Section headers

    //big output:
    //e.print_sym()  print formatted symbols
    //e.print_strtab(false); print all strings in the STRTAB sections

    return 0;
}
