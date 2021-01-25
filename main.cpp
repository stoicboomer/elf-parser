#include "elfparser/elfparse.h"
#include "elfparser/decoders.h"

int main(void){
    //you can change the path to any 64-bit binary you want
    ElfParse e("/bin/ls");

    //just flexing some of the formatting methods
    e.print_ehdr();
    e.print_phdr();
    e.print_shdr();
    //e.print_strtab(false); big output

    return 0;
}
