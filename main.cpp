#include "elfparser/elfparse.h"
#include "elfparser/decoders.h"

int main(void){
    ElfParse e("./examples/parse_me64");
    //print formatted elf header
    e.print_ehdr();
    //print formatted program headers
    e.print_phdr();
    //print formatted sections headers
    e.print_shdr(); 

    return 0;
}
