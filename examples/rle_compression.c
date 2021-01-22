#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//il numero massimo di caratteri ripetuti sostenuti 
//per unità compressa. Un numero superiore a 9 rende la 
//decompressione in questo codice obsoleta, in quanto il file compresso
//viene intepretato per char singoli e non per byte. 
#define COMPRESSION_DEPTH 9

void rle_compress(FILE *original, FILE *compress){

    rewind(original);
    rewind(compress);

    char c1, c2;
    while ((c1 = fgetc(original)) != EOF){

        char s[128];
        int rep = 1;
        c2 = fgetc(original);
        while (1){
            if (c2 != EOF){
                if (c1 == c2){
                    rep++;
                    if (rep < COMPRESSION_DEPTH){ 
                        c2 = fgetc(original);
                        continue;
                    }
                    else{           //compression depth reached
                        break;
                    }
                }
                else{               //found different char
                    fseek(original, -1, SEEK_CUR);
                    break;
                }
            }
            else{                   //reached EOF
                break;
            }
        }
        sprintf(s, "%d", rep);
        fwrite(s, strlen(s), 1, compress);
        fwrite(&c1, 1, 1, compress);
    }
}

void rle_decompress(FILE *original, FILE *decompress){
    
    rewind(original);
    rewind(decompress);

    int  rep;
    char c;
    while ((rep = fgetc(original)) != EOF){
        rep = atoi((char*)&rep);
        c = fgetc(original);
        for (int i = 0; i < rep; i++){
            printf("%d : %c\n", i, c);
            fputc(c, decompress);
        }
    }
}

int main(int argc, char **argv){

    if (argc < 4){
        puts("Usage: ./rle <compress/decompress> <input> <output>");
        return 1;
    }

    FILE *input = fopen(argv[2], "r");
    FILE *output = fopen(argv[3], "w"); 

    if (input == NULL){
        puts("ERROR: Can't read/open input file.");
        return 1;
    }
    if (output == NULL){
        puts("ERROR: Can't write/open output file.");
        return 1;
    }

    if (strcmp(argv[1], "compress") == 0){
        rle_compress(input, output);
    }
    else if (strcmp(argv[1], "decompress") == 0){
        rle_decompress(input, output);
    }
    
    fclose(input);
    fclose(output);
    return 0;
}
