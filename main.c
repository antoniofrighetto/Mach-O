//
//  main.c
//  Mach-O
//
//  Created by Antonio Frighetto on 03/11/2016.
//  Copyright © 2016 Antonio Frighetto. All rights reserved.
//

#include <stdio.h>

#include "parser/mach-o.h"

int main(int argc, const char * argv[]) {
    int fd;
    uint32_t magic_number;
    if (argc != 2) {
        fprintf(stderr, "[-] missing binary path.\n");
        exit(1);
    }
    if ((fd = open(argv[1], O_RDONLY)) < 0) {
        fprintf(stderr, "[-] could not open() %s...\n", argv[1]);
        exit(1);
    }
    
    lseek(fd, 0, SEEK_SET);
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "[-] unable to stat().\n");
        exit(1);
    }
    
    void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "[-] could not mmap().\n");
        exit(1);
    }
    read(fd, &magic_number, sizeof magic_number);
    if (check_magic(magic_number)) {
        fprintf(stderr, "[-] not a mach-o binary file.\n");
        exit(1);
    }
    
    init_macho(argv[1], map, magic_number, &st);
    
    return 0;
}

