//
//  mach-o.h
//  Mach-O
//
//  Created by Antonio Frighetto on 03/11/2016.
//  Copyright © 2016 Antonio Frighetto. All rights reserved.
//

#ifndef mach_o_h
#define mach_o_h

#include <assert.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/swap.h>

//Not actually all types supported.
static const char* filetypes[] = {
    "object", "executable", "shared library", "core file", "preloaded executable", "dynamic library", "dylinker", "bundle", "dylib_stub", "dsym", "kernel extension", (char*)0
};

typedef struct {
    const char* segment;
    const char** sections;
} segment_t;

static const segment_t segments[] = {
    { SEG_PAGEZERO, (const char*[]){ (char*)0 } },
    { SEG_TEXT, (const char*[]){ SECT_TEXT, "__cstring", "__const", "__unwind_info", (char*)0 } },
    { SEG_DATA, (const char*[]){ "__nl_symbol_ptr", "__la_symbol_ptr", "__const", SECT_DATA, SECT_BSS, (char*)0 } },
    { SEG_OBJC, (const char*[]){ SECT_OBJC_SYMBOLS, SECT_OBJC_MODULES, SECT_OBJC_STRINGS, (char*)0 } },
    { SEG_LINKEDIT, (const char*[]){ (char*)0} }
};

__attribute__((always_inline)) int check_magic(uint32_t magic);
__attribute__((always_inline)) void init_macho(const char* name, void* map, uint32_t magic_nm, struct stat* st);

#endif /* mach_o_h */
