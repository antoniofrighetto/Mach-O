//
//  mach-o.c
//  Mach-O
//
//  Created by Antonio Frighetto on 03/11/2016.
//  Copyright © 2016 Antonio Frighetto. All rights reserved.
//

#include "mach-o.h"

static int xsnprintf(char* str, size_t sz, const char* fmt, ...);
static struct mach_header_64* dump_mach_header(void* map, int swap, uint32_t magic_nm);
static struct fat_header* dump_fat_header(void* map, int swap);
static void dump_segments(void* map, int swap);
static struct load_command* get_load_command(void* mach_header, int swap, uint32_t cmd);
static char* get_main_segments(struct load_command* lc, struct mach_header_64* mach_header, const char* segname, const char** sections, int swap);
static void dump_dsymtable(void* header, int swap);
static char* print_header(struct mach_header_64* mach_header, struct load_command* lc);
static void print_segments(void* map, int swap);

__attribute__((always_inline)) int check_magic(uint32_t magic) {
    return !(magic == MH_MAGIC || magic == MH_CIGAM ||
             magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
             magic == FAT_MAGIC || magic == FAT_CIGAM);
}

__attribute__((always_inline)) void init_macho(const char* name, void* map, uint32_t magic_nm, struct stat* st) {
    struct passwd* pwd;
    printf("About\n");
    printf("%16s %s owned by %s ", "┖────", name, (pwd = getpwuid(st->st_uid)) ? pwd->pw_name : "Unknown");
    printf("(%c%c%c), ", st->st_mode & S_IRUSR ? 'r' : '-', st->st_mode & S_IWUSR ? 'w' : '-', st->st_mode & S_IXUSR ? 'x' : '-');
    printf("created at %s", asctime(localtime(&st->st_birthtimespec.tv_sec)));
    int swap = magic_nm == MH_CIGAM || magic_nm == MH_CIGAM_64;
    void* header;
    void* load_segments;
    mprotect(map, st->st_size, PROT_WRITE);
    
    if (magic_nm == MH_MAGIC_64 || magic_nm == MH_CIGAM_64) {
        load_segments = (void*)((uint64_t)map + sizeof(struct mach_header_64));
        header = (struct mach_header_64*)dump_mach_header(map, swap, magic_nm);
        memcpy(map, header, sizeof(struct mach_header_64));
        memcpy(map + sizeof(struct mach_header_64), load_segments, st->st_size - sizeof(struct mach_header_64));
    } else if (magic_nm == MH_MAGIC || magic_nm == MH_CIGAM) {
        load_segments = (void*)((uint64_t)map + sizeof(struct mach_header));
        header = (struct mach_header*)dump_mach_header(map, swap, magic_nm);
        memcpy(map, header, sizeof(struct mach_header));
        memcpy(map + sizeof(struct mach_header), load_segments, st->st_size - sizeof(struct mach_header));
    } else {
        header = (struct fat_header*)dump_fat_header(map, swap);
    }
    
    dump_segments(map, swap);
    dump_dsymtable(map, swap);
    free(header);
}

static int xsnprintf(char* str, size_t sz, const char* fmt, ...) {
    size_t len = strlen(str);
    va_list arg_list;
    va_start(arg_list, fmt);
    int rv = vsnprintf(str + len, sz - len, fmt, arg_list);
    assert(rv != -1);
    va_end(arg_list);
    return rv;
}

static struct mach_header_64* dump_mach_header(void* map, int swap, uint32_t magic_nm) {
    char* header = NULL;
    struct mach_header_64* mach_header = malloc(sizeof(struct mach_header_64));
    assert(mach_header);
    memcpy((void*)mach_header, (const void*)map, sizeof(struct mach_header_64));
    if (magic_nm == MH_MAGIC || magic_nm == MH_CIGAM)
        mach_header->reserved = 0;
    if (swap)
        swap_mach_header_64(mach_header, -1);
    struct load_command* lc = get_load_command(map, swap, LC_DYSYMTAB);
    header = print_header(mach_header, lc);
    printf("Header\n");
    printf("%16s %s\n", "┖────", header);
    free(header);
    return mach_header;
}

static struct fat_header* dump_fat_header(void* map, int swap) {
    char* header = NULL;
    struct fat_header* fat_header = malloc(sizeof(struct fat_header));
    memcpy((void*)fat_header, map, sizeof(struct fat_header));
    int fat_swap = fat_header->magic == FAT_CIGAM;
    if (fat_swap)
        swap_fat_header(fat_header, -1);
    struct fat_arch* arch = calloc(fat_header->nfat_arch, sizeof(struct fat_arch));
    assert(arch);
    memcpy((void*)arch, (const void*)((uint64_t)map + sizeof(struct fat_header)), sizeof(struct fat_arch) * fat_header->nfat_arch);
    if (fat_swap)
        swap_fat_arch(arch, fat_header->nfat_arch, -1);
    printf("Header\n");
    printf("%16s Universal FAT 32 bit binary (%#08x, %s), consists of:\n", "┖────", fat_header->magic, fat_swap ? "BE" : "LE");
    uint32_t nfat_arch = fat_header->nfat_arch;
    while (nfat_arch--) {
        struct mach_header_64* mach_header = (struct mach_header_64*)((uint64_t)map + arch[nfat_arch].offset);
        struct load_command* lc = (struct load_command*)get_load_command((void*)mach_header, swap, LC_DYSYMTAB);
        if (mach_header->magic == MH_CIGAM || mach_header->magic == MH_CIGAM_64) {
            if (mach_header->magic == MH_CIGAM)
                swap_mach_header((struct mach_header*)mach_header, -1);
            else
                swap_mach_header_64(mach_header, -1);
        }
        header = print_header(mach_header, lc);
        printf("%13s %s\n", "┖─", header);
        free(header);
    }
    free(arch);
    return fat_header;
}

static void dump_segments(void* mh, int swap) {
    if (((struct mach_header_64*)mh)->magic == FAT_MAGIC || ((struct mach_header_64*)mh)->magic == FAT_CIGAM ) {
        struct fat_header fat_header = *(struct fat_header*)mh;
        uint32_t nfat_arch = fat_header.magic == FAT_CIGAM ? OSSwapInt32(fat_header.nfat_arch) : fat_header.nfat_arch;
        struct fat_arch* arch = (struct fat_arch*)((uint64_t)mh + sizeof(struct fat_header));
        while (nfat_arch--) {
            uint32_t offset = fat_header.magic == FAT_CIGAM ? OSSwapInt32(arch[nfat_arch].offset) : arch[nfat_arch].offset;
            struct mach_header_64* header = (struct mach_header_64*)((uint64_t)mh + offset);
            print_segments(header, swap);
        }
    } else {
        struct mach_header_64* header = (struct mach_header_64*)mh;
        print_segments(header, swap);
    }
}

static struct load_command* get_load_command(void* mach_header, int swap, uint32_t cmd) {
    struct mach_header_64* header = (struct mach_header_64*)mach_header;
    struct load_command* lc = NULL;
    if (header->magic == MH_MAGIC) {
        lc = (struct load_command*)((uint64_t)((struct mach_header*)header) + sizeof(struct mach_header));
    } else {
        lc = (struct load_command*)((uint64_t)header + sizeof(struct mach_header_64));
    }
    if (cmd) {
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (lc->cmd == cmd)
                break;
            lc = (struct load_command*)((uint64_t)lc + lc->cmdsize);
        }
    }
    if (swap)
        swap_load_command(lc, -1);
    return lc;
}

static char* get_main_segments(struct load_command* load_cmd, struct mach_header_64* mach_header, const char* segname, const char** section, int swap) {
    struct load_command* lc = load_cmd;
    size_t sz = 400;
    char* buf = malloc(sz);
    assert(buf);
    for (uint32_t i = 0; i < mach_header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT) {
            struct segment_command* seg = (struct segment_command*)lc;
            if (swap)
                swap_segment_command(seg, -1);
            if (!(strcmp(seg->segname, segname))) {
                xsnprintf(buf, sz, "%13s LC %d 0x%08x - 0x%08x %-16s %c%c%c", "┖─", i, seg->vmaddr, seg->vmsize, seg->segname, seg->initprot & VM_PROT_READ ? 'r' : '-', seg->initprot & VM_PROT_WRITE ? 'w' : '-', seg->initprot & VM_PROT_EXECUTE ? 'x' : '-');
                struct section* sec = (struct section*)((uint64_t)seg + sizeof(struct segment_command));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    while (*section && !(strcmp(sec->sectname, *section))) {
                        if (swap)
                            swap_section(sec, 0, -1);
                        xsnprintf(buf, sz, "\n%14s 0x%08x - 0x%08x %s", "", sec->addr, sec->size, sec->sectname);
                        section++;
                    }
                    sec = (struct section*)((uint64_t)sec + sizeof(struct section));
                }
            }
        } else if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (swap)
                swap_segment_command_64(seg, -1);
            if (!(strcmp(seg->segname, segname))) {
                xsnprintf(buf, sz, "%13s LC_64 %d 0x%016llx - 0x%016llx %-16s %c%c%c", "┖─", i, seg->vmaddr, seg->vmsize, seg->segname, seg->initprot & VM_PROT_READ ? 'r' : '-', seg->initprot & VM_PROT_WRITE ? 'w' : '-', seg->initprot & VM_PROT_EXECUTE ? 'x' : '-');
                struct section_64* sec = (struct section_64*)((uint64_t)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    while (*section && !(strcmp(sec->sectname, *section))) {
                        if (swap)
                            swap_section_64(sec, 0, -1);
                        xsnprintf(buf, sz, "\n%17s 0x%016llx - 0x%016llx %s", "", sec->addr, sec->size, sec->sectname);
                        section++;
                    }
                    sec = (struct section_64*)((uint64_t)sec + sizeof(struct section_64));
                }
            }
        }
        lc = (struct load_command*)((uint64_t)lc + lc->cmdsize);
    }
    return buf;
}

static char* print_header(struct mach_header_64* mach_header, struct load_command* lc) {
    size_t sz = 800;
    char* buf = malloc(sz);
    assert(buf);
    uint32_t i = 0, magic_nm = mach_header->magic;
    uint32_t strip = 0;
    struct dysymtab_command* dysm = (struct dysymtab_command*)lc;
    if (dysm) {
        strip = dysm->iextdefsym;
    }
    for (const char** p = filetypes; *p; p++) {
        if (mach_header->filetype == ++i) {
            xsnprintf(buf, sz, "Mach-O %s bit %s (%#08x, %s, %s) ", magic_nm == MH_MAGIC ? "32" : "64", *p, magic_nm, magic_nm == MH_CIGAM || magic_nm == MH_CIGAM_64 ? "BE" : "LE", strip ? "stripped" : "not stripped" );
            break;
        }
    }
    for(const NXArchInfo* arch = NXGetAllArchInfos(); arch && arch->description; arch++) {
        if (mach_header->cputype == arch->cputype) {
            xsnprintf(buf, sz, "with architecture %s ", arch->description);
            switch (mach_header->cpusubtype & ~CPU_SUBTYPE_MASK) {
                case CPU_SUBTYPE_POWERPC_ALL:
                case CPU_SUBTYPE_X86_64_ALL:
                    strcat(buf, "(ALL)");
            }
            break;
        }
    }
    return buf;
}

static void print_segments(void* mh, int swap) {
    int flag = 0;
    struct mach_header_64* header = (struct mach_header_64*)mh;
    struct load_command* lc = get_load_command((void*)header, swap, 0);
    printf("Segments\n");
    printf("%16s %s %d %s\n", "┖────", "Dumping main segments of", header->ncmds, "totals:");
    for (int i = 0; i < sizeof(segments)/sizeof(segment_t); i++) {
        if (lc->cmdsize != 0) {
            char* segment = get_main_segments(lc, header, segments[i].segment, segments[i].sections, swap);
            if (*segment)
                printf("%s\n", segment);
            free(segment);
        }
    }
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_LOAD_DYLIB) {
            struct dylib_command* dy = (struct dylib_command*)lc;
            if (swap)
                swap_dylib_command(dy, -1);
            const char* name = (char*)(dy->dylib.name.offset + (uint64_t)lc);
            if (!flag)
                printf("%13s %s\n", "┖─", "Dynamically loaded libraries:");
            printf("%10s %s\n", "", name);
            flag = 1;
        } else if (lc->cmd == LC_MAIN) {
            struct entry_point_command* ep = (struct entry_point_command*)lc;
            if (swap)
                swap_entry_point_command(ep, -1);
            printf("%13s %s 0x%016llx\n", "┖─", "Entry point address:", ep->entryoff + ep->stacksize); //__TEXT.__text vm address
        } else if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64* enc = (struct encryption_info_command_64*)lc;
            if (enc->cryptid)
                printf("%13s %s\n", "┖─", "Binary is encrypted.");
        } else if (header->filetype == MH_KEXT_BUNDLE && lc->cmd == LC_CODE_SIGNATURE) { //should be extended to dylib et al
            printf("%13s %s\n", "┖─", "Kext signed.");
        }
        lc = (struct load_command*)((uint64_t)lc + lc->cmdsize);
    }
}

static void dump_dsymtable(void* header, int swap) {
    struct mach_header_64* mach_header = (struct mach_header_64*)header;
    if (mach_header->magic == FAT_MAGIC || mach_header->magic == FAT_CIGAM ) //to be added
        return;
    
    uint32_t sec_reserved1;
    uint64_t sec_length;
    char* sec_sectname, *sec_segname;
    struct load_command* lc = (struct load_command*)get_load_command((void*)mach_header, swap, 0);
    for (uint32_t i = 0; i < mach_header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            struct section_64* sec = (struct section_64*)((uint64_t)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if ((!strcmp(seg->segname, SEG_DATA)) && (!strcmp(((struct section_64*)sec)->sectname, "__la_symbol_ptr"))) {
                    sec_segname = sec->segname;
                    sec_sectname = sec->sectname;
                    sec_reserved1 = sec->reserved1;
                    sec_length = sec->size/sizeof(uint64_t);
                    goto found;
                }
                sec = (struct section_64*)((uint64_t)sec + sizeof(struct section_64));
            }
        } else if (lc->cmd == LC_SEGMENT) {
            struct segment_command* seg = (struct segment_command*)lc;
            struct section* sec = (struct section*)((uint64_t)seg + sizeof(struct segment_command));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if ((!strcmp(seg->segname, SEG_DATA)) && (!strcmp(((struct section*)sec)->sectname, "__la_symbol_ptr"))) {
                    sec_segname = sec->segname;
                    sec_sectname = sec->sectname;
                    sec_reserved1 = sec->reserved1;
                    sec_length = sec->size/sizeof(uint32_t);
                    goto found;
                }
                sec = (struct section*)((uint64_t)sec + sizeof(struct section));
            }
        }
        lc = (struct load_command*)((uint64_t)lc + lc->cmdsize);
    }
    return;
    
found:
    lc = (struct load_command*)get_load_command(header, swap, LC_SYMTAB);
    struct symtab_command* sc = (struct symtab_command*)lc;
    struct nlist *symbol_table_32 = (struct nlist*)(header + sc->symoff);
    struct nlist_64 *symbol_table_64 = (struct nlist_64*)(header + sc->symoff); //kinda sucks this
    const char *str_table = (char*)header + sc->stroff;
    
    lc = (struct load_command*)get_load_command(header, swap, LC_DYSYMTAB);
    struct dysymtab_command* dyc = (struct dysymtab_command*)lc;
    
    uint32_t dysym_table_offset = sec_reserved1; //with symbol_stub or __la_symbol_ptr, reserved 1 field hold the index into the dysym table
    uint32_t* indirect_table = (uint32_t*)(dyc->indirectsymoff + header);
    
    if (!sc || !dyc || !indirect_table)
        return;
    
    //non lazy & stubs symbols should be added too...
    printf("Indirect symtable\n");
    printf("%16s %s\n", "┖────", "Symbols imported at lazy binding:");
    for (uint32_t i = 0; i < sec_length; i++) {
        uint32_t symbol_index = indirect_table[dysym_table_offset + i];
        if (symbol_index < sc->nsyms) {
            uint32_t table_index = mach_header->magic == MH_MAGIC ? symbol_table_32[symbol_index].n_un.n_strx : symbol_table_64[symbol_index].n_un.n_strx;
            if (table_index < sc->strsize) {
                const char* symbol_name = &str_table[table_index];
                printf("%5s %s.%s %s\n", "", sec_segname, sec_sectname, symbol_name);
            }
        }
    }
}
