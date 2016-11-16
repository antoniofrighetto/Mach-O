### Mach-O
----

Found often myself to need to parse Mach-O executables to dump segments and symbols. So I decided to write it on my own. Note that there should be still a lot to do, also some parts would need to be reviewed/fixed and code is somewhere kinda dirty. It works though.

#### Demo

```
$ ./mach-o /usr/bin/uname
About
┖──── /usr/bin/uname owned by root (rwx), created at Wed Sep 14 02:56:50 2016
Header
┖──── Mach-O 64 bit executable (0xfeedfacf, LE, stripped) with architecture Intel x86-64 (ALL)
Segments
┖──── Dumping main segments of 16 totals:
┖─ LC_64 0 0x0000000000000000 - 0x0000000100000000 __PAGEZERO       ---
┖─ LC_64 1 0x0000000100000000 - 0x0000000000001000 __TEXT           r-x
0x0000000100000ad0 - 0x000000000000031e __text
0x0000000100000f28 - 0x0000000000000087 __cstring
┖─ LC_64 2 0x0000000100001000 - 0x0000000000001000 __DATA           rw-
0x0000000100001018 - 0x0000000000000010 __nl_symbol_ptr
0x0000000100001028 - 0x0000000000000058 __la_symbol_ptr
┖─ LC_64 3 0x0000000100002000 - 0x0000000000003000 __LINKEDIT       r--
┖─ Entry point address: 0x0000000000000ad0
┖─ Dynamically loaded libraries:
/usr/lib/libSystem.B.dylib
Indirect symtable
┖──── Symbols imported at lazy binding:
__DATA.__la_symbol_ptr _compat_mode
__DATA.__la_symbol_ptr _err
__DATA.__la_symbol_ptr _exit
__DATA.__la_symbol_ptr _fputs
__DATA.__la_symbol_ptr _fwrite
__DATA.__la_symbol_ptr _getenv
__DATA.__la_symbol_ptr _getopt
__DATA.__la_symbol_ptr _putchar
__DATA.__la_symbol_ptr _setlocale
__DATA.__la_symbol_ptr _strncpy
__DATA.__la_symbol_ptr _uname
```
