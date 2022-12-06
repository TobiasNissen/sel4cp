/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sel4cp.h>

#define __thread
#include <sel4/sel4.h>

void
sel4cp_dbg_putc(int c)
{
#if defined(CONFIG_DEBUG_BUILD)
    seL4_DebugPutChar(c);
#endif
}



void
sel4cp_dbg_puts(const char *s)
{
    while (*s) {
        sel4cp_dbg_putc(*s);
        s++;
    }
}

char 
sel4cp_internal_hexchar(unsigned int v) 
{
    return v < 10 ? '0' + v : ('a' - 10) + v;
}

/*
 * Output the given integer as a 64 bit hexadecimal number.
 */
void 
sel4cp_dbg_puthex64(uint64_t val) 
{
    char buffer[16 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[16 + 3 - 1] = 0;
    for (unsigned i = 16 + 1; i > 1; i--) {
        buffer[i] = sel4cp_internal_hexchar(val & 0xf);
        val >>= 4;
    }
    sel4cp_dbg_puts(buffer);
}


void
__assert_fail(const char  *str, const char *file, int line, const char *function)
{
    sel4cp_dbg_puts("assert failed: ");
    sel4cp_dbg_puts(str);
    sel4cp_dbg_puts(" ");
    sel4cp_dbg_puts(file);
    sel4cp_dbg_puts(" ");
    sel4cp_dbg_puts(function);
    sel4cp_dbg_puts("\n");
}
