/* misc.c  - FTP-Map misc
 
  Copyright (c) Hypsurus

  FTP-Map is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  FTP-Map is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "misc.h"

void die(int stat, char *format, ...) {
        va_list li;
        char m[MAX_STR];

        va_start(li, format);
        vsnprintf(m, sizeof(m), format, li);
        va_end(li);

        if ( stat == 1 ) {
            fprintf(stderr, "[ERROR] %s\n", m);
            exit(EXIT_FAILURE);
        }
}

void ftpmap_draw(int ch, int times) {
    int i = 0;

    printf("+");
    for ( i = 0; i <= times; i++ ) {
        putchar(ch);
    }
    printf("+\n");
}

void ftpmap_genchars(int ch, char *buffer, int length) {
    int i = 0;
   
    /* make */
    if ( length > 5000 )
        die(1,"Fuzzer buffer length is too long. ( > 5000)\n");
    for ( i = 0; i <= length; i++ ) {
        buffer[i] = ch;
    }
}

void * xmalloc(size_t size) {
    void *ret = malloc(size);

    if ( !ret && size )
        die(1, "Failed to allocate: %zu bytes.", size);

    return ret;
}


void sigalrm(int dummy) {
    (void) dummy;
    close(fd);
    fd = -1;
}


