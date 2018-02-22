/*
 * Copyright (c) 2013 by Kyle Isom <kyle@tyrfingr.is>.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include "noecho.h"


/*
 * readpass switches the console to a non-echoing mode, reads a
 * line of standard input, and then switches the console back to
 * echoing mode.
 */
char *
readpass()
{
	struct termios	 term, restore;
	char		*password = NULL;
	size_t		 pw_size = 0;
	ssize_t		 pw_len;

	if (tcgetattr(STDIN_FILENO, &term) == -1)
		return NULL;

	restore = term;
	term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		return NULL;

	pw_len = getline(&password, &pw_size, stdin);
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &restore) == -1)
		return NULL;
	if (password != NULL)
		password[pw_len - 1] = (char)0;
	return password;
}
