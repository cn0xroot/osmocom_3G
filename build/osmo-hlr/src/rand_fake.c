/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

static uint8_t ctr = 0;

static void print_msg(void)
{
	static int printed = 0;
	if (!printed) {
		fprintf(stderr, "Using fake random generator for deterministic "
			"test results. NEVER USE THIS IN PRODUCTION\n");
		printed = 1;
	}
}

int rand_init(void)
{
	print_msg();
	return 0;
}

int rand_get(uint8_t *rand, unsigned int len)
{
	print_msg();
	memset(rand, ctr, len);
	ctr++;
	return len;
}
