/* gen_ts_55_205_test_sets/main_template.c: Template to generate test code
 * from 3GPP TS 55.205 test sets */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/crypt/auth.h>

#include "logging.h"
#include "auc.h"

#define comment_start() fprintf(stderr, "\n===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		fprintf(stderr, #val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

char *vec_str(const struct osmo_auth_vector *vec)
{
	static char buf[1024];
	char *pos = buf;
	char *end = buf + sizeof(buf);

#define append(what) \
	if (pos >= end) \
		return buf; \
	pos += snprintf(pos, sizeof(buf) - (pos - buf), \
                        "  " #what ": %s\n", \
			osmo_hexdump_nospc((void*)&vec->what, sizeof(vec->what)))

	append(rand);
	append(ck);
	append(ik);
	append(res);
	append(kc);
	append(sres);
#undef append

	return buf;
}

#define VEC_IS(vec, expect) do { \
		char *_is = vec_str(vec); \
	        if (strcmp(_is, expect)) { \
			fprintf(stderr, "MISMATCH! expected ==\n%s\n", \
				expect); \
			char *a = _is; \
			char *b = expect; \
			for (; *a && *b; a++, b++) { \
				if (*a != *b) { \
					while (a > _is && *(a-1) != '\n') a--; \
					fprintf(stderr, "mismatch at %d:\n" \
						"%s", (int)(a - _is), a); \
					break; \
				} \
			} \
			OSMO_ASSERT(false); \
		} else \
			fprintf(stderr, "vector matches expectations\n"); \
	} while (0)

uint8_t fake_rand[16] = { 0 };

int rand_get(uint8_t *rand, unsigned int len)
{
	OSMO_ASSERT(len <= sizeof(fake_rand));
	memcpy(rand, fake_rand, len);
	return len;
}

FUNCTIONS

int main()
{
	printf("3GPP TS 55.205 Test Sets\n");
	osmo_init_logging(&hlr_log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

FUNCTION_CALLS

	printf("Done\n");
	return 0;
}
