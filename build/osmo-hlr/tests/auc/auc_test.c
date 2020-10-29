/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <getopt.h>

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
	append(autn);
	append(ck);
	append(ik);
	append(res);
	append(res_len);
	append(kc);
	append(sres);
	append(auth_types);
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
					fprintf(stderr, "mismatch at %d:\n", \
						(int)(a - _is)); \
					while (a > _is && *(a-1) != '\n') { \
						fprintf(stderr, " "); \
						a--; \
					} \
					fprintf(stderr, "v\n%s", a); \
					break; \
				} \
			} \
			OSMO_ASSERT(false); \
		} else \
			fprintf(stderr, "vector matches expectations\n"); \
	} while (0)

uint8_t fake_rand[16] = { 0 };
bool fake_rand_fixed = true;

void next_rand(const char *hexstr, bool fixed)
{
	osmo_hexparse(hexstr, fake_rand, sizeof(fake_rand));
	fake_rand_fixed = fixed;
}

int rand_get(uint8_t *rand, unsigned int len)
{
	int i;
	OSMO_ASSERT(len <= sizeof(fake_rand));
	memcpy(rand, fake_rand, len);
	if (!fake_rand_fixed) {
		for (i = 0; i < len; i++)
			fake_rand[i] += 0x11;
	}
	return len;
}

static void test_gen_vectors_2g_only(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_COMP128v1,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud2g.u.gsm.ki, sizeof(aud2g.u.gsm.ki));

	aud3g = (struct osmo_sub_auth_data){ 0 };

	next_rand("39fa2f4e3d523d8619a73b4f65c3e14d", true);

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 00000000000000000000000000000000\n"
	       "  ck: 00000000000000000000000000000000\n"
	       "  ik: 00000000000000000000000000000000\n"
	       "  res: 00000000000000000000000000000000\n"
	       "  res_len: 00\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 01000000\n"
	      );

	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);

	/* even though vec is not zero-initialized, it should produce the same
	 * result (regardless of the umts sequence nr) */
	aud3g.u.umts.sqn = 123;
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 00000000000000000000000000000000\n"
	       "  ck: 00000000000000000000000000000000\n"
	       "  ik: 00000000000000000000000000000000\n"
	       "  res: 00000000000000000000000000000000\n"
	       "  res_len: 00\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 01000000\n"
	      );

	comment_end();
}

static void test_gen_vectors_2g_plus_3g(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_COMP128v1,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud2g.u.gsm.ki, sizeof(aud2g.u.gsm.ki));

	aud3g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_MILENAGE,
		.u.umts.sqn = 31,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud3g.u.umts.k, sizeof(aud3g.u.umts.k));
	osmo_hexparse("FB2A3D1B360F599ABAB99DB8669F8308",
		      aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc));
	next_rand("39fa2f4e3d523d8619a73b4f65c3e14d", true);

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 32, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55d30000541dde77ea5b1d8c\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 03000000\n"
	      );

	/* even though vec is not zero-initialized, it should produce the same
	 * result with the same sequence nr */
	aud3g.u.umts.sqn = 31;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 32, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55d30000541dde77ea5b1d8c\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 03000000\n"
	      );

	comment_end();
}

void _test_gen_vectors_3g_only__expect_vecs(struct osmo_auth_vector vecs[3])
{
	fprintf(stderr, "[0]: ");
	VEC_IS(&vecs[0],
	       "  rand: 897210a0f7de278f0b8213098e098a3f\n"
	       "  autn: c6b9790dad4b00000cf322869ea6a481\n"
	       "  ck: e9922bd036718ed9e40bd1d02c3b81a5\n"
	       "  ik: f19c20ca863137f8892326d959ec5e01\n"
	       "  res: 9af5a557902d2db80000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 7526fc13c5976685\n"
	       "  sres: 0ad888ef\n"
	       "  auth_types: 03000000\n"
	      );
	fprintf(stderr, "[1]: ");
	VEC_IS(&vecs[1],
	       "  rand: 9a8321b108ef38a01c93241a9f1a9b50\n"
	       "  autn: 79a5113eb0910000be6020540503ffc5\n"
	       "  ck: 3686f05df057d1899c66ae4eb18cf941\n"
	       "  ik: 79f21ed53bcb47787de57d136ff803a5\n"
	       "  res: 43023475cb29292c0000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: aef73dd515e86c15\n"
	       "  sres: 882b1d59\n"
	       "  auth_types: 03000000\n"
	      );
	fprintf(stderr, "[2]: ");
	VEC_IS(&vecs[2],
	       "  rand: ab9432c2190049b12da4352bb02bac61\n"
	       "  autn: 24b018d46c3b00009c7e1b47f3a19b2b\n"
	       "  ck: d86c3191a36fc0602e48202ef2080964\n"
	       "  ik: 648dab72016181406243420649e63dc9\n"
	       "  res: 010cab11cc63a6e40000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: f0eaf8cb19e0758d\n"
	       "  sres: cd6f0df5\n"
	       "  auth_types: 03000000\n"
	      );
}

static void test_gen_vectors_3g_only(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	struct osmo_auth_vector vecs[3];
	uint8_t auts[14];
	uint8_t rand_auts[16];
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){ 0 };

	aud3g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_MILENAGE,
		.u.umts.sqn = 31,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud3g.u.umts.k, sizeof(aud3g.u.umts.k));
	osmo_hexparse("FB2A3D1B360F599ABAB99DB8669F8308",
		      aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc));
	next_rand("39fa2f4e3d523d8619a73b4f65c3e14d", true);

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 32, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55d30000541dde77ea5b1d8c\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 059a4f668f6fbe39\n"
	       "  sres: 9b36efdf\n"
	       "  auth_types: 03000000\n"
	      );

	/* Note: 3GPP TS 33.102 6.8.1.2: c3 function to get GSM auth is
	 * KC[0..7] == CK[0..7] ^ CK[8..15] ^ IK[0..7] ^ IK[8..15]
	 * In [16]: hex(  0xf64735036e587131
	 *              ^ 0x9c679f4742a75ea1
	 *              ^ 0x27497388b6cb0446
	 *              ^ 0x48f396aa155b95ef)
	 * Out[16]: '0x59a4f668f6fbe39L'
	 * hence expecting kc: 059a4f668f6fbe39
	 */

	/* even though vec is not zero-initialized, it should produce the same
	 * result with the same sequence nr */
	aud3g.u.umts.sqn = 31;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 32, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55d30000541dde77ea5b1d8c\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 059a4f668f6fbe39\n"
	       "  sres: 9b36efdf\n"
	       "  auth_types: 03000000\n"
	      );


	fprintf(stderr, "- test AUTS resync\n");
	vec = (struct osmo_auth_vector){};
	aud3g.u.umts.sqn = 31;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);

	/* The AUTN sent was 8704f5ba55f30000d2ee44b22c8ea919
	 * with the first 6 bytes being SQN ^ AK.
	 * K = EB215756028D60E3275E613320AEC880
	 * OPC = FB2A3D1B360F599ABAB99DB8669F8308
	 * RAND = 39fa2f4e3d523d8619a73b4f65c3e14d
	 * --milenage-f5-->
	 * AK = 8704f5ba55f3
	 *
	 * The first six bytes are 8704f5ba55f3,
	 * and 8704f5ba55f3 ^ AK = 0.
	 * --> SQN = 0.
	 *
	 * Say the USIM doesn't like that, let's say it is at SQN 23.
	 * SQN_MS = 000000000017
	 *
	 * AUTS = Conc(SQN_MS) || MAC-S
	 * Conc(SQN_MS) = SQN_MS ⊕ f5*[K](RAND)
	 * MAC-S = f1*[K] (SQN MS || RAND || AMF)
	 *
	 * f5*--> Conc(SQN_MS) = 000000000017 ^ 979498b1f73a
	 *                     = 979498b1f72d
	 * AMF = 0000 (TS 33.102 v7.0.0, 6.3.3)
	 *
	 * MAC-S = f1*[K] (000000000017 || 39fa2f4e3d523d8619a73b4f65c3e14d || 0000)
	 *       = 3e28c59fa2e72f9c
	 *
	 * AUTS = 979498b1f72d || 3e28c59fa2e72f9c
	 *
	 * verify valid AUTS resulting in SQN 23 with:
	 * osmo-auc-gen -3 -a milenage -k EB215756028D60E3275E613320AEC880 \
	 *              -o FB2A3D1B360F599ABAB99DB8669F8308 \
	 *              -r 39fa2f4e3d523d8619a73b4f65c3e14d \
	 *              -A 979498b1f72d3e28c59fa2e72f9c
	 */

	/* AUTS response by USIM */
	osmo_hexparse("979498b1f72d3e28c59fa2e72f9c",
		      auts, sizeof(auts));
	/* RAND sent to USIM, which AUTS was generated from */
	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d",
		      rand_auts, sizeof(rand_auts));
	/* new RAND token for the next key */
	next_rand("897210a0f7de278f0b8213098e098a3f", true);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, rand_auts, auts);
	VERBOSE_ASSERT(rc, == 1, "%d");
	/* The USIM's last sqn was 23, the calculated vector was 24 */
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 24, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 897210a0f7de278f0b8213098e098a3f\n"
	       "  autn: c6b9790dad4b00000cf322869ea6a481\n"
	       "  ck: e9922bd036718ed9e40bd1d02c3b81a5\n"
	       "  ik: f19c20ca863137f8892326d959ec5e01\n"
	       "  res: 9af5a557902d2db80000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 7526fc13c5976685\n"
	       "  sres: 0ad888ef\n"
	       "  auth_types: 03000000\n"
	      );


	fprintf(stderr, "- verify N vectors with AUTS resync"
		" == N vectors without AUTS\n"
		"First just set rand and sqn = 23, and compute 3 vectors\n");
	next_rand("897210a0f7de278f0b8213098e098a3f", false);
	aud3g.u.umts.sqn = 23;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 23, "%"PRIu64);

	memset(vecs, 0, sizeof(vecs));
	rc = auc_compute_vectors(vecs, 3, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 3, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 26, "%"PRIu64);

	_test_gen_vectors_3g_only__expect_vecs(vecs);

	fprintf(stderr, "Now reach sqn = 23 with AUTS and expect the same\n");
	/* AUTS response by USIM */
	osmo_hexparse("979498b1f72d3e28c59fa2e72f9c",
		      auts, sizeof(auts));
	/* RAND sent to USIM, which AUTS was generated from */
	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d",
		      rand_auts, sizeof(rand_auts));
	next_rand("897210a0f7de278f0b8213098e098a3f", false);
	rc = auc_compute_vectors(vecs, 3, &aud2g, &aud3g, rand_auts, auts);

	_test_gen_vectors_3g_only__expect_vecs(vecs);

	comment_end();
}

void test_gen_vectors_bad_args()
{
	struct osmo_auth_vector vec;
	uint8_t auts[14];
	uint8_t rand_auts[16];
	int rc;
	int i;

	struct osmo_sub_auth_data aud2g = {
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_COMP128v1,
	};

	struct osmo_sub_auth_data aud3g = {
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_MILENAGE,
	};

	struct osmo_sub_auth_data aud2g_noalg = {
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_NONE,
	};

	struct osmo_sub_auth_data aud3g_noalg = {
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_NONE,
	};

	struct osmo_sub_auth_data aud_notype = {
		.type = OSMO_AUTH_TYPE_NONE,
		.algo = OSMO_AUTH_ALG_MILENAGE,
	};

	struct osmo_sub_auth_data no_aud = {
		.type = OSMO_AUTH_TYPE_NONE,
		.algo = OSMO_AUTH_ALG_NONE,
	};

	struct {
		struct osmo_sub_auth_data *aud2g;
		struct osmo_sub_auth_data *aud3g;
		uint8_t *rand_auts;
		uint8_t *auts;
		const char *label;
	} tests[] = {
		{         NULL,         NULL,       NULL,  NULL, "no auth data (a)"},
		{         NULL, &aud3g_noalg,       NULL,  NULL, "no auth data (b)"},
		{         NULL,  &aud_notype,       NULL,  NULL, "no auth data (c)"},
		{         NULL,      &no_aud,       NULL,  NULL, "no auth data (d)"},
		{ &aud2g_noalg,         NULL,       NULL,  NULL, "no auth data (e)"},
		{ &aud2g_noalg, &aud3g_noalg,       NULL,  NULL, "no auth data (f)"},
		{ &aud2g_noalg,  &aud_notype,       NULL,  NULL, "no auth data (g)"},
		{ &aud2g_noalg,      &no_aud,       NULL,  NULL, "no auth data (h)"},
		{  &aud_notype,         NULL,       NULL,  NULL, "no auth data (i)"},
		{  &aud_notype, &aud3g_noalg,       NULL,  NULL, "no auth data (j)"},
		{  &aud_notype,  &aud_notype,       NULL,  NULL, "no auth data (k)"},
		{  &aud_notype,      &no_aud,       NULL,  NULL, "no auth data (l)"},
		{      &no_aud,         NULL,       NULL,  NULL, "no auth data (m)"},
		{      &no_aud, &aud3g_noalg,       NULL,  NULL, "no auth data (n)"},
		{      &no_aud,  &aud_notype,       NULL,  NULL, "no auth data (o)"},
		{      &no_aud,      &no_aud,       NULL,  NULL, "no auth data (p)"},
		{       &aud3g,         NULL,       NULL,  NULL, "wrong auth data type (a)"},
		{       &aud3g, &aud3g_noalg,       NULL,  NULL, "wrong auth data type (b)"},
		{       &aud3g,  &aud_notype,       NULL,  NULL, "wrong auth data type (c)"},
		{       &aud3g,      &no_aud,       NULL,  NULL, "wrong auth data type (d)"},
		{         NULL,       &aud2g,       NULL,  NULL, "wrong auth data type (e)"},
		{ &aud3g_noalg,       &aud2g,       NULL,  NULL, "wrong auth data type (f)"},
		{  &aud_notype,       &aud2g,       NULL,  NULL, "wrong auth data type (g)"},
		{      &no_aud,       &aud2g,       NULL,  NULL, "wrong auth data type (h)"},
		{       &aud3g,       &aud2g,       NULL,  NULL, "wrong auth data type (i)"},
		{       &aud3g,       &aud3g,       NULL,  NULL, "wrong auth data type (j)"},
		{       &aud2g,       &aud2g,       NULL,  NULL, "wrong auth data type (k)"},
		{       &aud2g,         NULL,  rand_auts,  auts, "AUTS for 2G-only (a)"},
		{       &aud2g, &aud3g_noalg,  rand_auts,  auts, "AUTS for 2G-only (b)"},
		{       &aud2g,  &aud_notype,  rand_auts,  auts, "AUTS for 2G-only (c)"},
		{       &aud2g,      &no_aud,  rand_auts,  auts, "AUTS for 2G-only (d)"},
		{         NULL,       &aud3g,       NULL,  auts, "incomplete AUTS (a)"},
		{         NULL,       &aud3g,  rand_auts,  NULL, "incomplete AUTS (b)"},
		{       &aud2g,       &aud3g,       NULL,  auts, "incomplete AUTS (c)"},
		{       &aud2g,       &aud3g,  rand_auts,  NULL, "incomplete AUTS (d)"},
	};

	comment_start();

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		fprintf(stderr, "\n- %s\n", tests[i].label);
		rc = auc_compute_vectors(&vec, 1,
					 tests[i].aud2g,
					 tests[i].aud3g,
					 tests[i].rand_auts,
					 tests[i].auts);
		VERBOSE_ASSERT(rc, < 0, "%d");
	}

	comment_end();
}

static struct {
	bool verbose;
} cmdline_opts = {
	.verbose = false,
};

static void print_help(const char *program)
{
	printf("Usage:\n"
	       "  %s [-v] [N [N...]]\n"
	       "Options:\n"
	       "  -h --help      show this text.\n"
	       "  -v --verbose   print source file and line numbers\n",
	       program
	       );
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"verbose", 1, 0, 'v'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help(argv[0]);
			exit(0);
		case 'v':
			cmdline_opts.verbose = true;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "too many args\n");
		exit(-1);
	}
}

int main(int argc, char **argv)
{
	printf("auc_3g_test.c\n");

	handle_options(argc, argv);

	osmo_init_logging(&hlr_log_info);
	log_set_print_filename(osmo_stderr_target, cmdline_opts.verbose);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_gen_vectors_2g_only();
	test_gen_vectors_2g_plus_3g();
	test_gen_vectors_3g_only();
	test_gen_vectors_bad_args();

	printf("Done\n");
	return 0;
}
