/* gen_ts_55_205_test_sets/func_template.c: Template to generate test code
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

static void {func_name}(void)
{{
        struct osmo_sub_auth_data aud2g;
        struct osmo_sub_auth_data aud3g;
        struct osmo_auth_vector vec;
        int rc;

        comment_start();

        aud2g = (struct osmo_sub_auth_data){{ 0 }};

        aud3g = (struct osmo_sub_auth_data){{
                .type = OSMO_AUTH_TYPE_UMTS,
                .algo = OSMO_AUTH_ALG_MILENAGE,
		.u.umts.sqn = 31,
        }};

        osmo_hexparse("{Ki}",
                      aud3g.u.umts.k, sizeof(aud3g.u.umts.k));
        osmo_hexparse("{OPc}",
                      aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc));

        osmo_hexparse("{RAND}",
                      fake_rand, sizeof(fake_rand));

        vec = (struct osmo_auth_vector){{ {{0}} }};
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 31, "%"PRIu64);
        rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
        VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 32, "%"PRIu64);

        VEC_IS(&vec,
               "  rand: {RAND}\n"
               "  ck: {MIL3G-CK}\n"
               "  ik: {MIL3G-IK}\n"
               "  res: {MIL3G-RES}0000000000000000\n"
               "  kc: {Kc}\n"
               "  sres: {SRES#1}\n"
              );

	comment_end();
}}
