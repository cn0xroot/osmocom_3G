/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/core/utils.h>
#include "gsup_server.h"

#define comment_start() printf("\n===== %s\n", __func__)
#define comment_end() printf("===== %s: SUCCESS\n\n", __func__)
#define btw(fmt, args...) printf("\n" fmt "\n", ## args)

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		printf(#val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0)

void osmo_gsup_server_add_conn(struct llist_head *clients,
			       struct osmo_gsup_conn *conn);

static void test_add_conn(void)
{
	struct llist_head _list;
	struct llist_head *clients = &_list;
	struct osmo_gsup_conn conn_inst[23] = {};
	struct osmo_gsup_conn *conn;
	unsigned int i;

	comment_start();

	INIT_LLIST_HEAD(clients);

	btw("Add 10 items");
	for (i = 0; i < 10; i++) {
		osmo_gsup_server_add_conn(clients, &conn_inst[i]);
		printf("conn_inst[%u].auc_3g_ind == %u\n", i, conn_inst[i].auc_3g_ind);
		OSMO_ASSERT(clients->next == &conn_inst[0].list);
	}

	btw("Expecting a list of 0..9");
	i = 0;
	llist_for_each_entry(conn, clients, list) {
		printf("conn[%u].auc_3g_ind == %u\n", i, conn->auc_3g_ind);
		OSMO_ASSERT(conn->auc_3g_ind == i);
		OSMO_ASSERT(conn == &conn_inst[i]);
		i++;
	}

	btw("Punch two holes in the sequence in arbitrary order,"
	    " a larger one from 2..4 and a single one at 7.");
	llist_del(&conn_inst[4].list);
	llist_del(&conn_inst[2].list);
	llist_del(&conn_inst[3].list);
	llist_del(&conn_inst[7].list);

	btw("Expecting a list of 0,1, 5,6, 8,9");
	i = 0;
	llist_for_each_entry(conn, clients, list) {
		printf("conn[%u].auc_3g_ind == %u\n", i, conn->auc_3g_ind);
		i++;
	}

	btw("Add conns, expecting them to take the open slots");
	osmo_gsup_server_add_conn(clients, &conn_inst[12]);
	VERBOSE_ASSERT(conn_inst[12].auc_3g_ind, == 2, "%u");

	osmo_gsup_server_add_conn(clients, &conn_inst[13]);
	VERBOSE_ASSERT(conn_inst[13].auc_3g_ind, == 3, "%u");

	osmo_gsup_server_add_conn(clients, &conn_inst[14]);
	VERBOSE_ASSERT(conn_inst[14].auc_3g_ind, == 4, "%u");

	osmo_gsup_server_add_conn(clients, &conn_inst[17]);
	VERBOSE_ASSERT(conn_inst[17].auc_3g_ind, == 7, "%u");

	osmo_gsup_server_add_conn(clients, &conn_inst[18]);
	VERBOSE_ASSERT(conn_inst[18].auc_3g_ind, == 10, "%u");

	btw("Expecting a list of 0..10");
	i = 0;
	llist_for_each_entry(conn, clients, list) {
		printf("conn[%u].auc_3g_ind == %u\n", i, conn->auc_3g_ind);
		OSMO_ASSERT(conn->auc_3g_ind == i);
		i++;
	}

	btw("Does it also work for the first item?");
	llist_del(&conn_inst[0].list);

	btw("Expecting a list of 1..10");
	i = 0;
	llist_for_each_entry(conn, clients, list) {
		printf("conn[%u].auc_3g_ind == %u\n", i, conn->auc_3g_ind);
		OSMO_ASSERT(conn->auc_3g_ind == i + 1);
		i++;
	}

	btw("Add another conn, should take auc_3g_ind == 0");
	osmo_gsup_server_add_conn(clients, &conn_inst[20]);
	VERBOSE_ASSERT(conn_inst[20].auc_3g_ind, == 0, "%u");

	btw("Expecting a list of 0..10");
	i = 0;
	llist_for_each_entry(conn, clients, list) {
		printf("conn[%u].auc_3g_ind == %u\n", i, conn->auc_3g_ind);
		OSMO_ASSERT(conn->auc_3g_ind == i);
		i++;
	}

	btw("If a client reconnects, it will (likely) get the same auc_3g_ind");
	VERBOSE_ASSERT(conn_inst[5].auc_3g_ind, == 5, "%u");
	llist_del(&conn_inst[5].list);
	conn_inst[5].auc_3g_ind = 423;
	osmo_gsup_server_add_conn(clients, &conn_inst[5]);
	VERBOSE_ASSERT(conn_inst[5].auc_3g_ind, == 5, "%u");

	comment_end();
}

int main(int argc, char **argv)
{
	printf("test_gsup_server.c\n");

	test_add_conn();

	printf("Done\n");
	return 0;
}
