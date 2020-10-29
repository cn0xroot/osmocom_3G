/* OsmoHLR TX/RX lu operations */

/* (C) 2017 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Harald Welte <laforge@gnumonks.org>
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

#pragma once

#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsup.h>

#include "db.h"

#define CANCEL_TIMEOUT_SECS	30
#define ISD_TIMEOUT_SECS	30

enum lu_state {
	LU_S_NULL,
	LU_S_LU_RECEIVED,
	LU_S_CANCEL_SENT,
	LU_S_CANCEL_ACK_RECEIVED,
	LU_S_ISD_SENT,
	LU_S_ISD_ACK_RECEIVED,
	LU_S_COMPLETE,
};

extern const struct value_string lu_state_names[];

struct lu_operation {
	/*! entry in global list of location update operations */
	struct llist_head list;
	/*! to which gsup_server do we belong */
	struct osmo_gsup_server *gsup_server;
	/*! state of the location update */
	enum lu_state state;
	/*! CS (false) or PS (true) Location Update? */
	bool is_ps;
	/*! currently running timer */
	struct osmo_timer_list timer;

	/*! subscriber related to this operation */
	struct hlr_subscriber subscr;
	/*! peer VLR/SGSN starting the request */
	uint8_t *peer;
};

int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg);

struct lu_operation *lu_op_alloc(struct osmo_gsup_server *srv);
struct lu_operation *lu_op_alloc_conn(struct osmo_gsup_conn *conn);
void lu_op_statechg(struct lu_operation *luop, enum lu_state new_state);
bool lu_op_fill_subscr(struct lu_operation *luop, struct db_context *dbc,
		       const char *imsi);
struct lu_operation *lu_op_by_imsi(const char *imsi,
				   const struct llist_head *lst);

void lu_op_tx_error(struct lu_operation *luop, enum gsm48_gmm_cause cause);
void lu_op_tx_ack(struct lu_operation *luop);
void lu_op_tx_cancel_old(struct lu_operation *luop);
void lu_op_tx_insert_subscr_data(struct lu_operation *luop);
void lu_op_tx_del_subscr_data(struct lu_operation *luop);
