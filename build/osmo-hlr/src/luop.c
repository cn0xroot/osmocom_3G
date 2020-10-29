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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>

#include "gsup_server.h"
#include "gsup_router.h"
#include "logging.h"
#include "luop.h"

const struct value_string lu_state_names[] = {
	{ LU_S_NULL,			"NULL" },
	{ LU_S_LU_RECEIVED,		"LU RECEIVED" },
	{ LU_S_CANCEL_SENT,		"CANCEL SENT" },
	{ LU_S_CANCEL_ACK_RECEIVED,	"CANCEL-ACK RECEIVED" },
	{ LU_S_ISD_SENT,		"ISD SENT" },
	{ LU_S_ISD_ACK_RECEIVED,	"ISD-ACK RECEIVED" },
	{ LU_S_COMPLETE,		"COMPLETE" },
	{ 0, NULL }
};

/* Transmit a given GSUP message for the given LU operation */
static void _luop_tx_gsup(struct lu_operation *luop,
			  const struct osmo_gsup_message *gsup)
{
	struct msgb *msg_out;

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP LUOP");
	osmo_gsup_encode(msg_out, gsup);

	osmo_gsup_addr_send(luop->gsup_server, luop->peer,
			    talloc_total_size(luop->peer),
			    msg_out);
}

static inline void fill_gsup_msg(struct osmo_gsup_message *out,
				 const struct lu_operation *lu,
				 enum osmo_gsup_message_type mt)
{
	memset(out, 0, sizeof(struct osmo_gsup_message));
	if (lu)
		osmo_strlcpy(out->imsi, lu->subscr.imsi,
			     GSM23003_IMSI_MAX_DIGITS + 1);
	out->message_type = mt;
}

/* timer call-back in case LU operation doesn't receive an response */
static void lu_op_timer_cb(void *data)
{
	struct lu_operation *luop = data;

	DEBUGP(DMAIN, "LU OP timer expired in state %s\n",
		get_value_string(lu_state_names, luop->state));

	switch (luop->state) {
	case LU_S_CANCEL_SENT:
		break;
	case LU_S_ISD_SENT:
		break;
	default:
		break;
	}

	lu_op_tx_error(luop, GMM_CAUSE_NET_FAIL);
}

bool lu_op_fill_subscr(struct lu_operation *luop, struct db_context *dbc,
		       const char *imsi)
{
	struct hlr_subscriber *subscr = &luop->subscr;

	if (db_subscr_get(dbc, imsi, subscr) < 0)
		return false;

	return true;
}

struct lu_operation *lu_op_alloc(struct osmo_gsup_server *srv)
{
	struct lu_operation *luop;

	luop = talloc_zero(srv, struct lu_operation);
	OSMO_ASSERT(luop);
	luop->gsup_server = srv;
	luop->timer.cb = lu_op_timer_cb;
	luop->timer.data = luop;

	return luop;
}

struct lu_operation *lu_op_alloc_conn(struct osmo_gsup_conn *conn)
{
	uint8_t *peer_addr;
	struct lu_operation *luop = lu_op_alloc(conn->server);
	int rc = osmo_gsup_conn_ccm_get(conn, &peer_addr, IPAC_IDTAG_SERNR);
	if (rc < 0)
		return NULL;

	luop->peer = talloc_memdup(luop, peer_addr, rc);

	return luop;
}

/* FIXME: this doesn't seem to work at all */
struct lu_operation *lu_op_by_imsi(const char *imsi,
				   const struct llist_head *lst)
{
	struct lu_operation *luop;

	llist_for_each_entry(luop, lst, list) {
		if (!strcmp(imsi, luop->subscr.imsi))
			return luop;
	}
	return NULL;
}

void lu_op_statechg(struct lu_operation *luop, enum lu_state new_state)
{
	enum lu_state old_state = luop->state;

	DEBUGP(DMAIN, "LU OP state change: %s -> ",
		get_value_string(lu_state_names, old_state));
	DEBUGPC(DMAIN, "%s\n",
		get_value_string(lu_state_names, new_state));

	luop->state = new_state;
}

/* Send a msgb to a given address using routing */
int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg)
{
	struct osmo_gsup_conn *conn;

	conn = gsup_route_find(gs, addr, addrlen);
	if (!conn) {
		DEBUGP(DMAIN, "Cannot find route for addr %s\n", addr);
		msgb_free(msg);
		return -ENODEV;
	}

	return osmo_gsup_conn_send(conn, msg);
}

/*! Transmit UPD_LOC_ERROR and destroy lu_operation */
void lu_op_tx_error(struct lu_operation *luop, enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup;

	DEBUGP(DMAIN, "%s: LU OP Tx Error (cause %s)\n",
	       luop->subscr.imsi, get_value_string(gsm48_gmm_cause_names,
						   cause));

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR);
	gsup.cause = cause;

	_luop_tx_gsup(luop, &gsup);

	llist_del(&luop->list);
	talloc_free(luop);
}

/*! Transmit UPD_LOC_RESULT and destroy lu_operation */
void lu_op_tx_ack(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT);
	//FIXME gsup.hlr_enc;

	_luop_tx_gsup(luop, &gsup);

	llist_del(&luop->list);
	talloc_free(luop);
}

/*! Send Cancel Location to old VLR/SGSN */
void lu_op_tx_cancel_old(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED);

	fill_gsup_msg(&gsup, NULL, OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST);
	//gsup.cause = FIXME;
	//gsup.cancel_type = FIXME;

	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_CANCEL_SENT);
	osmo_timer_schedule(&luop->timer, CANCEL_TIMEOUT_SECS, 0);
}

/*! Transmit Insert Subscriber Data to new VLR/SGSN */
void lu_op_tx_insert_subscr_data(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;
	uint8_t apn[APN_MAXLEN];
	uint8_t msisdn_enc[43]; /* TODO use constant; TS 24.008 10.5.4.7 */
	int l;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED ||
		    luop->state == LU_S_CANCEL_ACK_RECEIVED);

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_INSERT_DATA_REQUEST);

	l = gsm48_encode_bcd_number(msisdn_enc, sizeof(msisdn_enc), 0,
				    luop->subscr.msisdn);
	if (l < 1) {
		LOGP(DMAIN, LOGL_ERROR,
		     "%s: Error: cannot encode MSISDN '%s'\n",
		     luop->subscr.imsi, luop->subscr.msisdn);
		lu_op_tx_error(luop, GMM_CAUSE_PROTO_ERR_UNSPEC);
		return;
	}
	gsup.msisdn_enc = msisdn_enc;
	gsup.msisdn_enc_len = l;

	/* FIXME: deal with encoding the following data */
	gsup.hlr_enc;

	if (luop->is_ps) {
		/* FIXME: PDP infos - use more fine-grained access control
		   instead of wildcard APN */
		l = osmo_apn_from_str(apn, sizeof(apn), "*");
		if (l > 0) {
			gsup.pdp_infos[0].apn_enc = apn;
			gsup.pdp_infos[0].apn_enc_len = l;
			gsup.pdp_infos[0].have_info = 1;
			gsup.num_pdp_infos = 1;
			/* FIXME: use real value: */
			gsup.pdp_infos[0].context_id = 1;
		}
	}

	/* Send ISD to new VLR/SGSN */
	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_ISD_SENT);
	osmo_timer_schedule(&luop->timer, ISD_TIMEOUT_SECS, 0);
}

/*! Transmit Delete Subscriber Data to new VLR/SGSN */
void lu_op_tx_del_subscr_data(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_DELETE_DATA_REQUEST);

	gsup.cn_domain = OSMO_GSUP_CN_DOMAIN_PS;

	/* Send ISD to new VLR/SGSN */
	_luop_tx_gsup(luop, &gsup);
}
