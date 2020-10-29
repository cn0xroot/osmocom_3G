/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>

#include "gsup_server.h"
#include "gsup_router.h"

static void osmo_gsup_server_send(struct osmo_gsup_conn *conn,
			     int proto_ext, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, proto_ext);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_server_conn_send(conn->conn, msg_tx);
}

int osmo_gsup_conn_send(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	if (!conn) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	osmo_gsup_server_send(conn, IPAC_PROTO_EXT_GSUP, msg);

	return 0;
}

static int osmo_gsup_conn_oap_handle(struct osmo_gsup_conn *conn,
				struct msgb *msg_rx)
{
#if 0
	int rc;
	struct msgb *msg_tx;
	rc = oap_handle(&conn->oap_state, msg_rx, &msg_tx);
	msgb_free(msg_rx);
	if (rc < 0)
		return rc;

	if (msg_tx)
		osmo_gsup_conn_send(conn, IPAC_PROTO_EXT_OAP, msg_tx);
#endif
	return 0;
}

/* Data from a given client has arrived over the socket */
static int osmo_gsup_server_read_cb(struct ipa_server_conn *conn,
			       struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;
	int rc;

	msg->l2h = &hh->data[0];

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		rc = ipa_server_conn_ccm(conn, msg);
		if (rc < 0) {
			/* conn is already invalid here! */
			return -1;
		}
		msgb_free(msg);
		return 0;
	}

	if (hh->proto != IPAC_PROTO_OSMO) {
		LOGP(DLGSUP, LOGL_NOTICE, "Unsupported IPA stream ID 0x%02x\n",
			hh->proto);
		goto invalid;
	}

	if (!he || msgb_l2len(msg) < sizeof(*he)) {
		LOGP(DLGSUP, LOGL_NOTICE, "short IPA message\n");
		goto invalid;
	}

	msg->l2h = &he->data[0];

	if (he->proto == IPAC_PROTO_EXT_GSUP) {
		OSMO_ASSERT(clnt->server->read_cb != NULL);
		clnt->server->read_cb(clnt, msg);
		/* expecting read_cb() to free msg */
	} else if (he->proto == IPAC_PROTO_EXT_OAP) {
		return osmo_gsup_conn_oap_handle(clnt, msg);
		/* osmo_gsup_client_oap_handle frees msg */
	} else {
		LOGP(DLGSUP, LOGL_NOTICE, "Unsupported IPA Osmo Proto 0x%02x\n",
			hh->proto);
		goto invalid;
	}

	return 0;

invalid:
	LOGP(DLGSUP, LOGL_NOTICE,
	     "GSUP received an invalid IPA message from %s:%d: %s\n",
	     conn->addr, conn->port, osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));
	msgb_free(msg);
	return -1;

}

static void osmo_tlvp_dump(const struct tlv_parsed *tlvp,
			   int subsys, int level)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tlvp->lv); i++) {
		if (!TLVP_PRESENT(tlvp, i))
			continue;

		LOGP(subsys, level, "%u: %s\n", i,
			TLVP_VAL(tlvp, i));
		LOGP(subsys, level, "%u: %s\n", i,
			osmo_hexdump(TLVP_VAL(tlvp, i),
				     TLVP_LEN(tlvp, i)));
	}
}

/* FIXME: should this be parrt of ipas_server handling, not GSUP? */
static void tlvp_copy(void *ctx, struct tlv_parsed *out, const struct tlv_parsed *in)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(out->lv); i++) {
		if (!TLVP_PRESENT(in, i)) {
			if (TLVP_PRESENT(out, i)) {
				talloc_free((void *) out->lv[i].val);
				out->lv[i].val = NULL;
				out->lv[i].len = 0;
			}
			continue;
		}
		out->lv[i].val = talloc_memdup(ctx, in->lv[i].val, in->lv[i].len);
		out->lv[i].len = in->lv[i].len;
	}
}

int osmo_gsup_conn_ccm_get(const struct osmo_gsup_conn *clnt, uint8_t **addr,
			   uint8_t tag)
{
	if (!TLVP_PRESENT(&clnt->ccm, tag))
		return -ENODEV;
	*addr = (uint8_t *) TLVP_VAL(&clnt->ccm, tag);

	return TLVP_LEN(&clnt->ccm, tag);
}

static int osmo_gsup_server_ccm_cb(struct ipa_server_conn *conn,
				   struct msgb *msg, struct tlv_parsed *tlvp,
				   struct ipaccess_unit *unit)
{
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;
	uint8_t *addr = NULL;
	size_t addr_len;

	LOGP(DLGSUP, LOGL_INFO, "CCM Callback\n");

	/* FIXME: should this be parrt of ipas_server handling, not
	 * GSUP? */
	tlvp_copy(clnt, &clnt->ccm, tlvp);
	osmo_tlvp_dump(tlvp, DLGSUP, LOGL_INFO);

	addr_len = osmo_gsup_conn_ccm_get(clnt, &addr, IPAC_IDTAG_SERNR);
	if (addr_len <= 0) {
		LOGP(DLGSUP, LOGL_ERROR, "GSUP client %s:%u has no %s IE and"
		     " cannot be routed\n",
		     conn->addr, conn->port,
		     ipa_ccm_idtag_name(IPAC_IDTAG_SERNR));
		return -EINVAL;
	}

	gsup_route_add(clnt, addr, addr_len);
	return 0;
}

static int osmo_gsup_server_closed_cb(struct ipa_server_conn *conn)
{
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;

	LOGP(DLGSUP, LOGL_INFO, "Lost GSUP client %s:%d\n",
		conn->addr, conn->port);

	gsup_route_del_conn(clnt);
	llist_del(&clnt->list);
	talloc_free(clnt);

	return 0;
}

/* Add conn to the clients list in a way that conn->auc_3g_ind takes the lowest
 * unused integer and the list of clients remains sorted by auc_3g_ind.
 * Keep this function non-static to allow linking in a unit test. */
void osmo_gsup_server_add_conn(struct llist_head *clients,
			       struct osmo_gsup_conn *conn)
{
	struct osmo_gsup_conn *c;
	struct osmo_gsup_conn *prev_conn;

	c = llist_first_entry_or_null(clients, struct osmo_gsup_conn, list);

	/* Is the first index, 0, unused? */
	if (!c || c->auc_3g_ind > 0) {
		conn->auc_3g_ind = 0;
		llist_add(&conn->list, clients);
		return;
	}

	/* Look for a gap later on */
	prev_conn = NULL;
	llist_for_each_entry(c, clients, list) {
		/* skip first item, we know it has auc_3g_ind == 0. */
		if (!prev_conn) {
			prev_conn = c;
			continue;
		}
		if (c->auc_3g_ind > prev_conn->auc_3g_ind + 1)
			break;
		prev_conn = c;
	}

	OSMO_ASSERT(prev_conn);

	conn->auc_3g_ind = prev_conn->auc_3g_ind + 1;
	llist_add(&conn->list, &prev_conn->list);
}

/* a client has connected to the server socket and we have accept()ed it */
static int osmo_gsup_server_accept_cb(struct ipa_server_link *link, int fd)
{
	struct osmo_gsup_conn *conn;
	struct osmo_gsup_server *gsups =
		(struct osmo_gsup_server *) link->data;
	int rc;

	conn = talloc_zero(gsups, struct osmo_gsup_conn);
	OSMO_ASSERT(conn);

	conn->conn = ipa_server_conn_create(gsups, link, fd,
					   osmo_gsup_server_read_cb,
					   osmo_gsup_server_closed_cb, conn);
	OSMO_ASSERT(conn->conn);
	conn->conn->ccm_cb = osmo_gsup_server_ccm_cb;

	/* link data structure with server structure */
	conn->server = gsups;
	osmo_gsup_server_add_conn(&gsups->clients, conn);

	LOGP(DLGSUP, LOGL_INFO, "New GSUP client %s:%d (IND=%u)\n",
	     conn->conn->addr, conn->conn->port, conn->auc_3g_ind);

	/* request the identity of the client */
	rc = ipa_ccm_send_id_req(fd);
	if (rc < 0)
		goto failed;
#if 0
	rc = oap_init(&gsups->oap_config, &conn->oap_state);
	if (rc != 0)
		goto failed;
#endif
	return 0;
failed:
	ipa_server_conn_destroy(conn->conn);
	return -1;
}

struct osmo_gsup_server *
osmo_gsup_server_create(void *ctx, const char *ip_addr, uint16_t tcp_port,
			osmo_gsup_read_cb_t read_cb,
			struct llist_head *lu_op_lst)
{
	struct osmo_gsup_server *gsups;
	int rc;

	gsups = talloc_zero(ctx, struct osmo_gsup_server);
	OSMO_ASSERT(gsups);

	INIT_LLIST_HEAD(&gsups->clients);
	INIT_LLIST_HEAD(&gsups->routes);

	gsups->link = ipa_server_link_create(gsups,
					/* no e1inp */ NULL,
					ip_addr, tcp_port,
					osmo_gsup_server_accept_cb,
					gsups);
	if (!gsups->link)
		goto failed;

	gsups->read_cb = read_cb;

	rc = ipa_server_link_open(gsups->link);
	if (rc < 0)
		goto failed;

	gsups->luop = lu_op_lst;

	return gsups;

failed:
	osmo_gsup_server_destroy(gsups);
	return NULL;
}

void osmo_gsup_server_destroy(struct osmo_gsup_server *gsups)
{
	if (gsups->link) {
		ipa_server_link_close(gsups->link);
		ipa_server_link_destroy(gsups->link);
		gsups->link = NULL;
	}
	talloc_free(gsups);
}
