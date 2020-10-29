#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>

struct osmo_gsup_conn;

/* Expects message in msg->l2h */
typedef int (*osmo_gsup_read_cb_t)(struct osmo_gsup_conn *conn, struct msgb *msg);

struct osmo_gsup_server {
	/* list of osmo_gsup_conn */
	struct llist_head clients;

	/* lu_operations list */
	struct llist_head *luop;

	struct ipa_server_link *link;
	osmo_gsup_read_cb_t read_cb;
	struct llist_head routes;
};


/* a single connection to a given client (SGSN, MSC) */
struct osmo_gsup_conn {
	struct llist_head list;

	struct osmo_gsup_server *server;
	struct ipa_server_conn *conn;
	//struct oap_state oap_state;
	struct tlv_parsed ccm;

	unsigned int auc_3g_ind; /*!< IND index used for UMTS AKA SQN */
};


int osmo_gsup_conn_send(struct osmo_gsup_conn *conn, struct msgb *msg);
int osmo_gsup_conn_ccm_get(const struct osmo_gsup_conn *clnt, uint8_t **addr,
			   uint8_t tag);

struct osmo_gsup_server *osmo_gsup_server_create(void *ctx,
						 const char *ip_addr,
						 uint16_t tcp_port,
						 osmo_gsup_read_cb_t read_cb,
						 struct llist_head *lu_op_lst);

void osmo_gsup_server_destroy(struct osmo_gsup_server *gsups);

