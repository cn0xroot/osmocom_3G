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

#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/ctrl/control_vty.h>

#include "db.h"
#include "hlr.h"
#include "ctrl.h"
#include "logging.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "rand.h"
#include "luop.h"
#include "hlr_vty.h"

static struct hlr *g_hlr;

/***********************************************************************
 * Send Auth Info handling
 ***********************************************************************/

/* process an incoming SAI request */
static int rx_send_auth_info(struct osmo_gsup_conn *conn,
			     const struct osmo_gsup_message *gsup,
			     struct db_context *dbc)
{
	struct osmo_gsup_message gsup_out;
	struct msgb *msg_out;
	int rc;

	/* initialize return message structure */
	memset(&gsup_out, 0, sizeof(gsup_out));
	memcpy(&gsup_out.imsi, &gsup->imsi, sizeof(gsup_out.imsi));

	rc = db_get_auc(dbc, gsup->imsi, conn->auc_3g_ind,
			gsup_out.auth_vectors,
			ARRAY_SIZE(gsup_out.auth_vectors),
			gsup->rand, gsup->auts);
	if (rc < 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
		gsup_out.cause = GMM_CAUSE_NET_FAIL;
	} else if (rc == 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
		gsup_out.cause = GMM_CAUSE_IMSI_UNKNOWN;
	} else {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT;
		gsup_out.num_auth_vectors = rc;
	}

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP AUC response");
	osmo_gsup_encode(msg_out, &gsup_out);
	return osmo_gsup_conn_send(conn, msg_out);
}

/***********************************************************************
 * LU Operation State / Structure
 ***********************************************************************/

static LLIST_HEAD(g_lu_ops);

/*! Receive Cancel Location Result from old VLR/SGSN */
void lu_op_rx_cancel_old_ack(struct lu_operation *luop,
			     const struct osmo_gsup_message *gsup)
{
	OSMO_ASSERT(luop->state == LU_S_CANCEL_SENT);
	/* FIXME: Check for spoofing */

	osmo_timer_del(&luop->timer);

	/* FIXME */

	lu_op_tx_insert_subscr_data(luop);
}

/*! Receive Insert Subscriber Data Result from new VLR/SGSN */
static void lu_op_rx_insert_subscr_data_ack(struct lu_operation *luop,
				    const struct osmo_gsup_message *gsup)
{
	OSMO_ASSERT(luop->state == LU_S_ISD_SENT);
	/* FIXME: Check for spoofing */

	osmo_timer_del(&luop->timer);

	/* Subscriber_Present_HLR */
	/* CS only: Check_SS_required? -> MAP-FW-CHECK_SS_IND.req */

	/* Send final ACK towards inquiring VLR/SGSN */
	lu_op_tx_ack(luop);
}

/*! Receive GSUP message for given \ref lu_operation */
void lu_op_rx_gsup(struct lu_operation *luop,
		  const struct osmo_gsup_message *gsup)
{
	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
		/* FIXME */
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
		lu_op_rx_insert_subscr_data_ack(luop, gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
		/* FIXME */
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		lu_op_rx_cancel_old_ack(luop, gsup);
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "Unhandled GSUP msg_type 0x%02x\n",
			gsup->message_type);
		break;
	}
}

/*! Receive Update Location Request, creates new \ref lu_operation */
static int rx_upd_loc_req(struct osmo_gsup_conn *conn,
			  const struct osmo_gsup_message *gsup)
{
	struct lu_operation *luop = lu_op_alloc_conn(conn);
	if (!luop) {
		LOGP(DMAIN, LOGL_ERROR, "LU REQ from conn without addr?\n");
		return -EINVAL;
	}

	lu_op_statechg(luop, LU_S_LU_RECEIVED);

	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		luop->is_ps = true;
	llist_add(&luop->list, &g_lu_ops);

	/* Roughly follwing "Process Update_Location_HLR" of TS 09.02 */

	/* check if subscriber is known at all */
	if (!lu_op_fill_subscr(luop, g_hlr->dbc, gsup->imsi)) {
		/* Send Error back: Subscriber Unknown in HLR */
		strcpy(luop->subscr.imsi, gsup->imsi);
		lu_op_tx_error(luop, GMM_CAUSE_IMSI_UNKNOWN);
		return 0;
	}

	/* Check if subscriber is generally permitted on CS or PS
	 * service (as requested) */
	if (!luop->is_ps && !luop->subscr.nam_cs) {
		lu_op_tx_error(luop, GMM_CAUSE_PLMN_NOTALLOWED);
		return 0;
	} else if (luop->is_ps && !luop->subscr.nam_ps) {
		lu_op_tx_error(luop, GMM_CAUSE_GPRS_NOTALLOWED);
		return 0;
	}

	/* TODO: Set subscriber tracing = deactive in VLR/SGSN */

#if 0
	/* Cancel in old VLR/SGSN, if new VLR/SGSN differs from old */
	if (luop->is_ps == false &&
	    strcmp(subscr->vlr_number, vlr_number)) {
		lu_op_tx_cancel_old(luop);
	} else if (luop->is_ps == true &&
		   strcmp(subscr->sgsn_number, sgsn_number)) {
		lu_op_tx_cancel_old(luop);
	} else
#endif
	{
		/* TODO: Subscriber allowed to roam in PLMN? */
		/* TODO: Update RoutingInfo */
		/* TODO: Reset Flag MS Purged (cs/ps) */
		/* TODO: Control_Tracing_HLR / Control_Tracing_HLR_with_SGSN */
		lu_op_tx_insert_subscr_data(luop);
	}
	return 0;
}

static int rx_purge_ms_req(struct osmo_gsup_conn *conn,
			   const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};
	struct msgb *msg_out;
	bool is_ps = false;
	int rc;

	LOGP(DAUC, LOGL_INFO, "%s: Purge MS (%s)\n", gsup->imsi,
		is_ps ? "PS" : "CS");

	memcpy(gsup_reply.imsi, gsup->imsi, sizeof(gsup_reply.imsi));

	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		is_ps = true;

	/* FIXME: check if the VLR that sends the purge is the same that
	 * we have on record. Only update if yes */

	/* Perform the actual update of the DB */
	rc = db_subscr_purge(g_hlr->dbc, gsup->imsi, is_ps);

	if (rc == 1)
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_RESULT;
	else if (rc == 0) {
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_ERROR;
		gsup_reply.cause = GMM_CAUSE_IMSI_UNKNOWN;
	} else {
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_ERROR;
		gsup_reply.cause = GMM_CAUSE_NET_FAIL;
	}

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP AUC response");
	osmo_gsup_encode(msg_out, &gsup_reply);
	return osmo_gsup_conn_send(conn, msg_out);
}

static int read_cb(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	static struct osmo_gsup_message gsup;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "error in GSUP decode: %d\n", rc);
		return rc;
	}

	switch (gsup.message_type) {
	/* requests sent to us */
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		rx_send_auth_info(conn, &gsup, g_hlr->dbc);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		rx_upd_loc_req(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		rx_purge_ms_req(conn, &gsup);
		break;
	/* responses to requests sent by us */
	case OSMO_GSUP_MSGT_DELETE_DATA_ERROR:
		LOGP(DMAIN, LOGL_ERROR, "Error while deleting subscriber data "
		     "for IMSI %s\n", gsup.imsi);
		break;
	case OSMO_GSUP_MSGT_DELETE_DATA_RESULT:
		LOGP(DMAIN, LOGL_ERROR, "Deleting subscriber data for IMSI %s\n",
		     gsup.imsi);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		{
			struct lu_operation *luop = lu_op_by_imsi(gsup.imsi,
								  &g_lu_ops);
			if (!luop) {
				LOGP(DMAIN, LOGL_ERROR, "GSUP message %s for "
				     "unknown IMSI %s\n",
				     osmo_gsup_message_type_name(gsup.message_type),
					gsup.imsi);
				break;
			}
			lu_op_rx_gsup(luop, &gsup);
		}
		break;
	default:
		LOGP(DMAIN, LOGL_DEBUG, "Unhandled GSUP message type %s\n",
		     osmo_gsup_message_type_name(gsup.message_type));
		break;
	}
	msgb_free(msg);
	return 0;
}

static void print_usage()
{
	printf("Usage: osmo-hlr\n");
}

static void print_help()
{
	printf("  -h --help                  This text.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -l --database db-name      The database to use.\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -s --disable-color         Do not print ANSI colors in the log\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -V --version               Print the version of OsmoHLR.\n");
}

static struct {
	const char *config_file;
	const char *db_file;
	bool daemonize;
} cmdline_opts = {
	.config_file = "osmo-hlr.cfg",
	.db_file = "hlr.db",
	.daemonize = false,
};

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"database", 1, 0, 'l'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"disable-color", 0, 0, 's'},
			{"log-level", 1, 0, 'e'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hc:l:d:Dse:TV",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'c':
			cmdline_opts.config_file = optarg;
			break;
		case 'l':
			cmdline_opts.db_file = optarg;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			cmdline_opts.daemonize = 1;
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

static void *hlr_ctx = NULL;

static void signal_hdlr(int signal)
{
	switch (signal) {
	case SIGINT:
		LOGP(DMAIN, LOGL_NOTICE, "Terminating due to SIGINT\n");
		osmo_gsup_server_destroy(g_hlr->gs);
		db_close(g_hlr->dbc);
		log_fini();
		talloc_report_full(hlr_ctx, stderr);
		exit(0);
		break;
	case SIGUSR1:
		LOGP(DMAIN, LOGL_DEBUG, "Talloc Report due to SIGUSR1\n");
		talloc_report_full(hlr_ctx, stderr);
		break;
	}
}

static const char vlr_copyright[] =
	"Copyright (C) 2016, 2017 by Harald Welte, sysmocom s.f.m.c. GmbH\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	 "There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct vty_app_info vty_info = {
	.name 		= "OsmoHLR",
	.version	= PACKAGE_VERSION,
	.copyright	= vlr_copyright,
	.is_config_node	= hlr_vty_is_config_node,
	.go_parent_cb   = hlr_vty_go_parent,
};

int main(int argc, char **argv)
{
	int rc;

	hlr_ctx = talloc_named_const(NULL, 1, "OsmoHLR");
	msgb_talloc_ctx_init(hlr_ctx, 0);

	g_hlr = talloc_zero(hlr_ctx, struct hlr);

	rc = osmo_init_logging(&hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(1);
	}

	vty_init(&vty_info);
	ctrl_vty_init(hlr_ctx);
	handle_options(argc, argv);
	hlr_vty_init(g_hlr, &hlr_log_info);

	rc = vty_read_config_file(cmdline_opts.config_file, NULL);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL,
		     "Failed to parse the config file: '%s'\n",
		     cmdline_opts.config_file);
		return rc;
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(hlr_ctx, NULL, vty_get_bind_addr(),
			       OSMO_VTY_PORT_HLR);
	if (rc < 0)
		return rc;

	LOGP(DMAIN, LOGL_NOTICE, "hlr starting\n");

	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error initializing random source\n");
		exit(1);
	}

	g_hlr->dbc = db_open(hlr_ctx, cmdline_opts.db_file);
	if (!g_hlr->dbc) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening database\n");
		exit(1);
	}

	g_hlr->gs = osmo_gsup_server_create(hlr_ctx, g_hlr->gsup_bind_addr, 2222,
					    read_cb, &g_lu_ops);
	if (!g_hlr->gs) {
		LOGP(DMAIN, LOGL_FATAL, "Error starting GSUP server\n");
		exit(1);
	}

	g_hlr->ctrl_bind_addr = ctrl_vty_get_bind_addr();
	g_hlr->ctrl = hlr_controlif_setup(g_hlr, g_hlr->gs);

	osmo_init_ignore_signals();
	signal(SIGINT, &signal_hdlr);
	signal(SIGUSR1, &signal_hdlr);

	if (cmdline_opts.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}

	db_close(g_hlr->dbc);

	log_fini();

	exit(0);
}
