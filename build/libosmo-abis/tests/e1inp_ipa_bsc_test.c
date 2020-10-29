#include <stdio.h>
#include <signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

static void *tall_test;
static struct e1inp_sign_link *oml_sign_link, *rsl_sign_link;

#define DBSCTEST 0

struct log_info_cat bsc_test_cat[] = {
	[DBSCTEST] = {
		.name = "DBSCTEST",
		.description = "BSC-mode test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

static struct e1inp_sign_link *
sign_link_up(void *dev, struct e1inp_line *line, enum e1inp_sign_type type)
{
	struct e1inp_sign_link *sign_link = NULL;
	struct e1inp_line *oml_line;

	switch(type) {
	case E1INP_SIGN_OML:
		LOGP(DBSCTEST, LOGL_NOTICE, "OML link up request received.\n");
		e1inp_ts_config_sign(&line->ts[E1INP_SIGN_OML - 1], line);
		sign_link = oml_sign_link =
			e1inp_sign_link_create(&line->ts[E1INP_SIGN_OML - 1],
					       E1INP_SIGN_OML, NULL, 255, 0);
		break;
	case E1INP_SIGN_RSL:
		if (!oml_sign_link) {
			LOGP(DBSCTEST, LOGL_ERROR, "OML link not yet set, "
						   "giving up\n");
			return NULL;
		}
		LOGP(DBSCTEST, LOGL_NOTICE, "RSL link up request received.\n");

		/* We have to use the same line that the OML link. */
		oml_line = oml_sign_link->ts->line;
		e1inp_ts_config_sign(&oml_line->ts[E1INP_SIGN_RSL - 1],
				     oml_line);
		sign_link = rsl_sign_link =
		     e1inp_sign_link_create(&oml_line->ts[E1INP_SIGN_RSL - 1],
					    E1INP_SIGN_RSL, NULL, 0, 0);
		break;
	default:
		break;
	}
	if (sign_link)
		LOGP(DBSCTEST, LOGL_NOTICE, "signal link has been set up.\n");

	return sign_link;
}

static void sign_link_down(struct e1inp_line *line)
{
	LOGP(DBSCTEST, LOGL_NOTICE, "signal link has been closed\n");
	if (oml_sign_link) {
		e1inp_sign_link_destroy(oml_sign_link);
		oml_sign_link = NULL;
	}
	if (rsl_sign_link) {
		e1inp_sign_link_destroy(rsl_sign_link);
		rsl_sign_link = NULL;
	}
}

static void fill_om_hdr(struct abis_om_hdr *oh, uint8_t len)
{
	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = len;
}

static void fill_om_fom_hdr(struct abis_om_hdr *oh, uint8_t len,
                            uint8_t msg_type, uint8_t obj_class,
                            uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr)
{
	struct abis_om_fom_hdr *foh =
		(struct abis_om_fom_hdr *) oh->data;

	fill_om_hdr(oh, len+sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;
}

#define OM_ALLOC_SIZE           1024
#define OM_HEADROOM_SIZE        128

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE, "OML");
}


static int abis_nm_sw_act_req_ack(struct e1inp_sign_link *sign_link,
				  uint8_t obj_class,
				  uint8_t i1, uint8_t i2, uint8_t i3,
				  uint8_t *attr, int att_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t msgtype = NM_MT_SW_ACT_REQ_ACK;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, att_len, msgtype, obj_class, i1, i2, i3);

	if (attr) {
		uint8_t *ptr = msgb_put(msg, att_len);
		memcpy(ptr, attr, att_len);
	}
	msg->dst = sign_link;
	return abis_sendmsg(msg);
}

static int abis_nm_rx_sw_act_req(struct msgb *msg)
{
	struct abis_om_hdr *oh = msgb_l2(msg);
	struct abis_om_fom_hdr *foh = msgb_l3(msg);
	int ret;

        ret = abis_nm_sw_act_req_ack(msg->dst,
				     foh->obj_class,
				     foh->obj_inst.bts_nr,
				     foh->obj_inst.trx_nr,
				     foh->obj_inst.ts_nr,
				     foh->data, oh->length-sizeof(*foh));

	return ret;
}

static int abis_nm_rcvmsg_fom(struct msgb *msg)
{
	struct abis_om_fom_hdr *foh = msgb_l3(msg);
	uint8_t mt = foh->msg_type;
	int ret = 0;

	switch (mt) {
	case NM_MT_SW_ACT_REQ:	/* Software activate request from BTS. */
		ret = abis_nm_rx_sw_act_req(msg);
		break;
	default:
		break;
	}
	return ret;
}

static int abis_nm_rcvmsg(struct msgb *msg)
{
	int ret = 0;
	struct abis_om_hdr *oh = msgb_l2(msg);

	msg->l3h = (unsigned char *)oh + sizeof(*oh);
	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		ret = abis_nm_rcvmsg_fom(msg);
		break;
	default:
		LOGP(DBSCTEST, LOGL_ERROR, "unknown OML message\n");
		break;
	}
	return ret;
}

static int sign_link(struct msgb *msg)
{
	int ret = 0;
	struct e1inp_sign_link *link = msg->dst;

	switch(link->type) {
	case E1INP_SIGN_RSL:
		LOGP(DBSCTEST, LOGL_NOTICE, "RSL message received.\n");
		break;
	case E1INP_SIGN_OML:
		LOGP(DBSCTEST, LOGL_NOTICE, "OML message received.\n");
		ret = abis_nm_rcvmsg(msg);
		break;
	default:
		LOGP(DBSCTEST, LOGL_ERROR, "Unknown signallin message.\n");
		break;
	}
	msgb_free(msg);
	return ret;
}

const struct log_info bsc_test_log_info = {
        .filter_fn = NULL,
        .cat = bsc_test_cat,
        .num_cat = ARRAY_SIZE(bsc_test_cat),
};

static struct e1inp_line *line;

static void sighandler(int foo)
{
	e1inp_line_put(line);
	exit(EXIT_SUCCESS);
}

int main(void)
{
	tall_test = talloc_named_const(NULL, 1, "e1inp_test");
	libosmo_abis_init(tall_test);

	osmo_init_logging(&bsc_test_log_info);

	struct e1inp_line_ops ops = {
		.cfg = {
			.ipa = {
				.addr	= "0.0.0.0",
				.role	= E1INP_LINE_R_BSC,
			},
		},
		.sign_link_up	= sign_link_up,
		.sign_link_down	= sign_link_down,
		.sign_link	= sign_link,
	};

	if (signal(SIGINT, sighandler) == SIG_ERR ||
	    signal(SIGTERM, sighandler) == SIG_ERR) {
		perror("Cannot set sighandler");
		exit(EXIT_FAILURE);
	}

#define LINENR 0

	line = e1inp_line_create(LINENR, "ipa");
	if (line == NULL) {
		LOGP(DBSCTEST, LOGL_ERROR, "problem creating E1 line\n");
		exit(EXIT_FAILURE);
	}

	e1inp_line_bind_ops(line, &ops);

	/*
	 * Depending if this is a real or virtual E1 lines:
	 * - real (ISDN): create signal link for OML and RSL before line up.
	 * - vitual (INET): we create it in signal_link_up(...) callback.
	 *
	 * The signal link is created via e1inp_sign_link_create(...)
	 *
	 * See e1_reconfig_trx and e1_reconfig_bts in libbsc/e1_config.c,
	 * it explains how this is done with ISDN.
	 */

	if (e1inp_line_update(line) < 0) {
		LOGP(DBSCTEST, LOGL_ERROR, "problem creating E1 line\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DBSCTEST, LOGL_NOTICE, "entering main loop\n");

	while (1) {
		osmo_select_main(0);
	}
	return 0;
}
