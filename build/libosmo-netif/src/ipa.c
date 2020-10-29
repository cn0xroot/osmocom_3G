#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/netif/channel.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/netif/ipa_unit.h>

#define IPA_ALLOC_SIZE 1200

/*
 * Common propietary IPA messages:
 *	- PONG: in reply to PING.
 *	- ID_REQUEST: first messages once OML has been established.
 *	- ID_ACK: in reply to ID_ACK.
 */
const uint8_t ipa_pong_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG
};

const uint8_t ipa_id_ack_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK
};

const uint8_t ipa_id_req_msg[] = {
	0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
	0x01, IPAC_IDTAG_UNIT,
	0x01, IPAC_IDTAG_MACADDR,
	0x01, IPAC_IDTAG_LOCATION1,
	0x01, IPAC_IDTAG_LOCATION2,
	0x01, IPAC_IDTAG_EQUIPVERS,
	0x01, IPAC_IDTAG_SWVERSION,
	0x01, IPAC_IDTAG_UNITNAME,
	0x01, IPAC_IDTAG_SERNR,
};

static const char *idtag_names[] = {
	[IPAC_IDTAG_SERNR]	= "Serial_Number",
	[IPAC_IDTAG_UNITNAME]	= "Unit_Name",
	[IPAC_IDTAG_LOCATION1]	= "Location_1",
	[IPAC_IDTAG_LOCATION2]	= "Location_2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equipment_Version",
	[IPAC_IDTAG_SWVERSION]	= "Software_Version",
	[IPAC_IDTAG_IPADDR]	= "IP_Address",
	[IPAC_IDTAG_MACADDR]	= "MAC_Address",
	[IPAC_IDTAG_UNIT]	= "Unit_ID",
};

const char *ipaccess_idtag_name(uint8_t tag)
{
	if (tag >= ARRAY_SIZE(idtag_names))
		return "unknown";

	return idtag_names[tag];
}


struct msgb *osmo_ipa_msg_alloc(int headroom)
{
	struct msgb *msg;

	headroom += sizeof(struct ipa_head);

	msg = msgb_alloc_headroom(IPA_ALLOC_SIZE + headroom, headroom, "IPA");
	if (msg == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	return msg;
}

void osmo_ipa_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipa_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipa_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

int osmo_ipa_process_msg(struct msgb *msg)
{
	struct ipa_head *hh;
	int len;

	if (msg->len < sizeof(struct ipa_head)) {
		LOGP(DLINP, LOGL_ERROR, "too small IPA message\n");
		return -EIO;
	}
	hh = (struct ipa_head *) msg->data;

	len = sizeof(struct ipa_head) + ntohs(hh->len);
	if (len > msg->len) {
		LOGP(DLINP, LOGL_ERROR, "bad IPA message header "
					"hdrlen=%u < datalen=%u\n",
					len, msg->len);
		return -EIO;
	}
	msg->l2h = msg->data + sizeof(*hh);

	return 0;
}

int osmo_ipa_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;

	memset(dec, 0, sizeof(*dec));

	while (len >= 2) {
		len -= 2;
		t_len = *cur++;
		t_tag = *cur++;

		if (t_len > len + 1) {
			LOGP(DLMI, LOGL_ERROR, "The tag does not fit: %d\n", t_len);
			return -EINVAL;
		}

		DEBUGPC(DLMI, "%s='%s' ", ipaccess_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len;
		dec->lv[t_tag].val = cur;

		cur += t_len;
		len -= t_len;
	}
	return 0;
}

int osmo_ipa_parse_unitid(const char *str, struct ipaccess_unit *unit_data)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->bts_id = ul & 0xffff;
	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->trx_id = ul & 0xffff;

	return 0;
}

static int ipaccess_send(int fd, const void *msg, size_t msglen)
{
	int ret;

	ret = write(fd, msg, msglen);
	if (ret < 0)
		return ret;
	if (ret < msglen) {
		LOGP(DLINP, LOGL_ERROR, "ipaccess_send: short write\n");
		return -EIO;
	}
	return ret;
}

int ipaccess_send_pong(int fd)
{
	return ipaccess_send(fd, ipa_pong_msg, sizeof(ipa_pong_msg));
}

int ipaccess_send_id_ack(int fd)
{
	return ipaccess_send(fd, ipa_id_ack_msg, sizeof(ipa_id_ack_msg));
}

int ipaccess_send_id_req(int fd)
{
	return ipaccess_send(fd, ipa_id_req_msg, sizeof(ipa_id_req_msg));
}

/* base handling of the ip.access protocol */
int osmo_ipa_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd, int server)
{
	int ipa_ccm = 0;
	uint8_t msg_type = *(msg->l2h);

	switch (msg_type) {
	case IPAC_MSGT_PING:
		LOGP(DLINP, LOGL_DEBUG, "PING!\n");
		ipa_ccm = 1;
		ipaccess_send_pong(bfd->fd);
		break;
	case IPAC_MSGT_PONG:
		LOGP(DLINP, LOGL_DEBUG, "PONG!\n");
		ipa_ccm = 1;
		break;
	case IPAC_MSGT_ID_ACK:
		if (server) {
			LOGP(DLINP, LOGL_DEBUG, "ID_ACK? -> ACK!\n");
			ipa_ccm = 1;
			ipaccess_send_id_ack(bfd->fd);
		} else {
			LOGP(DLINP, LOGL_DEBUG, "ID_ACK! OK!\n");
			ipa_ccm = 1;
		}
		break;
	}
	return ipa_ccm;
}

int ipaccess_parse_unitid(const char *str, struct ipaccess_unit *unit_data)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->bts_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	unit_data->trx_id = ul & 0xffff;

	return 0;
}

struct msgb *ipa_cli_id_resp(struct osmo_ipa_unit *dev, uint8_t *data, int len)
{
	struct msgb *nmsg;
	char str[64];
	uint8_t *tag;

	nmsg = osmo_ipa_msg_alloc(0);
	if (nmsg == NULL)
		return NULL;

	*msgb_put(nmsg, 1) = IPAC_MSGT_ID_RESP;
	while (len) {
		if (len < 2) {
			LOGP(DLINP, LOGL_NOTICE,
				"Short read of ipaccess tag\n");
			msgb_free(nmsg);
			return NULL;
		}
		switch (data[1]) {
		case IPAC_IDTAG_UNIT:
			osmo_ipa_unit_snprintf(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_MACADDR:
			osmo_ipa_unit_snprintf_mac_addr(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_LOCATION1:
			osmo_ipa_unit_snprintf_loc1(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_LOCATION2:
			osmo_ipa_unit_snprintf_loc2(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_EQUIPVERS:
			osmo_ipa_unit_snprintf_hwvers(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_SWVERSION:
			osmo_ipa_unit_snprintf_swvers(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_UNITNAME:
			osmo_ipa_unit_snprintf_name(str, sizeof(str), dev);
			break;
		case IPAC_IDTAG_SERNR:
			osmo_ipa_unit_snprintf_serno(str, sizeof(str), dev);
			break;
		default:
			LOGP(DLINP, LOGL_NOTICE,
				"Unknown ipaccess tag 0x%02x\n", *data);
			msgb_free(nmsg);
			return NULL;
		}
		LOGP(DLINP, LOGL_INFO, " tag %d: %s\n", data[1], str);
		tag = msgb_put(nmsg, 3 + strlen(str) + 1);
		tag[0] = 0x00;
		tag[1] = 1 + strlen(str) + 1;
		tag[2] = data[1];
		memcpy(tag + 3, str, strlen(str) + 1);
		data += 2;
		len -= 2;
	}
	osmo_ipa_msg_push_header(nmsg, IPAC_PROTO_IPACCESS);
	return nmsg;
}

struct msgb *ipa_cli_id_ack(void)
{
	struct msgb *nmsg2;

	nmsg2 = osmo_ipa_msg_alloc(0);
	if (nmsg2 == NULL)
		return NULL;

	*msgb_put(nmsg2, 1) = IPAC_MSGT_ID_ACK;
	osmo_ipa_msg_push_header(nmsg2, IPAC_PROTO_IPACCESS);

	return nmsg2;
}

int
osmo_ipa_parse_msg_id_resp(struct msgb *msg, struct ipaccess_unit *unit_data)
{
	struct tlv_parsed tlvp;
	char *unitid;
	int len, ret;

	DEBUGP(DLINP, "ID_RESP\n");
	/* parse tags, search for Unit ID */
	ret = osmo_ipa_idtag_parse(&tlvp, (uint8_t *)msg->l2h + 2,
					msgb_l2len(msg)-2);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"with malformed TLVs\n");
		return -EINVAL;
	}
	if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"without unit ID\n");
		return  -EINVAL;
	}
	len = TLVP_LEN(&tlvp, IPAC_IDTAG_UNIT);
	if (len < 1) {
		LOGP(DLINP, LOGL_ERROR, "IPA response message "
			"with too small unit ID\n");
		return -EINVAL;
	}
	unitid = (char *) TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT);
	unitid[len - 1] = '\0';

	if (osmo_ipa_parse_unitid(unitid, unit_data) < 0) {
		LOGP(DLINP, LOGL_ERROR, "failed to parse IPA IDTAG\n");
		return -EINVAL;
	}

	return 0;
}
